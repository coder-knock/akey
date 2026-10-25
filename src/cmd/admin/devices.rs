//! `devices`: list, trust, untrust, and revoke recipients.

use chrono::Utc;

use super::git_for;
use crate::audit::{self, Action};
use crate::cli::{DevicesArgs, DevicesCommand};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::vault::model::is_valid_name;
use crate::vault::recipients::{RecipientKind, Recipients};
use crate::vault::store::SYNCED_FILES;

pub fn devices(ctx: &Ctx, args: &DevicesArgs) -> Result<()> {
    let mut store = ctx.store()?;
    match &args.command {
        DevicesCommand::List => {
            let recipients = store.load_recipients()?;
            let mine = store.identity.pubkey();
            let rows: Vec<_> = recipients
                .recipients
                .iter()
                .map(|(pubkey, record)| {
                    serde_json::json!({
                        "name": record.name,
                        "pubkey": pubkey,
                        "kind": match record.kind {
                            RecipientKind::Device => "device",
                            RecipientKind::Bootstrap => "bootstrap",
                        },
                        "active": record.is_active(),
                        "this_device": pubkey == &mine,
                        "added_at": record.added_at,
                        "last_seen_at": record.last_seen_at,
                        "revoked_at": record.revoked_at,
                    })
                })
                .collect();

            let human = if rows.is_empty() {
                crate::msg!("no devices", "没有设备")
            } else {
                rows.iter()
                    .map(|r| {
                        let this_device = if r["this_device"].as_bool() == Some(true) {
                            crate::msg!("  (this device)", "（本设备）")
                        } else {
                            String::new()
                        };
                        format!(
                            "{:<20} {:<8} {}{}",
                            r["name"].as_str().unwrap_or("?"),
                            if r["active"].as_bool() == Some(true) {
                                crate::msg!("active", "有效")
                            } else {
                                crate::msg!("revoked", "已吊销")
                            },
                            r["pubkey"].as_str().unwrap_or(""),
                            this_device,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            ctx.out.emit(human, &serde_json::json!({ "devices": rows }))
        }

        DevicesCommand::Add { name } => {
            // A token is a read-only credential: changing the recipient set changes the
            // cryptographic boundary, so it must use the local device identity.
            ctx.gate_write()?;
            let name = name
                .clone()
                .unwrap_or_else(|| store.config.device_name.clone());
            if ctx.dry_run {
                return ctx.out.emit(
                    crate::msg!(
                        "dry run: would re-add this device as '{}'",
                        "试运行：会以 '{}' 重新添加本设备",
                        name
                    ),
                    &serde_json::json!({ "action": "devices add", "name": name }),
                );
            }
            let now = Utc::now();
            // This device must be in the trust set, otherwise the save_with below refuses
            // to write.
            store.trust(&[store.identity.pubkey()], now)?;
            store.with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                recipients.add(&store.identity.pubkey(), &name, RecipientKind::Device, now);
                recipients.save(&store.recipients_path())?;
                let vault = store.load()?;
                store.save_with(&vault, &recipients)
            })?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: re-add device {name}"))?;
            audit::record(
                &ctx.paths,
                store.identity.name(),
                Action::DeviceAdd,
                Some(&name),
                "ok",
            )?;
            ctx.out.emit(
                crate::msg!(
                    "device '{}' is now an active, trusted recipient",
                    "设备 '{}' 现在已是有效且受信任的收件人",
                    name
                ),
                &serde_json::json!({ "name": name, "pubkey": store.identity.pubkey(), "trusted": true }),
            )
        }

        DevicesCommand::Rm { name } => {
            ctx.gate_write()?;
            if *name == store.config.device_name {
                return Err(Error::usage(crate::msg!(
                    "refusing to remove this device ('{}'): it would immediately lock this \
                     machine out of the vault",
                    "拒绝移除此设备（'{}'）：这会立刻让本机无法访问金库",
                    name
                )));
            }
            if ctx.dry_run {
                return ctx.out.emit(
                    crate::msg!(
                        "dry run: would revoke '{}' and re-encrypt the vault",
                        "试运行：会吊销 '{}' 并重新加密金库",
                        name
                    ),
                    &serde_json::json!({ "action": "devices rm", "name": name }),
                );
            }
            let now = Utc::now();
            // Withdraw approval first, then re-encrypt: revoke is only a marker in the
            // ledger, while withdrawing approval is what actually keeps it from getting
            // ciphertext.
            let doomed = store
                .load_recipients()?
                .find_by_name(name)
                .map(|(key, _)| key.clone());
            store.with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                recipients.revoke(name, now)?;
                recipients.save(&store.recipients_path())?;
                let vault = store.load()?;
                // The key step: re-encrypt, so from this moment on the revoked device can
                // never open a new revision again.
                store.save_with(&vault, &recipients)
            })?;
            if let Some(key) = doomed {
                store.untrust(&key)?;
            }
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: revoke device {name}"))?;
            let pushed = matches!(git.push()?, crate::sync::PushOutcome::Pushed);
            audit::record(
                &ctx.paths,
                store.identity.name(),
                Action::DeviceRemove,
                Some(name),
                "ok",
            )?;
            ctx.out.emit(
                crate::msg!(
                    "revoked '{}' and re-encrypted the vault",
                    "已吊销 '{}' 并重新加密金库",
                    name
                ),
                &serde_json::json!({ "name": name, "reencrypted": true, "pushed": pushed }),
            )
        }

        DevicesCommand::Rename { old, new } => {
            ctx.gate_write()?;
            if !is_valid_name(new) {
                return Err(Error::usage(crate::msg!(
                    "invalid device name '{}'",
                    "非法设备名 '{}'",
                    new
                )));
            }
            store.with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                let (pubkey, _) = recipients.find_by_name(old).ok_or_else(|| {
                    Error::not_found(crate::msg!(
                        "no device named '{}'",
                        "没有名为 '{}' 的设备",
                        old
                    ))
                })?;
                let pubkey = pubkey.clone();
                let mut record = recipients
                    .recipients
                    .remove(&pubkey)
                    .expect("just looked up");
                record.name = new.clone();
                recipients.recipients.insert(pubkey, record);
                recipients.save(&store.recipients_path())
            })?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: rename device {old} -> {new}"))?;
            ctx.out.emit(
                crate::msg!("renamed '{}' to '{}'", "已将 '{}' 重命名为 '{}'", old, new),
                &serde_json::json!({ "old": old, "new": new }),
            )
        }

        // Approve a recipient and **immediately** encrypt the current vault to it —
        // otherwise it gets no content until the next write.
        DevicesCommand::Trust { key } => {
            ctx.gate_write()?;
            let recipients = store.load_recipients()?;
            let (pubkey, name) = resolve_recipient(&recipients, key)?;
            if !recipients
                .recipients
                .get(&pubkey)
                .is_some_and(|record| record.is_active())
            {
                return Err(Error::usage(crate::msg!(
                    "'{}' is revoked; re-add it with `akey devices add` before trusting it",
                    "'{}' 已被吊销；请先用 `akey devices add` 重新添加后再信任它",
                    name
                )));
            }
            if ctx.dry_run {
                return ctx.out.emit(
                    crate::msg!(
                        "dry run: would trust '{}' and re-encrypt the vault to it",
                        "试运行：会信任 '{}' 并向其重新加密金库",
                        name
                    ),
                    &serde_json::json!({ "action": "devices trust", "name": name, "pubkey": pubkey }),
                );
            }
            let added = store.trust(std::slice::from_ref(&pubkey), Utc::now())? > 0;
            store.with_lock(|store| {
                let vault = store.load()?;
                let recipients = store.load_recipients()?;
                store.save_with(&vault, &recipients)
            })?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: trust device {name}"))?;
            let pushed = matches!(git.push()?, crate::sync::PushOutcome::Pushed);
            audit::record(
                &ctx.paths,
                store.identity.name(),
                Action::DeviceAdd,
                Some(&name),
                "ok",
            )?;
            ctx.out.emit(
                crate::msg!(
                    "'{}' is trusted and can now decrypt the vault",
                    "'{}' 已受信任，现在可以解密金库",
                    name
                ),
                &serde_json::json!({ "name": name, "pubkey": pubkey, "newly_trusted": added, "pushed": pushed }),
            )
        }

        DevicesCommand::Untrust { key } => {
            ctx.gate_write()?;
            let recipients = store.load_recipients()?;
            let (pubkey, name) = resolve_recipient(&recipients, key)?;
            if pubkey == store.identity.pubkey() {
                return Err(Error::usage(crate::msg!(
                    "refusing to untrust this device: it would immediately lock this machine out",
                    "拒绝取消信任本设备：这会立刻让本机无法访问金库"
                )));
            }
            if ctx.dry_run {
                return ctx.out.emit(
                    crate::msg!(
                        "dry run: would stop encrypting to '{}'",
                        "试运行：会停止向 '{}' 加密",
                        name
                    ),
                    &serde_json::json!({ "action": "devices untrust", "name": name }),
                );
            }
            let removed = store.untrust(&pubkey)?;
            store.with_lock(|store| {
                let vault = store.load()?;
                let recipients = store.load_recipients()?;
                store.save_with(&vault, &recipients)
            })?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: untrust device {name}"))?;
            ctx.out.emit(
                crate::msg!(
                    "'{}' is no longer trusted; it still appears in recipients.json but will \
                     not receive new ciphertext",
                    "'{}' 已不再受信任；它仍出现在 recipients.json 中，但不会再收到新的密文",
                    name
                ),
                &serde_json::json!({ "name": name, "pubkey": pubkey, "was_trusted": removed }),
            )
        }
    }
}

/// Resolve a `devices trust/untrust` argument into `(pubkey, name)`: an `age1…` value is a
/// public key, anything else is a name.
fn resolve_recipient(recipients: &Recipients, key: &str) -> Result<(String, String)> {
    if key.starts_with("age1") {
        let record = recipients.recipients.get(key).ok_or_else(|| {
            Error::not_found(crate::msg!(
                "no recipient with public key '{}'",
                "没有公钥为 '{}' 的收件人",
                key
            ))
        })?;
        return Ok((key.to_string(), record.name.clone()));
    }
    let (pubkey, record) = recipients.find_by_name(key).ok_or_else(|| {
        Error::not_found(crate::msg!(
            "no recipient named '{}'",
            "没有名为 '{}' 的收件人",
            key
        ))
    })?;
    Ok((pubkey.clone(), record.name.clone()))
}

//! `recovery`: set, show, unlock, and rotate the bootstrap passphrase.

use std::fs;

use age::secrecy::{ExposeSecret, SecretString};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::passphrase::{read_new_passphrase, read_passphrase, resolve_min_passphrase_len};
use super::{MIN_PASSPHRASE_LEN, git_for, internal};
use crate::cli::{RecoveryArgs, RecoveryCommand};
use crate::cmd::Ctx;
use crate::crypto::{DeviceIdentity, encrypt_with_passphrase};
use crate::error::{Error, Result};
use crate::paths::{self, FILE_MODE};
use crate::vault::recipients::RecipientKind;
use crate::vault::store::{RECOVERY_FILE, SYNCED_FILES, Store};

/// The decrypted contents of `recovery.age`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RecoveryFile {
    pub(super) version: u32,
    /// The bootstrap identity's private key. It is always one of the vault's recipients, so
    /// this file never expires.
    pub(super) bootstrap_identity: String,
    created_at: DateTime<Utc>,
}

pub fn recovery(ctx: &Ctx, args: &RecoveryArgs) -> Result<()> {
    match &args.command {
        RecoveryCommand::Set { min_passphrase_len } => {
            // If a token could set the recovery passphrase, it would be leaving itself a
            // backdoor key the operator cannot see.
            ctx.gate_write()?;
            let min_len = resolve_min_passphrase_len(*min_passphrase_len);
            let passphrase = read_passphrase(true, min_len)?;
            set_recovery(ctx, passphrase)?;
            let store = ctx.store()?;
            ctx.out.emit(
                crate::msg!(
                    "recovery passphrase set; this is the only way to attach a new device",
                    "恢复密码已设置；这是接入新设备的唯一途径"
                ),
                &serde_json::json!({
                    "recovery_file": store.recovery_path(),
                    "min_length": min_len,
                }),
            )
        }
        RecoveryCommand::Rotate { min_passphrase_len } => {
            ctx.gate_write()?;
            let store = ctx.store()?;
            let min_len = resolve_min_passphrase_len(*min_passphrase_len);
            let passphrase = read_passphrase(false, min_len)?;
            let new_passphrase = read_new_passphrase(min_len)?;
            rotate_recovery(&store, &passphrase, &new_passphrase)?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit("akey: rotate recovery passphrase")?;
            ctx.out.emit(
                crate::msg!("recovery passphrase rotated", "恢复密码已轮换"),
                &serde_json::json!({ "rotated": true, "min_length": min_len }),
            )
        }
        RecoveryCommand::Unlock => {
            let store = ctx.store()?;
            let passphrase = read_passphrase(false, MIN_PASSPHRASE_LEN)?;
            let payload = decrypt_recovery(&store, &passphrase)?;
            let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap")?;
            let ciphertext = paths::read_file(&store.vault_path())?;
            bootstrap.decrypt(&ciphertext)?;
            ctx.out.emit(
                crate::msg!(
                    "recovery passphrase is valid and can unlock this vault",
                    "恢复密码有效，可以解开本金库"
                ),
                &serde_json::json!({ "valid": true, "created_at": payload.created_at }),
            )
        }
        RecoveryCommand::Status => {
            let store = ctx.store()?;
            let configured = store.recovery_path().is_file();
            // `recovery.age` is passphrase-wrapped; its plaintext contains the bootstrap
            // identity, not the passphrase itself. Strength is reported from the
            // operator-supplied `--min-passphrase-len` (or the compile-time default) so the
            // operator can compare against their policy. **Never** the passphrase.
            let min_length = resolve_min_passphrase_len(None);
            let data = serde_json::json!({
                "configured": configured,
                "min_length": min_length,
                "current_length": serde_json::Value::Null,
                "strength": strength_label(min_length),
                "recovery_file": store.recovery_path(),
            });
            let human = if configured {
                crate::msg!(
                    "recovery passphrase configured (min length {} characters)",
                    "已配置恢复密码（最小长度 {} 字符）",
                    min_length
                )
            } else {
                crate::msg!(
                    "no recovery.age; you cannot attach a new device if this machine is lost",
                    "没有 recovery.age；本机丢失后将无法接入新设备"
                )
            };
            ctx.out.emit(human, &data)
        }
    }
}

fn strength_label(len: usize) -> &'static str {
    match len {
        0..=7 => "too-short",
        8..=11 => "weak",
        12..=15 => "fair",
        16..=23 => "strong",
        _ => "very-strong",
    }
}

pub(super) fn set_recovery(ctx: &Ctx, passphrase: SecretString) -> Result<()> {
    let mut store = ctx.store()?;
    let now = Utc::now();
    // The bootstrap identity is new every time; it is merely "an entrance openable with the
    // passphrase" and plays no long-term role.
    let bootstrap = DeviceIdentity::generate("bootstrap");
    // It must be approved before save_with: it is the key to the recovery path, and a
    // recovery.age that cannot get ciphertext is useless.
    store.trust(&[bootstrap.pubkey()], now)?;
    let payload = RecoveryFile {
        version: 1,
        bootstrap_identity: bootstrap.secret_string().expose_secret().to_string(),
        created_at: now,
    };

    store.with_lock(|store| {
        let mut recipients = store.load_recipients()?;
        // The newly generated identity replaces the old bootstrap one. Keeping it would
        // accumulate several recipients named bootstrap, while `devices rm bootstrap` can
        // revoke only one of them — an inexplicable in-between state.
        let stale: Vec<String> = recipients
            .recipients
            .iter()
            .filter(|(_, record)| record.kind == RecipientKind::Bootstrap && record.is_active())
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            if let Some(record) = recipients.recipients.get_mut(&key) {
                record.revoked_at = Some(now);
            }
        }

        recipients.add(
            &bootstrap.pubkey(),
            "bootstrap",
            RecipientKind::Bootstrap,
            now,
        );
        recipients.save(&store.recipients_path())?;
        let vault = store.load()?;
        // The bootstrap identity must be a recipient, otherwise the key in recovery.age
        // cannot open the vault.
        store.save_with(&vault, &recipients)?;
        write_recovery(store, &payload, &passphrase)
    })?;

    let git = git_for(&store);
    git.add_paths(SYNCED_FILES)?;
    git.commit("akey: set recovery passphrase")?;
    Ok(())
}

pub(super) fn write_recovery(
    store: &Store,
    payload: &RecoveryFile,
    passphrase: &SecretString,
) -> Result<()> {
    let plaintext = serde_json::to_vec(payload).map_err(internal)?;
    let ciphertext = encrypt_with_passphrase(passphrase, &plaintext)?;
    paths::atomic_write(&store.recovery_path(), &ciphertext, FILE_MODE)
}

/// Rotate the recovery passphrase: unlock the bootstrap identity with the old passphrase,
/// then rewrite `recovery.age` with the new one.
///
/// Extracted as a pure function so it can be tested directly — the `recovery` command itself
/// takes passphrases from env / TTY, which tests cannot easily drive.
pub(super) fn rotate_recovery(
    store: &Store,
    current: &SecretString,
    replacement: &SecretString,
) -> Result<()> {
    if current.expose_secret() == replacement.expose_secret() {
        // Non-interactively, both reads return the same environment variable, so the
        // command would spin for nothing and still report success.
        return Err(Error::usage(crate::msg!(
            "new passphrase is identical to the current one; set \
             AKEY_NEW_RECOVERY_PASSPHRASE to actually rotate",
            "新密码与当前密码相同；请设置 AKEY_NEW_RECOVERY_PASSPHRASE 才能真正轮换"
        )));
    }
    let payload = decrypt_recovery(store, current)?;
    write_recovery(store, &payload, replacement)
}

pub(super) fn decrypt_recovery(store: &Store, passphrase: &SecretString) -> Result<RecoveryFile> {
    if !store.recovery_path().is_file() {
        return Err(Error::usage(crate::msg!(
            "no recovery passphrase is configured; run `akey recovery set` first",
            "没有配置恢复密码；请先运行 `akey recovery set`"
        )));
    }
    let plaintext =
        crate::crypto::decrypt_with_passphrase(passphrase, &fs::read(store.recovery_path())?)?;
    serde_json::from_slice(&plaintext).map_err(|e| {
        Error::corrupt(crate::msg!(
            "{} is malformed: {}",
            "{} 格式不对：{}",
            RECOVERY_FILE,
            e
        ))
    })
}

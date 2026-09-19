//! Lifecycle commands: init, devices, recovery passphrase, capability tokens, self-check,
//! audit, schema, completion.

use std::fs;
use std::io::{IsTerminal, Read};

use age::secrecy::{ExposeSecret, SecretString};
use chrono::{DateTime, Utc};
use clap::CommandFactory;
use serde::{Deserialize, Serialize};

use crate::agents_md::VAULT_AGENTS_MD;
use crate::audit::{self, Action};
use crate::cli::{
    Cli, CompletionArgs, DevicesArgs, DevicesCommand, DoctorArgs, InitArgs, LogArgs, RecoveryArgs,
    RecoveryCommand, SchemaArgs, TokenArgs, TokenCommand,
};
use crate::cmd::{Ctx, parse_duration};
use crate::config::Config;
use crate::crypto::{DeviceIdentity, encrypt_to, encrypt_with_passphrase, token as tokenmod};
use crate::error::{Error, Result};
use crate::paths::{self, FILE_MODE};
use crate::sync::Git;
use crate::vault::model::{Vault, is_valid_name};
use crate::vault::recipients::{RecipientKind, Recipients};
use crate::vault::store::{
    Store, AGENTS_FILE, RECIPIENTS_FILE, RECOVERY_FILE, SYNCED_FILES, VAULT_FILE,
};

/// Minimum recovery-passphrase length. It is the vault's last resort, so do not let it
/// become the weakest link.
pub const MIN_PASSPHRASE_LEN: usize = 12;

const GITIGNORE: &str = ".DS_Store\n.akey-tmp-*\n";

/// The decrypted contents of `recovery.age`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryFile {
    version: u32,
    /// The bootstrap identity's private key. It is always one of the vault's recipients, so
    /// this file never expires.
    bootstrap_identity: String,
    created_at: DateTime<Utc>,
}

fn default_device_name() -> String {
    if let Ok(name) = std::env::var("AKEY_DEVICE_NAME")
        && !name.trim().is_empty()
    {
        return name.trim().to_string();
    }
    // Prefer the environment: it costs no process spawn, and Windows names the machine in
    // `COMPUTERNAME` while unix shells export `HOSTNAME`.
    if let Some(name) = ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .filter(|name| !name.trim().is_empty())
    {
        return name.trim().to_string();
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "device".to_string())
}

/// Obtain the recovery passphrase. Order: the `AKEY_RECOVERY_PASSPHRASE` environment
/// variable → read stdin when not a TTY → prompt when a TTY.
///
/// A non-interactive run never blocks: with no TTY and no environment variable, reading
/// stdin to EOF fails instead of hanging on a prompt.
///
/// `confirm = true` means **this passphrase is being newly created**, in which case the
/// minimum length applies no matter where it came from.
fn read_passphrase(confirm: bool) -> Result<SecretString> {
    if let Ok(value) = std::env::var("AKEY_RECOVERY_PASSPHRASE")
        && !value.is_empty()
    {
        return enforce_min(SecretString::from(value), confirm);
    }

    if !std::io::stdin().is_terminal() {
        let mut raw = String::new();
        std::io::stdin().read_to_string(&mut raw)?;
        let line = raw.lines().next().unwrap_or("").to_string();
        if line.is_empty() {
            return Err(Error::usage(crate::msg!(
                "no passphrase available: set AKEY_RECOVERY_PASSPHRASE or pipe it on stdin",
                "没有可用的恢复密码：请设置 AKEY_RECOVERY_PASSPHRASE，或通过 stdin 传入"
            )));
        }
        return enforce_min(SecretString::from(line), confirm);
    }

    let first = rpassword::prompt_password("Recovery passphrase: ")?;
    if confirm {
        let second = rpassword::prompt_password("Repeat passphrase: ")?;
        if first != second {
            return Err(Error::usage(crate::msg!(
                "passphrases do not match",
                "两次输入的密码不一致"
            )));
        }
    }
    enforce_min(SecretString::from(first), confirm)
}

/// Enforce the length limit only for a **new** passphrase.
///
/// The other way round (enforcing it on existing passphrases too) would make tightening the
/// policy suicidal: once an old vault's passphrase is shorter than the new minimum, it could
/// no longer be unlocked / rotated / bootstrapped, when it should still work.
fn enforce_min(passphrase: SecretString, is_new: bool) -> Result<SecretString> {
    if is_new && passphrase.expose_secret().len() < MIN_PASSPHRASE_LEN {
        return Err(Error::usage(crate::msg!(
            "passphrase must be at least {} characters",
            "恢复密码至少需要 {} 个字符",
            MIN_PASSPHRASE_LEN
        )));
    }
    Ok(passphrase)
}

/// Obtain the **new** recovery passphrase. `AKEY_NEW_RECOVERY_PASSPHRASE` lets it be given
/// separately from the old one — otherwise a non-interactive rotate could only read the same
/// value twice.
fn read_new_passphrase() -> Result<SecretString> {
    if let Ok(value) = std::env::var("AKEY_NEW_RECOVERY_PASSPHRASE")
        && !value.is_empty()
    {
        return enforce_min(SecretString::from(value), true);
    }
    read_passphrase(true)
}

fn git_for(store: &Store) -> Git {
    let name = store.config.device_name.clone();
    Git::new(
        store.repo(),
        &name,
        format!("akey+{}@akey.invalid", sanitise(&name)),
    )
}

fn sanitise(device: &str) -> String {
    device
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

// ---------------------------------------------------------------- init

pub fn init(ctx: &Ctx, args: &InitArgs) -> Result<()> {
    if ctx.paths.has_config() {
        return Err(Error::usage(crate::msg!(
            "already initialized at {}; to attach another repository use `akey init --from <url>`",
            "已在 {} 初始化；要接入另一个仓库，请使用 `akey init --from <url>`",
            ctx.paths.config.display()
        )));
    }
    match &args.from {
        Some(url) => {
            let passphrase = read_passphrase(false)?;
            init_from_remote(ctx, args, url, passphrase)
        }
        None => init_fresh(ctx, args),
    }
}

fn init_fresh(ctx: &Ctx, args: &InitArgs) -> Result<()> {
    ctx.paths.ensure()?;
    let now = Utc::now();
    let device_name = args.device.clone().unwrap_or_else(default_device_name);
    let repo = match &args.repo {
        Some(path) => Config::normalise_repo(path)?,
        None => ctx.paths.home.join("repo"),
    };
    fs::create_dir_all(&repo)?;

    let identity = DeviceIdentity::generate(device_name.clone());
    identity.save(&ctx.paths.identity)?;

    let mut recipients = Recipients::default();
    recipients.add(
        &identity.pubkey(),
        &device_name,
        RecipientKind::Device,
        now,
    );
    recipients.save(&repo.join(RECIPIENTS_FILE))?;

    let vault = Vault::default();
    let ciphertext = encrypt_to(
        &recipients.to_recipients()?,
        &serde_json::to_vec(&vault).map_err(internal)?,
    )?;
    paths::atomic_write(&repo.join(VAULT_FILE), &ciphertext, FILE_MODE)?;
    fs::write(repo.join(AGENTS_FILE), VAULT_AGENTS_MD)?;
    fs::write(repo.join(".gitignore"), GITIGNORE)?;

    let config = Config {
        repo: repo.clone(),
        remote: args.remote.clone(),
        device_name: device_name.clone(),
        // This device is the first member of the trust set.
        trusted: std::collections::BTreeMap::from([(identity.pubkey(), now)]),
        trust_seeded: true,
        created_at: now,
    };
    config.save(&ctx.paths)?;

    let git = git_for_repo(&repo, &device_name);
    if !git.is_repo() {
        git.init()?;
    }
    git.add_paths(SYNCED_FILES)?;
    git.commit("akey: initialize vault")?;

    let mut steps = vec!["created device identity".to_string(), "created vault".to_string()];

    if args.recovery {
        let passphrase = read_passphrase(true)?;
        set_recovery(ctx, passphrase)?;
        steps.push("enabled recovery passphrase".to_string());
    }

    if let Some(remote) = &args.remote {
        git.set_remote(remote)?;
        match git.push()? {
            crate::sync::PushOutcome::Pushed | crate::sync::PushOutcome::UpToDate => {
                steps.push(format!("pushed to {remote}"))
            }
            crate::sync::PushOutcome::Rejected => {
                return Err(Error::SyncFailed(crate::msg!(
                    "the remote {} already has commits; refusing to overwrite — \
                     use `akey init --from {}` to adopt it instead",
                    "远端 {} 已有提交；拒绝覆盖——请改用 `akey init --from {}` 接收它",
                    remote, remote
                )));
            }
        }
    }

    audit::record(
        &ctx.paths,
        &device_name,
        Action::Init,
        None,
        "ok",
    )?;

    ctx.out.emit(
        format!(
            "initialized akey\n  device  {device_name}\n  identity  {}\n  repo  {}\n  vault  {}",
            ctx.paths.identity.display(),
            repo.display(),
            repo.join(VAULT_FILE).display()
        ),
        &serde_json::json!({
            "device": device_name,
            "pubkey": identity.pubkey(),
            "repo": repo,
            "remote": args.remote,
            "recovery": args.recovery,
            "steps": steps,
        }),
    )
}

fn init_from_remote(
    ctx: &Ctx,
    args: &InitArgs,
    url: &str,
    passphrase: SecretString,
) -> Result<()> {
    ctx.paths.ensure()?;
    let now = Utc::now();
    let device_name = args.device.clone().unwrap_or_else(default_device_name);
    let repo = match &args.repo {
        Some(path) => Config::normalise_repo(path)?,
        None => ctx.paths.home.join("repo"),
    };

    if repo.join(".git").is_dir() {
        return Err(Error::usage(crate::msg!(
            "{} already contains a git repository; remove it first",
            "{} 已包含一个 git 仓库；请先移除它",
            repo.display()
        )));
    }

    let git = Git::clone(url, &repo)?;

    let recovery_path = repo.join(RECOVERY_FILE);
    if !recovery_path.is_file() {
        return Err(Error::usage(crate::msg!(
            "this vault has no {}; ask an operator to run `akey recovery set` first",
            "本金库没有 {}；请让运维人员先运行 `akey recovery set`",
            RECOVERY_FILE
        )));
    }
    let recovered = crate::crypto::decrypt_with_passphrase(
        &passphrase,
        &fs::read(&recovery_path)?,
    )?;
    let recovery: RecoveryFile = serde_json::from_slice(&recovered)
        .map_err(|e| Error::corrupt(crate::msg!(
            "{} is malformed: {}",
            "{} 格式不对：{}",
            RECOVERY_FILE,
            e
        )))?;
    let bootstrap = DeviceIdentity::parse(&recovery.bootstrap_identity, "bootstrap")?;

    let vault_ciphertext = fs::read(repo.join(VAULT_FILE))
        .map_err(|_| Error::corrupt(crate::msg!(
            "{} is missing {}",
            "{} 缺少 {}",
            repo.display(),
            VAULT_FILE
        )))?;
    let vault_plain = bootstrap.decrypt(&vault_ciphertext).map_err(|_| {
        Error::locked(crate::msg!(
            "recovery passphrase decrypts the bootstrap key but not the vault",
            "恢复密码能解密引导密钥，但解不开金库"
        ))
    })?;
    let vault: Vault = serde_json::from_slice(&vault_plain)
        .map_err(|e| Error::corrupt(crate::msg!(
            "vault is not valid JSON: {}",
            "金库不是合法的 JSON：{}",
            e
        )))?;

    let identity = DeviceIdentity::generate(device_name.clone());
    identity.save(&ctx.paths.identity)?;

    let mut recipients = Recipients::load(&repo.join(RECIPIENTS_FILE))?;
    recipients.add(&identity.pubkey(), &device_name, RecipientKind::Device, now);
    recipients.save(&repo.join(RECIPIENTS_FILE))?;

    let ciphertext = encrypt_to(
        &recipients.to_recipients()?,
        &serde_json::to_vec(&vault).map_err(internal)?,
    )?;
    paths::atomic_write(&repo.join(VAULT_FILE), &ciphertext, FILE_MODE)?;

    let config = Config {
        repo: repo.clone(),
        remote: Some(url.to_string()),
        device_name: device_name.clone(),
        // Bootstrap approves the devices **already in the vault at that moment**: they are
        // exactly the set that can open the vault this device just joined, and the operator
        // handing over the recovery passphrase is the trust anchor. Public keys appearing
        // later are not automatically trusted.
        trusted: recipients
            .recipients
            .iter()
            .filter(|(_, record)| record.is_active())
            .map(|(key, _)| (key.clone(), now))
            .collect(),
        trust_seeded: true,
        created_at: now,
    };
    config.save(&ctx.paths)?;

    git.add_paths(SYNCED_FILES)?;
    git.commit(&format!("akey: add device {device_name}"))?;
    let pushed = matches!(git.push()?, crate::sync::PushOutcome::Pushed);

    audit::record(&ctx.paths, &device_name, Action::Recover, None, "ok")?;

    ctx.out.emit(
        format!(
            "joined the vault\n  device  {device_name}\n  repo  {}\n  entries  {}",
            repo.display(),
            vault.entries.len()
        ),
        &serde_json::json!({
            "device": device_name,
            "pubkey": identity.pubkey(),
            "repo": repo,
            "remote": url,
            "entries": vault.entries.len(),
            "pushed": pushed,
        }),
    )
}

/// Only to get a Git handle before the config exists; nothing is written to disk.
fn git_for_repo(repo: &std::path::Path, device_name: &str) -> Git {
    Git::new(
        repo,
        device_name,
        format!("akey+{}@akey.invalid", sanitise(device_name)),
    )
}

fn internal(e: serde_json::Error) -> Error {
    Error::Io(std::io::Error::other(e))
}

// ---------------------------------------------------------------- devices

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
                "no devices".to_string()
            } else {
                rows.iter()
                    .map(|r| {
                        format!(
                            "{:<20} {:<8} {}{}",
                            r["name"].as_str().unwrap_or("?"),
                            if r["active"].as_bool() == Some(true) { "active" } else { "revoked" },
                            r["pubkey"].as_str().unwrap_or(""),
                            if r["this_device"].as_bool() == Some(true) { "  (this device)" } else { "" },
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
            let name = name.clone().unwrap_or_else(|| store.config.device_name.clone());
            if ctx.dry_run {
                return ctx.out.emit(
                    format!("dry run: would re-add this device as '{name}'"),
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
            audit::record(&ctx.paths, store.identity.name(), Action::DeviceAdd, Some(&name), "ok")?;
            ctx.out.emit(
                format!("device '{name}' is now an active, trusted recipient"),
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
                    format!("dry run: would revoke '{name}' and re-encrypt the vault"),
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
            audit::record(&ctx.paths, store.identity.name(), Action::DeviceRemove, Some(name), "ok")?;
            ctx.out.emit(
                format!("revoked '{name}' and re-encrypted the vault"),
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
                let (pubkey, _) = recipients
                    .find_by_name(old)
                    .ok_or_else(|| Error::not_found(crate::msg!(
                        "no device named '{}'",
                        "没有名为 '{}' 的设备",
                        old
                    )))?;
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
                format!("renamed '{old}' to '{new}'"),
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
                    format!("dry run: would trust '{name}' and re-encrypt the vault to it"),
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
            audit::record(&ctx.paths, store.identity.name(), Action::DeviceAdd, Some(&name), "ok")?;
            ctx.out.emit(
                format!("'{name}' is trusted and can now decrypt the vault"),
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
                    format!("dry run: would stop encrypting to '{name}'"),
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
                format!(
                    "'{name}' is no longer trusted; it still appears in recipients.json but will \
                     not receive new ciphertext"
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
    let (pubkey, record) = recipients
        .find_by_name(key)
        .ok_or_else(|| Error::not_found(crate::msg!(
            "no recipient named '{}'",
            "没有名为 '{}' 的收件人",
            key
        )))?;
    Ok((pubkey.clone(), record.name.clone()))
}

// ---------------------------------------------------------------- recovery

pub fn recovery(ctx: &Ctx, args: &RecoveryArgs) -> Result<()> {
    match &args.command {
        RecoveryCommand::Set => {
            // If a token could set the recovery passphrase, it would be leaving itself a
            // backdoor key the operator cannot see.
            ctx.gate_write()?;
            let passphrase = read_passphrase(true)?;
            set_recovery(ctx, passphrase)?;
            let store = ctx.store()?;
            ctx.out.emit(
                "recovery passphrase set; this is the only way to attach a new device",
                &serde_json::json!({ "recovery_file": store.recovery_path() }),
            )
        }
        RecoveryCommand::Rotate => {
            ctx.gate_write()?;
            let store = ctx.store()?;
            let passphrase = read_passphrase(false)?;
            let new_passphrase = read_new_passphrase()?;
            rotate_recovery(&store, &passphrase, &new_passphrase)?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit("akey: rotate recovery passphrase")?;
            ctx.out.emit(
                "recovery passphrase rotated",
                &serde_json::json!({ "rotated": true }),
            )
        }
        RecoveryCommand::Unlock => {
            let store = ctx.store()?;
            let passphrase = read_passphrase(false)?;
            let payload = decrypt_recovery(&store, &passphrase)?;
            let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap")?;
            let ciphertext = paths::read_file(&store.vault_path())?;
            bootstrap.decrypt(&ciphertext)?;
            ctx.out.emit(
                "recovery passphrase is valid and can unlock this vault",
                &serde_json::json!({ "valid": true, "created_at": payload.created_at }),
            )
        }
    }
}

fn set_recovery(ctx: &Ctx, passphrase: SecretString) -> Result<()> {
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

fn write_recovery(store: &Store, payload: &RecoveryFile, passphrase: &SecretString) -> Result<()> {
    let plaintext = serde_json::to_vec(payload).map_err(internal)?;
    let ciphertext = encrypt_with_passphrase(passphrase, &plaintext)?;
    paths::atomic_write(&store.recovery_path(), &ciphertext, FILE_MODE)
}

/// Rotate the recovery passphrase: unlock the bootstrap identity with the old passphrase,
/// then rewrite `recovery.age` with the new one.
///
/// Extracted as a pure function so it can be tested directly — the `recovery` command itself
/// takes passphrases from env / TTY, which tests cannot easily drive.
fn rotate_recovery(
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

fn decrypt_recovery(store: &Store, passphrase: &SecretString) -> Result<RecoveryFile> {
    if !store.recovery_path().is_file() {
        return Err(Error::usage(crate::msg!(
            "no recovery passphrase is configured; run `akey recovery set` first",
            "没有配置恢复密码；请先运行 `akey recovery set`"
        )));
    }
    let plaintext = crate::crypto::decrypt_with_passphrase(
        passphrase,
        &fs::read(store.recovery_path())?,
    )?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| Error::corrupt(crate::msg!(
            "{} is malformed: {}",
            "{} 格式不对：{}",
            RECOVERY_FILE,
            e
        )))
}

// ---------------------------------------------------------------- token

pub fn token(ctx: &Ctx, args: &TokenArgs) -> Result<()> {
    let store = ctx.store()?;
    match &args.command {
        TokenCommand::Create {
            name,
            allow,
            deny_reveal,
            ttl,
        } => {
            // Key: without this gate, a token restricted to a single entry could mint an
            // **unrestricted** token and read the whole vault with it — scoping drops to zero
            // on the spot. Reproduced in practice.
            ctx.gate_write()?;
            if !is_valid_name(name) {
                return Err(Error::usage(crate::msg!(
                    "invalid token name '{}'",
                    "非法令牌名 '{}'",
                    name
                )));
            }
            let now = Utc::now();
            let expires_at = match ttl {
                Some(raw) => Some(now + parse_duration(raw)?),
                None => None,
            };
            let allow = if allow.is_empty() {
                None
            } else {
                Some(allow.clone())
            };

            if ctx.dry_run {
                return ctx.out.emit(
                    format!("dry run: would issue token '{name}'"),
                    &serde_json::json!({ "action": "token create", "name": name, "allow": allow }),
                );
            }

            let issued = tokenmod::issue(name, allow.clone(), *deny_reveal, expires_at, now)?;
            let meta = issued.meta.clone();
            let id = meta.id;
            store.update(|vault| {
                vault.tokens.insert(id, meta);
                Ok(())
            })?;

            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: issue token {name}"))?;
            audit::record(&ctx.paths, store.identity.name(), Action::TokenIssue, Some(name), "ok")?;

            ctx.out.emit(
                format!(
                    "token '{name}' issued — copy it now, it will never be shown again\n{}",
                    issued.plaintext
                ),
                &serde_json::json!({
                    "name": name,
                    "token": issued.plaintext,
                    "allow": allow,
                    "deny_reveal": deny_reveal,
                    "expires_at": expires_at,
                }),
            )
        }

        TokenCommand::List => {
            let vault = store.load()?;
            let now = Utc::now();
            let rows: Vec<_> = vault
                .tokens
                .values()
                .map(|meta| {
                    serde_json::json!({
                        "name": meta.name,
                        "id": meta.id.to_string(),
                        "active": meta.is_active(now),
                        "allow": meta.allow,
                        "deny_reveal": meta.deny_reveal,
                        "expires_at": meta.expires_at,
                        "created_at": meta.created_at,
                        "last_used_at": meta.last_used_at,
                        "revoked_at": meta.revoked_at,
                    })
                })
                .collect();
            let human = if rows.is_empty() {
                "no tokens".to_string()
            } else {
                rows.iter()
                    .map(|r| {
                        format!(
                            "{:<20} {:<8} expires {}",
                            r["name"].as_str().unwrap_or("?"),
                            if r["active"].as_bool() == Some(true) { "active" } else { "inactive" },
                            r["expires_at"].as_str().unwrap_or("never"),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            ctx.out.emit(human, &serde_json::json!({ "tokens": rows }))
        }

        TokenCommand::Rm { name } => {
            ctx.gate_write()?;
            let now = Utc::now();
            let id = store.update(|vault| {
                let meta = vault
                    .tokens
                    .values()
                    .find(|t| &t.name == name)
                    .ok_or_else(|| Error::not_found(crate::msg!(
                        "no token named '{}'",
                        "没有名为 '{}' 的令牌",
                        name
                    )))?;
                let id = meta.id;
                let meta = vault.tokens.get_mut(&id).expect("just found");
                if meta.revoked_at.is_none() {
                    meta.revoked_at = Some(now);
                }
                Ok(id)
            })?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: revoke token {name}"))?;
            audit::record(&ctx.paths, store.identity.name(), Action::TokenRevoke, Some(name), "ok")?;
            ctx.out.emit(
                format!("token '{name}' revoked"),
                &serde_json::json!({ "name": name, "id": id.to_string(), "revoked": true }),
            )
        }
    }
}

// ---------------------------------------------------------------- whoami / doctor / log

pub fn whoami(ctx: &Ctx) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let recipients = store.load_recipients()?;
    let token_scope = match ctx.active_token(&vault) {
        Ok(Some(meta)) => Some(serde_json::json!({
            "name": meta.name,
            "allow": meta.allow,
            "deny_reveal": meta.deny_reveal,
        })),
        _ => None,
    };

    let data = serde_json::json!({
        "device": store.config.device_name,
        "pubkey": store.identity.pubkey(),
        "home": store.paths.home,
        "repo": store.config.repo,
        "remote": store.config.remote,
        "vault": vault.vault,
        "entries": vault.live_entries().count(),
        "devices": recipients.recipients.values().filter(|r| r.is_active()).count(),
        "tokens": vault.tokens.values().filter(|t| t.is_active(Utc::now())).count(),
        "token_scope": token_scope,
    });

    ctx.out.emit(
        format!(
            "device  {}\npubkey  {}\nrepo  {}\nremote  {}\nentries  {}\n",
            store.config.device_name,
            store.identity.pubkey(),
            store.config.repo.display(),
            store.config.remote.as_deref().unwrap_or("(none)"),
            vault.live_entries().count(),
        ),
        &data,
    )
}

pub fn doctor(ctx: &Ctx, _args: &DoctorArgs) -> Result<()> {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut push = |name: &str, status: &str, detail: String| {
        checks.push(serde_json::json!({ "name": name, "status": status, "detail": detail }));
    };

    push(
        "home",
        "ok",
        format!("{}", ctx.paths.home.display()),
    );

    if ctx.paths.has_identity() {
        match paths::permissions_exposed(&ctx.paths.identity) {
            Ok(false) => push("identity_permissions", "ok", "owner-only".into()),
            Ok(true) => push(
                "identity_permissions",
                "error",
                format!("{} is readable by other users", ctx.paths.identity.display()),
            ),
            Err(e) => push("identity_permissions", "error", e.to_string()),
        }
    } else {
        push("identity", "error", "no identity.key; run `akey init`".into());
    }

    if ctx.paths.has_config()
        && paths::permissions_exposed(&ctx.paths.config).unwrap_or(false)
    {
        push(
            "config_permissions",
            "error",
            format!("{} is readable by other users", ctx.paths.config.display()),
        );
    } else if ctx.paths.has_config() {
        push("config_permissions", "ok", "owner-only".into());
    }

    let store = ctx.store()?;
    let git = git_for(&store);
    push(
        "repository",
        if git.is_repo() { "ok" } else { "error" },
        format!("{}", store.repo().display()),
    );
    push(
        "remote",
        if store.config.remote.is_some() { "ok" } else { "warning" },
        store
            .config
            .remote
            .clone()
            .unwrap_or_else(|| "no remote; vault is local-only".into()),
    );

    let vault = store.load()?;
    push(
        "vault",
        "ok",
        format!("{} entries, {} tokens", vault.entries.len(), vault.tokens.len()),
    );

    let recipients = store.load_recipients()?;
    let mine = store.identity.pubkey();
    let active = recipients.recipients.iter().any(|(k, r)| k == &mine && r.is_active());
    push(
        "this_device_is_recipient",
        if active { "ok" } else { "error" },
        mine.to_string(),
    );

    push(
        "recovery",
        if store.recovery_path().is_file() { "ok" } else { "warning" },
        if store.recovery_path().is_file() {
            "recovery passphrase configured".into()
        } else {
            "no recovery.age; you cannot attach a new device if this machine is lost".to_string()
        },
    );

    // A recipient this machine never approved is what a remote-write attacker leaves behind.
    // It cannot decrypt anything, but the user should see it and decide.
    let pending = store.pending_recipients()?;
    push(
        "recipients",
        if pending.is_empty() { "ok" } else { "warning" },
        if pending.is_empty() {
            "every recipient in the repository is trusted by this machine".into()
        } else {
            format!(
                "{} untrusted recipient(s) present (they receive no ciphertext): {} — \
                 `akey devices trust <name>` to approve",
                pending.len(),
                pending
                    .iter()
                    .map(|(name, key)| format!("{name} ({key})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    );

    let now = Utc::now();
    let conflicts = crate::sync::pending_conflicts(&vault);
    push(
        "conflicts",
        if conflicts.is_empty() { "ok" } else { "warning" },
        if conflicts.is_empty() {
            "none".into()
        } else {
            conflicts.join(", ")
        },
    );

    let expired_tokens: Vec<&str> = vault
        .tokens
        .values()
        .filter(|t| !t.is_active(now))
        .map(|t| t.name.as_str())
        .collect();
    push(
        "tokens",
        if expired_tokens.is_empty() { "ok" } else { "warning" },
        if expired_tokens.is_empty() {
            "all active".into()
        } else {
            format!("inactive: {}", expired_tokens.join(", "))
        },
    );

    let soon = now + chrono::Duration::days(30);
    let expiring: Vec<&str> = vault
        .live_entries()
        .filter(|e| matches!(e.expires_at, Some(at) if at <= soon))
        .map(|e| e.name.as_str())
        .collect();
    push(
        "expiring",
        if expiring.is_empty() { "ok" } else { "warning" },
        if expiring.is_empty() {
            "nothing expiring in 30 days".into()
        } else {
            expiring.join(", ")
        },
    );

    let problems = checks
        .iter()
        .filter(|c| c["status"] == "error")
        .count();
    let human = checks
        .iter()
        .map(|c| {
            format!(
                "{:<26} {:<8} {}",
                c["name"].as_str().unwrap_or("?"),
                c["status"].as_str().unwrap_or("?"),
                c["detail"].as_str().unwrap_or(""),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    ctx.out.emit(
        human,
        &serde_json::json!({ "healthy": problems == 0, "errors": problems, "checks": checks }),
    )
}

pub fn log(ctx: &Ctx, args: &LogArgs) -> Result<()> {
    let cutoff = match &args.since {
        Some(raw) => Some(Utc::now() - parse_duration(raw)?),
        None => None,
    };
    let records = audit::tail(&ctx.paths, args.limit.max(1))?;
    let filtered: Vec<_> = records
        .into_iter()
        .filter(|r| cutoff.is_none_or(|c| r.ts >= c))
        .filter(|r| args.item.as_deref().is_none_or(|i| r.subject.as_deref() == Some(i)))
        .collect();

    let human = if filtered.is_empty() {
        "no audit records".to_string()
    } else {
        filtered
            .iter()
            .map(|r| {
                format!(
                    "{}  {:<14} {:<12} {}",
                    r.ts.to_rfc3339(),
                    r.action.as_str(),
                    r.subject.as_deref().unwrap_or("-"),
                    r.outcome,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    ctx.out.emit(human, &serde_json::json!({ "records": filtered }))
}

// ---------------------------------------------------------------- schema / completion

pub fn schema(ctx: &Ctx, _args: &SchemaArgs) -> Result<()> {
    let command = Cli::command();
    let commands: Vec<_> = command
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
        .map(|sub| {
            let args: Vec<_> = sub
                .get_arguments()
                .filter(|a| !a.is_global_set())
                .map(|a| {
                    serde_json::json!({
                        "name": a.get_id().to_string(),
                        "long": a.get_long(),
                        "short": a.get_short().map(|c| c.to_string()),
                        "required": a.is_required_set(),
                        "takes_value": a.get_num_args().map(|r| r.max_values() > 0).unwrap_or(false),
                        "help": a.get_help().map(|h| h.to_string()),
                    })
                })
                .collect();
            serde_json::json!({
                "name": sub.get_name(),
                "summary": sub.get_about().map(|s| s.to_string()).unwrap_or_default(),
                "args": args,
            })
        })
        .collect();

    let data = serde_json::json!({
        "name": "akey",
        "version": env!("CARGO_PKG_VERSION"),
        "global_flags": ["--json", "--format human|json", "--no-color", "--quiet", "--debug",
                         "--home <dir>", "--repo <path>", "--token <t>", "--yes", "--dry-run"],
        "env_vars": ["AKEY_HOME", "AKEY_TOKEN", "AKEY_NO_REVEAL", "AKEY_DEVICE_NAME",
                     "AKEY_RECOVERY_PASSPHRASE", "AKEY_NEW_RECOVERY_PASSPHRASE"],
        "exit_codes": {
            "0": "ok", "2": "usage", "3": "not_found_or_ambiguous", "4": "locked",
            "5": "conflict", "6": "sync_failed", "7": "denied", "8": "token_scope",
            "1": "internal",
        },
        "reference": {
            "grammar": "akey://[vault/]item[/section]/field[?attribute=value|otp|title|type|id]",
            "examples": [
                "akey://openai/credential",
                "akey://default/db/password",
                "akey://github/credentials/personal_token",
                "akey://github/one-time-password?attribute=otp",
            ],
        },
        "commands": commands,
    });

    ctx.out.emit(
        "akey schema (use --json for the machine-readable form)",
        &data,
    )
}

pub fn completion(ctx: &Ctx, args: &CompletionArgs) -> Result<()> {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, name, &mut std::io::stdout());
    let _ = ctx;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Command;
    use clap::Parser;

    fn init_ctx(dir: &std::path::Path) -> (Cli, Ctx) {
        let cli = Cli::parse_from([
            "akey",
            "--home",
            dir.to_str().unwrap(),
            "init",
            "--no-recovery",
        ]);
        let ctx = Ctx::new(&cli).unwrap();
        (cli, ctx)
    }

    fn init_args(cli: &Cli) -> &InitArgs {
        match &cli.command {
            Command::Init(args) => args,
            other => panic!("expected init, got {other:?}"),
        }
    }

    #[test]
    fn init_creates_a_usable_vault_without_a_remote() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();

        let store = ctx.store().unwrap();
        let vault = store.load().unwrap();
        assert!(vault.entries.is_empty());
        assert!(store.repo().join(VAULT_FILE).is_file());
        assert!(store.repo().join(RECIPIENTS_FILE).is_file());
        assert!(store.repo().join(AGENTS_FILE).is_file());
        assert!(!paths::permissions_exposed(&ctx.paths.identity).unwrap());
    }

    #[test]
    fn init_refuses_to_run_twice() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let err = init(&ctx, init_args(&cli)).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("already initialized"));
    }

    #[test]
    fn a_second_device_joins_without_the_owner() {
        // One machine creates the vault, another bootstraps with the recovery passphrase —
        // the core path of S4.
        let owner_dir = tempfile::tempdir().unwrap();
        let (owner_cli, owner_ctx) = init_ctx(owner_dir.path());
        init(&owner_ctx, init_args(&owner_cli)).unwrap();
        let owner_store = owner_ctx.store().unwrap();

        let passphrase = SecretString::from("correct-horse-battery");
        set_recovery(&owner_ctx, passphrase.clone()).unwrap();

        // Move the repository to a bare remote, simulating "bootstrap from a remote".
        let bare = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(bare.path())
            .output()
            .unwrap();
        let url = format!("file://{}", bare.path().display());
        let owner_git = git_for(&owner_store);
        owner_git.set_remote(&url).unwrap();
        owner_git.push().unwrap();

        let joiner_dir = tempfile::tempdir().unwrap();
        let joiner_cli = Cli::parse_from([
            "akey",
            "--home",
            joiner_dir.path().to_str().unwrap(),
            "init",
            "--from",
            &url,
            "--device",
            "laptop",
        ]);
        let joiner_ctx = Ctx::new(&joiner_cli).unwrap();
        // Pass the passphrase directly rather than mutating process-level environment
        // variables in a test (parallel tests would step on each other).
        init_from_remote(
            &joiner_ctx,
            init_args(&joiner_cli),
            &url,
            SecretString::from("correct-horse-battery"),
        )
        .unwrap();

        let joiner_store = joiner_ctx.store().unwrap();
        assert_eq!(joiner_store.identity.name(), "laptop");
        // The bootstrapped device can decrypt the vault on its own.
        assert_eq!(joiner_store.load().unwrap().entries.len(), 0);
    }

    #[test]
    fn revoked_device_cannot_open_the_new_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        // Another "device" is approved and joins, then gets revoked.
        let mut store = ctx.store().unwrap();
        let stranger = DeviceIdentity::generate("stranger");
        let now = Utc::now();
        // Approve first: without this step save_with would encrypt only to this device, and
        // the "it can decrypt" assertion below would mean nothing.
        store.trust(&[stranger.pubkey()], now).unwrap();
        store
            .with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                recipients.add(&stranger.pubkey(), "stranger", RecipientKind::Device, now);
                let vault = store.load()?;
                store.save_with(&vault, &recipients)?;
                recipients.save(&store.recipients_path())
            })
            .unwrap();
        assert!(stranger.decrypt(&fs::read(store.vault_path()).unwrap()).is_ok());

        store
            .with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                recipients.revoke("stranger", Utc::now())?;
                recipients.save(&store.recipients_path())?;
                let vault = store.load()?;
                store.save_with(&vault, &recipients)
            })
            .unwrap();
        store.untrust(&stranger.pubkey()).unwrap();

        let err = stranger
            .decrypt(&fs::read(store.vault_path()).unwrap())
            .unwrap_err();
        assert_eq!(err.exit_code(), 4, "revoked device must be locked out");
    }

    #[test]
    fn devices_rm_refuses_to_remove_this_machine() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let store = ctx.store().unwrap();
        let me = store.config.device_name.clone();

        let cli = Cli::parse_from([
            "akey",
            "--home",
            dir.path().to_str().unwrap(),
            "devices",
            "rm",
            &me,
        ]);
        let ctx = Ctx::new(&cli).unwrap();
        let args = match &cli.command {
            Command::Devices(args) => args,
            other => panic!("expected devices, got {other:?}"),
        };
        let err = devices(&ctx, args).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("refusing"));
    }

    #[test]
    fn recovery_roundtrip_then_rotation_keeps_bootstrap_usable() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let store = ctx.store().unwrap();

        set_recovery(&ctx, SecretString::from("first-passphrase-here")).unwrap();
        let payload = decrypt_recovery(&store, &SecretString::from("first-passphrase-here"))
            .unwrap();
        assert_eq!(payload.version, 1);

        // After the rotation the old passphrase stops working and the new one works.
        write_recovery(&store, &payload, &SecretString::from("second-passphrase-here"))
            .unwrap();
        assert!(
            decrypt_recovery(&store, &SecretString::from("first-passphrase-here")).is_err()
        );
        assert!(
            decrypt_recovery(&store, &SecretString::from("second-passphrase-here")).is_ok()
        );
    }

    #[test]
    fn recovery_unlock_verifies_the_bootstrap_can_open_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        set_recovery(&ctx, SecretString::from("a-long-enough-passphrase")).unwrap();

        let store = ctx.store().unwrap();
        let payload =
            decrypt_recovery(&store, &SecretString::from("a-long-enough-passphrase"))
                .unwrap();
        let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap").unwrap();
        assert!(
            bootstrap
                .decrypt(&fs::read(store.vault_path()).unwrap())
                .is_ok(),
            "bootstrap identity must be a vault recipient"
        );
    }

    #[test]
    fn token_create_shows_plaintext_once_and_list_never_does() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();

        let create = Cli::parse_from([
            "akey",
            "--home",
            dir.path().to_str().unwrap(),
            "token",
            "create",
            "--name",
            "ci",
            "--allow",
            "openai",
            "--deny-reveal",
            "--ttl",
            "30d",
        ]);
        let ctx = Ctx::new(&create).unwrap();
        let args = match &create.command {
            Command::Token(args) => args,
            other => panic!("expected token, got {other:?}"),
        };
        token(&ctx, args).unwrap();

        let store = ctx.store().unwrap();
        let vault = store.load().unwrap();
        let meta = vault.find_token("ci").unwrap();
        assert_eq!(meta.allow.as_deref(), Some(&["openai".to_string()][..]));
        assert!(meta.deny_reveal);
        assert!(meta.expires_at.is_some());
        // The vault holds only the digest, never the plaintext.
        let raw = serde_json::to_string(&vault).unwrap();
        assert!(!raw.contains("akey_"), "token plaintext leaked into the vault");
    }

    #[test]
    fn rotation_actually_changes_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let store = ctx.store().unwrap();

        let old = SecretString::from("old-passphrase-here");
        let new = SecretString::from("new-passphrase-here");
        set_recovery(&ctx, old.clone()).unwrap();

        rotate_recovery(&store, &old, &new).unwrap();

        assert!(
            decrypt_recovery(&store, &old).is_err(),
            "the old passphrase must stop working"
        );
        assert!(
            decrypt_recovery(&store, &new).is_ok(),
            "the new passphrase must work"
        );
        // After the rotation the bootstrap identity can still open the vault — otherwise
        // the machine-transfer path would break.
        let payload = decrypt_recovery(&store, &new).unwrap();
        let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap").unwrap();
        assert!(bootstrap.decrypt(&fs::read(store.vault_path()).unwrap()).is_ok());
    }

    #[test]
    fn rotating_to_the_same_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let store = ctx.store().unwrap();

        let same = SecretString::from("same-passphrase-here");
        set_recovery(&ctx, same.clone()).unwrap();
        let err = rotate_recovery(&store, &same, &same).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("identical"));
    }

    #[test]
    fn repeated_recovery_set_leaves_exactly_one_active_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let store = ctx.store().unwrap();

        set_recovery(&ctx, SecretString::from("first-passphrase-here")).unwrap();
        set_recovery(&ctx, SecretString::from("second-passphrase-here")).unwrap();

        let recipients = store.load_recipients().unwrap();
        let bootstraps = recipients
            .recipients
            .values()
            .filter(|r| r.kind == RecipientKind::Bootstrap && r.is_active())
            .count();
        assert_eq!(
            bootstraps, 1,
            "a second `recovery set` must retire the previous bootstrap identity"
        );

        // Only the newest passphrase works, and it can open the vault.
        assert!(
            decrypt_recovery(&store, &SecretString::from("first-passphrase-here")).is_err()
        );
        let payload =
            decrypt_recovery(&store, &SecretString::from("second-passphrase-here")).unwrap();
        let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap").unwrap();
        assert!(bootstrap.decrypt(&fs::read(store.vault_path()).unwrap()).is_ok());
    }

    #[test]
    fn passphrase_minimum_applies_to_new_ones_only() {
        let short = SecretString::from("a");
        let long = SecretString::from("long-enough-to-be-a-passphrase");

        // New: must be long enough no matter where it came from (this once held only on the
        // TTY path, so AKEY_RECOVERY_PASSPHRASE could set a 1-character passphrase).
        assert!(enforce_min(short.clone(), true).is_err());
        assert_eq!(enforce_min(short.clone(), true).unwrap_err().exit_code(), 2);
        assert!(enforce_min(long.clone(), true).is_ok());

        // Existing: the length must never be enforced here, otherwise tightening the policy
        // would make an old vault impossible to open.
        assert!(enforce_min(short, false).is_ok());
        assert!(enforce_min(long, false).is_ok());
    }

    #[test]
    fn schema_lists_every_documented_command() {
        let command = Cli::command();
        let names: Vec<String> = command
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        for expected in [
            "init", "read", "run", "inject", "get", "set", "edit", "rm", "restore", "cp", "mv",
            "list", "template", "doc", "token", "devices", "recovery", "sync", "conflicts",
            "resolve", "log", "whoami", "doctor", "schema", "completion", "export", "import", "mcp",
        ] {
            assert!(names.contains(&expected.to_string()), "missing command {expected}");
        }
    }
}

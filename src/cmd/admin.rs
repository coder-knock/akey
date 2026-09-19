//! 生命周期命令：初始化、设备、恢复密码、能力令牌、自检、审计、schema、补全。

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

/// 恢复密码的最短长度。它是整库的最终后路，别让它成为最弱环节。
pub const MIN_PASSPHRASE_LEN: usize = 12;

const GITIGNORE: &str = ".DS_Store\n.akey-tmp-*\n";

/// `recovery.age` 解密后的内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryFile {
    version: u32,
    /// 引导身份的私钥。它始终是金库收件人之一，所以这个文件永不过期。
    bootstrap_identity: String,
    created_at: DateTime<Utc>,
}

fn default_device_name() -> String {
    if let Ok(name) = std::env::var("AKEY_DEVICE_NAME")
        && !name.trim().is_empty()
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

/// 取恢复密码。顺序：`AKEY_RECOVERY_PASSPHRASE` 环境变量 → 非 TTY 时读 stdin → TTY 时提示。
///
/// 非交互场景永远不阻塞：没有 TTY 又没有环境变量时，stdin 读完即失败，而不是挂在提示上。
///
/// `confirm = true` 表示**这是要新建的密码**，此时无论来源都必须满足长度下限。
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
            return Err(Error::usage(
                "no passphrase available: set AKEY_RECOVERY_PASSPHRASE or pipe it on stdin",
            ));
        }
        return enforce_min(SecretString::from(line), confirm);
    }

    let first = rpassword::prompt_password("Recovery passphrase: ")?;
    if confirm {
        let second = rpassword::prompt_password("Repeat passphrase: ")?;
        if first != second {
            return Err(Error::usage("passphrases do not match"));
        }
    }
    enforce_min(SecretString::from(first), confirm)
}

/// 只在**新建**密码时卡长度。
///
/// 反过来（对已有密码也卡长度）会让收紧策略变成自杀：老金库的密码一旦短于新下限，
/// 就再也 unlock / rotate / 引导不了，而它本该还能用。
fn enforce_min(passphrase: SecretString, is_new: bool) -> Result<SecretString> {
    if is_new && passphrase.expose_secret().len() < MIN_PASSPHRASE_LEN {
        return Err(Error::usage(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        )));
    }
    Ok(passphrase)
}

/// 取**新**的恢复密码。允许用 `AKEY_NEW_RECOVERY_PASSPHRASE` 与旧密码分开提供——
/// 否则非交互场景下 rotate 只能读到同一个值。
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
        return Err(Error::usage(format!(
            "already initialized at {}; to attach another repository use `akey init --from <url>`",
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
                return Err(Error::SyncFailed(format!(
                    "the remote {remote} already has commits; refusing to overwrite — \
                     use `akey init --from {remote}` to adopt it instead"
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
        return Err(Error::usage(format!(
            "{} already contains a git repository; remove it first",
            repo.display()
        )));
    }

    let git = Git::clone(url, &repo)?;

    let recovery_path = repo.join(RECOVERY_FILE);
    if !recovery_path.is_file() {
        return Err(Error::usage(format!(
            "this vault has no {RECOVERY_FILE}; ask an operator to run `akey recovery set` first"
        )));
    }
    let recovered = crate::crypto::decrypt_with_passphrase(
        &passphrase,
        &fs::read(&recovery_path)?,
    )?;
    let recovery: RecoveryFile = serde_json::from_slice(&recovered)
        .map_err(|e| Error::corrupt(format!("{RECOVERY_FILE} is malformed: {e}")))?;
    let bootstrap = DeviceIdentity::parse(&recovery.bootstrap_identity, "bootstrap")?;

    let vault_ciphertext = fs::read(repo.join(VAULT_FILE))
        .map_err(|_| Error::corrupt(format!("{} is missing {VAULT_FILE}", repo.display())))?;
    let vault_plain = bootstrap.decrypt(&vault_ciphertext).map_err(|_| {
        Error::locked("recovery passphrase decrypts the bootstrap key but not the vault")
    })?;
    let vault: Vault = serde_json::from_slice(&vault_plain)
        .map_err(|e| Error::corrupt(format!("vault is not valid JSON: {e}")))?;

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

/// 只为了在建 config 之前拿到 Git 封装；不落盘。
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
    let store = ctx.store()?;
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
            // 令牌是只读凭据：改组收件人等于改密码学边界，必须用本机身份。
            ctx.gate_write()?;
            let name = name.clone().unwrap_or_else(|| store.config.device_name.clone());
            if ctx.dry_run {
                return ctx.out.emit(
                    format!("dry run: would re-add this device as '{name}'"),
                    &serde_json::json!({ "action": "devices add", "name": name }),
                );
            }
            let now = Utc::now();
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
                format!("device '{name}' is now an active recipient"),
                &serde_json::json!({ "name": name, "pubkey": store.identity.pubkey() }),
            )
        }

        DevicesCommand::Rm { name } => {
            ctx.gate_write()?;
            if *name == store.config.device_name {
                return Err(Error::usage(format!(
                    "refusing to remove this device ('{name}'): it would immediately lock this \
                     machine out of the vault"
                )));
            }
            if ctx.dry_run {
                return ctx.out.emit(
                    format!("dry run: would revoke '{name}' and re-encrypt the vault"),
                    &serde_json::json!({ "action": "devices rm", "name": name }),
                );
            }
            let now = Utc::now();
            store.with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                recipients.revoke(name, now)?;
                recipients.save(&store.recipients_path())?;
                let vault = store.load()?;
                // 关键一步：重新加密，被吊销的设备从此刻起再也解不开新版本。
                store.save_with(&vault, &recipients)
            })?;
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
                return Err(Error::usage(format!("invalid device name '{new}'")));
            }
            store.with_lock(|store| {
                let mut recipients = store.load_recipients()?;
                let (pubkey, _) = recipients
                    .find_by_name(old)
                    .ok_or_else(|| Error::not_found(format!("no device named '{old}'")))?;
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
    }
}

// ---------------------------------------------------------------- recovery

pub fn recovery(ctx: &Ctx, args: &RecoveryArgs) -> Result<()> {
    match &args.command {
        RecoveryCommand::Set => {
            // 令牌若能设恢复密码，就等于给自己留了一把运营者看不见的后门钥匙。
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
    let store = ctx.store()?;
    let now = Utc::now();
    // 引导身份每次都是新的；它只是"用密码可以打开的入口"，不承担任何长期角色。
    let bootstrap = DeviceIdentity::generate("bootstrap");
    let payload = RecoveryFile {
        version: 1,
        bootstrap_identity: bootstrap.secret_string().expose_secret().to_string(),
        created_at: now,
    };

    store.with_lock(|store| {
        let mut recipients = store.load_recipients()?;
        // 旧的引导身份由这次新生成的顶替。留着会积累出多个名为 bootstrap 的收件人，
        // 而 `devices rm bootstrap` 只能吊销其中一个——那是个说不清的中间态。
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
        // 引导身份必须成为收件人，否则 recovery.age 里的钥匙打不开库。
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

/// 轮换恢复密码：用旧密码解出引导身份，再用新密码重写 `recovery.age`。
///
/// 抽成纯函数是为了能直接测——`recovery` 命令本身从 env / TTY 取密码，测试不便驱动。
fn rotate_recovery(
    store: &Store,
    current: &SecretString,
    replacement: &SecretString,
) -> Result<()> {
    if current.expose_secret() == replacement.expose_secret() {
        // 非交互场景下两次读取会拿到同一个环境变量，很容易空转一圈还报成功。
        return Err(Error::usage(
            "new passphrase is identical to the current one; set \
             AKEY_NEW_RECOVERY_PASSPHRASE to actually rotate",
        ));
    }
    let payload = decrypt_recovery(store, current)?;
    write_recovery(store, &payload, replacement)
}

fn decrypt_recovery(store: &Store, passphrase: &SecretString) -> Result<RecoveryFile> {
    if !store.recovery_path().is_file() {
        return Err(Error::usage(
            "no recovery passphrase is configured; run `akey recovery set` first",
        ));
    }
    let plaintext = crate::crypto::decrypt_with_passphrase(
        passphrase,
        &fs::read(store.recovery_path())?,
    )?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| Error::corrupt(format!("{RECOVERY_FILE} is malformed: {e}")))
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
            // 关键：不加这道闸门，一个被限制在单条目上的令牌可以铸出**无限制**令牌，
            // 再拿它读全库——作用域当场归零。实测可复现。
            ctx.gate_write()?;
            if !is_valid_name(name) {
                return Err(Error::usage(format!("invalid token name '{name}'")));
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
                    .ok_or_else(|| Error::not_found(format!("no token named '{name}'")))?;
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
        // 一台机器建库，另一台用恢复密码引导——这是 S4 的核心路径。
        let owner_dir = tempfile::tempdir().unwrap();
        let (owner_cli, owner_ctx) = init_ctx(owner_dir.path());
        init(&owner_ctx, init_args(&owner_cli)).unwrap();
        let owner_store = owner_ctx.store().unwrap();

        let passphrase = SecretString::from("correct-horse-battery");
        set_recovery(&owner_ctx, passphrase.clone()).unwrap();

        // 把仓库搬到一个裸远端，模拟"从远端引导"。
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
        // 直接传密码，避免在测试里改进程级环境变量（并行测试会互相踩）。
        init_from_remote(
            &joiner_ctx,
            init_args(&joiner_cli),
            &url,
            SecretString::from("correct-horse-battery"),
        )
        .unwrap();

        let joiner_store = joiner_ctx.store().unwrap();
        assert_eq!(joiner_store.identity.name(), "laptop");
        // 引导后的设备能独立解密金库。
        assert_eq!(joiner_store.load().unwrap().entries.len(), 0);
    }

    #[test]
    fn revoked_device_cannot_open_the_new_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (cli, ctx) = init_ctx(dir.path());
        init(&ctx, init_args(&cli)).unwrap();
        let store = ctx.store().unwrap();

        // 另一个"设备"把自己加入，然后被吊销。
        let stranger = DeviceIdentity::generate("stranger");
        let now = Utc::now();
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

        // 轮换后旧密码失效、新密码可用。
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
        // 库里只有摘要，没有明文。
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
        // 旋转后引导身份仍能开库——否则换机路径就断了。
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

        // 只有最新那个密码有效，且它能开库。
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

        // 新建：无论来源都必须够长（这条以前只在 TTY 路径成立，
        // 走 AKEY_RECOVERY_PASSPHRASE 时能设出 1 字符的密码）。
        assert!(enforce_min(short.clone(), true).is_err());
        assert_eq!(enforce_min(short.clone(), true).unwrap_err().exit_code(), 2);
        assert!(enforce_min(long.clone(), true).is_ok());

        // 使用已有的：绝不能卡长度，否则收紧策略会让老金库彻底打不开。
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

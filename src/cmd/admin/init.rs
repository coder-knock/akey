//! `init`: create a vault, or join an existing remote repository.

use std::fs;

use age::secrecy::SecretString;
use chrono::Utc;

use super::passphrase::{read_passphrase, resolve_min_passphrase_len};
use super::recovery::{RecoveryFile, set_recovery};
use super::{internal, sanitise};
use crate::agents_md::VAULT_AGENTS_MD;
use crate::audit::{self, Action};
use crate::cli::InitArgs;
use crate::cmd::Ctx;
use crate::config::Config;
use crate::crypto::{DeviceIdentity, encrypt_to};
use crate::error::{Error, Result};
use crate::paths::{self, FILE_MODE};
use crate::sync::Git;
use crate::vault::model::Vault;
use crate::vault::recipients::{RecipientKind, Recipients};
use crate::vault::store::{AGENTS_FILE, RECIPIENTS_FILE, RECOVERY_FILE, SYNCED_FILES, VAULT_FILE};

const GITIGNORE: &str = ".DS_Store\n.akey-tmp-*\n";

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
            let min_len = resolve_min_passphrase_len(args.min_passphrase_len);
            let passphrase = read_passphrase(false, min_len)?;
            init_from_remote(ctx, args, url, passphrase)
        }
        None => init_fresh(ctx, args),
    }
}

fn init_fresh(ctx: &Ctx, args: &InitArgs) -> Result<()> {
    // Validate recovery input before creating an identity, repository, or config. A typo or
    // missing non-interactive passphrase must leave `init` safely retryable.
    let recovery_passphrase = if args.recovery {
        let min_len = resolve_min_passphrase_len(args.min_passphrase_len);
        Some(read_passphrase(true, min_len)?)
    } else {
        None
    };
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
    recipients.add(&identity.pubkey(), &device_name, RecipientKind::Device, now);
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

    let mut steps = vec![
        "created device identity".to_string(),
        "created vault".to_string(),
    ];

    if let Some(passphrase) = recovery_passphrase {
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
                    remote,
                    remote
                )));
            }
        }
    }

    audit::record(&ctx.paths, &device_name, Action::Init, None, "ok")?;

    ctx.out.emit(
        crate::msg!(
            "initialized akey\n  device  {}\n  identity  {}\n  repo  {}\n  vault  {}",
            "已初始化 akey\n  设备  {}\n  身份  {}\n  仓库  {}\n  金库  {}",
            device_name,
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

pub(super) fn init_from_remote(
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

    if repo.is_dir() && repo.read_dir()?.next().is_some() {
        return Err(Error::usage(crate::msg!(
            "{} is not empty; choose an empty repository path",
            "{} 不是空目录；请选择空的仓库路径",
            repo.display()
        )));
    }

    let parent = repo.parent().ok_or_else(|| {
        Error::usage(crate::msg!(
            "repository path {} has no parent directory",
            "仓库路径 {} 没有父目录",
            repo.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    let staging = tempfile::TempDir::new_in(parent)?;
    let staging_repo = staging.path().join("repo");
    let git = Git::clone(url, &staging_repo)?;

    let recovery_path = staging_repo.join(RECOVERY_FILE);
    if !recovery_path.is_file() {
        return Err(Error::usage(crate::msg!(
            "this vault has no {}; ask an operator to run `akey recovery set` first",
            "本金库没有 {}；请让运维人员先运行 `akey recovery set`",
            RECOVERY_FILE
        )));
    }
    let recovered =
        crate::crypto::decrypt_with_passphrase(&passphrase, &fs::read(&recovery_path)?)?;
    let recovery: RecoveryFile = serde_json::from_slice(&recovered).map_err(|e| {
        Error::corrupt(crate::msg!(
            "{} is malformed: {}",
            "{} 格式不对：{}",
            RECOVERY_FILE,
            e
        ))
    })?;
    let bootstrap = DeviceIdentity::parse(&recovery.bootstrap_identity, "bootstrap")?;

    let vault_ciphertext = fs::read(staging_repo.join(VAULT_FILE)).map_err(|_| {
        Error::corrupt(crate::msg!(
            "{} is missing {}",
            "{} 缺少 {}",
            repo.display(),
            VAULT_FILE
        ))
    })?;
    let vault_plain = bootstrap.decrypt(&vault_ciphertext).map_err(|_| {
        Error::locked(crate::msg!(
            "recovery passphrase decrypts the bootstrap key but not the vault",
            "恢复密码能解密引导密钥，但解不开金库"
        ))
    })?;
    let vault: Vault = serde_json::from_slice(&vault_plain).map_err(|e| {
        Error::corrupt(crate::msg!(
            "vault is not valid JSON: {}",
            "金库不是合法的 JSON：{}",
            e
        ))
    })?;

    let identity = DeviceIdentity::generate(device_name.clone());
    let mut recipients = Recipients::load(&staging_repo.join(RECIPIENTS_FILE))?;
    recipients.add(&identity.pubkey(), &device_name, RecipientKind::Device, now);
    recipients.save(&staging_repo.join(RECIPIENTS_FILE))?;

    let ciphertext = encrypt_to(
        &recipients.to_recipients()?,
        &serde_json::to_vec(&vault).map_err(internal)?,
    )?;
    paths::atomic_write(&staging_repo.join(VAULT_FILE), &ciphertext, FILE_MODE)?;

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
    git.add_paths(SYNCED_FILES)?;
    git.commit(&format!("akey: add device {device_name}"))?;

    // Install a complete, usable local state before publishing this recipient. If the
    // subsequent push races with another writer, the device can finish with `akey sync`;
    // the opposite order could leave an unusable public key permanently published remotely.
    // Nothing reaches these paths until the recovery passphrase and vault are validated.
    if repo.is_dir() {
        fs::remove_dir(&repo)?;
    }
    fs::rename(&staging_repo, &repo)?;
    identity.save(&ctx.paths.identity)?;
    config.save(&ctx.paths)?;

    let installed_git = git_for_repo(&repo, &device_name);
    let pushed = match installed_git.push()? {
        crate::sync::PushOutcome::Pushed => true,
        crate::sync::PushOutcome::UpToDate => false,
        crate::sync::PushOutcome::Rejected => {
            return Err(Error::SyncFailed(crate::msg!(
                "joined locally, but the remote changed while adding device {}; run `akey sync`",
                "已在本地加入，但添加设备 {} 时远端发生变化；请运行 `akey sync`",
                device_name
            )));
        }
    };

    audit::record(&ctx.paths, &device_name, Action::Recover, None, "ok")?;

    ctx.out.emit(
        crate::msg!(
            "joined the vault\n  device  {}\n  repo  {}\n  entries  {}",
            "已加入金库\n  设备  {}\n  仓库  {}\n  条目  {}",
            device_name,
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

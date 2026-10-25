//! `whoami` / `doctor`: identity summary and environment self-check.

use chrono::Utc;

use super::git_for;
use crate::cli::DoctorArgs;
use crate::cmd::Ctx;
use crate::error::Result;
use crate::paths;

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
        Ok(None) => None,
        Err(err) => return Err(err),
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
        crate::msg!(
            "device  {}\npubkey  {}\nrepo  {}\nremote  {}\nentries  {}\n",
            "设备  {}\n公钥  {}\n仓库  {}\n远端  {}\n条目  {}\n",
            store.config.device_name,
            store.identity.pubkey(),
            store.config.repo.display(),
            store
                .config
                .remote
                .as_deref()
                .unwrap_or(crate::i18n::m("(none)", "（无）")),
            vault.live_entries().count(),
        ),
        &data,
    )
}

pub fn doctor(ctx: &Ctx, _args: &DoctorArgs) -> Result<()> {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    // The table's detail column is prose and follows `--lang`, while `checks[].detail` is the
    // machine-readable payload and stays English — the same message rendered twice. `None`
    // means the detail is a value (a path, a key, an OS error) and reads the same either way.
    let mut table: Vec<String> = Vec::new();
    let mut push = |name: &str, status: &str, detail: String, localized: Option<String>| {
        table.push(format!(
            "{name:<26} {status:<8} {}",
            localized.as_deref().unwrap_or(&detail)
        ));
        checks.push(serde_json::json!({ "name": name, "status": status, "detail": detail }));
    };

    push("home", "ok", format!("{}", ctx.paths.home.display()), None);

    if ctx.paths.has_identity() {
        match paths::permissions_exposed(&ctx.paths.identity) {
            Ok(false) => push(
                "identity_permissions",
                "ok",
                "owner-only".into(),
                Some(crate::msg!("owner-only", "仅所有者可读")),
            ),
            Ok(true) => push(
                "identity_permissions",
                "error",
                format!(
                    "{} is readable by other users",
                    ctx.paths.identity.display()
                ),
                Some(crate::msg!(
                    "{} is readable by other users",
                    "{} 可被其他用户读取",
                    ctx.paths.identity.display()
                )),
            ),
            Err(e) => push("identity_permissions", "error", e.to_string(), None),
        }
    } else {
        push(
            "identity",
            "error",
            "no identity.key; run `akey init`".into(),
            Some(crate::msg!(
                "no identity.key; run `akey init`",
                "没有 identity.key；请运行 `akey init`"
            )),
        );
    }

    if ctx.paths.has_config() && paths::permissions_exposed(&ctx.paths.config).unwrap_or(false) {
        push(
            "config_permissions",
            "error",
            format!("{} is readable by other users", ctx.paths.config.display()),
            Some(crate::msg!(
                "{} is readable by other users",
                "{} 可被其他用户读取",
                ctx.paths.config.display()
            )),
        );
    } else if ctx.paths.has_config() {
        push(
            "config_permissions",
            "ok",
            "owner-only".into(),
            Some(crate::msg!("owner-only", "仅所有者可读")),
        );
    }

    let store = ctx.store()?;
    let git = git_for(&store);
    push(
        "repository",
        if git.is_repo() { "ok" } else { "error" },
        format!("{}", store.repo().display()),
        None,
    );
    let remote = store.config.remote.clone();
    push(
        "remote",
        if remote.is_some() { "ok" } else { "warning" },
        remote
            .clone()
            .unwrap_or_else(|| "no remote; vault is local-only".into()),
        remote.is_none().then(|| {
            crate::msg!(
                "no remote; vault is local-only",
                "没有远端；金库仅存在于本地"
            )
        }),
    );

    let vault = store.load()?;
    push(
        "vault",
        "ok",
        format!(
            "{} entries, {} tokens",
            vault.entries.len(),
            vault.tokens.len()
        ),
        Some(crate::msg!(
            "{} entries, {} tokens",
            "{} 个条目，{} 个令牌",
            vault.entries.len(),
            vault.tokens.len()
        )),
    );

    let recipients = store.load_recipients()?;
    let mine = store.identity.pubkey();
    let active = recipients
        .recipients
        .iter()
        .any(|(k, r)| k == &mine && r.is_active());
    push(
        "this_device_is_recipient",
        if active { "ok" } else { "error" },
        mine.to_string(),
        None,
    );

    push(
        "recovery",
        if store.recovery_path().is_file() {
            "ok"
        } else {
            "warning"
        },
        if store.recovery_path().is_file() {
            "recovery passphrase configured".into()
        } else {
            "no recovery.age; you cannot attach a new device if this machine is lost".to_string()
        },
        Some(if store.recovery_path().is_file() {
            crate::msg!("recovery passphrase configured", "已配置恢复密码")
        } else {
            crate::msg!(
                "no recovery.age; you cannot attach a new device if this machine is lost",
                "没有 recovery.age；本机丢失后将无法接入新设备"
            )
        }),
    );

    // A recipient this machine never approved is what a remote-write attacker leaves behind.
    // It cannot decrypt anything, but the user should see it and decide.
    let pending = store.pending_recipients()?;
    let untrusted = pending
        .iter()
        .map(|(name, key)| format!("{name} ({key})"))
        .collect::<Vec<_>>()
        .join(", ");
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
                untrusted
            )
        },
        Some(if pending.is_empty() {
            crate::msg!(
                "every recipient in the repository is trusted by this machine",
                "本机信任仓库中的每一位收件人"
            )
        } else {
            crate::msg!(
                "{} untrusted recipient(s) present (they receive no ciphertext): {} — \
                 `akey devices trust <name>` to approve",
                "存在 {} 位未受信任的收件人（它们收不到密文）：{}——请用 \
                 `akey devices trust <name>` 批准",
                pending.len(),
                untrusted
            )
        }),
    );

    let now = Utc::now();
    let conflicts = crate::sync::pending_conflicts(&vault);
    push(
        "conflicts",
        if conflicts.is_empty() {
            "ok"
        } else {
            "warning"
        },
        if conflicts.is_empty() {
            "none".into()
        } else {
            conflicts.join(", ")
        },
        conflicts.is_empty().then(|| crate::msg!("none", "无")),
    );

    let expired_tokens: Vec<&str> = vault
        .tokens
        .values()
        .filter(|t| !t.is_active(now))
        .map(|t| t.name.as_str())
        .collect();
    push(
        "tokens",
        if expired_tokens.is_empty() {
            "ok"
        } else {
            "warning"
        },
        if expired_tokens.is_empty() {
            "all active".into()
        } else {
            format!("inactive: {}", expired_tokens.join(", "))
        },
        Some(if expired_tokens.is_empty() {
            crate::msg!("all active", "全部有效")
        } else {
            crate::msg!("inactive: {}", "无效：{}", expired_tokens.join(", "))
        }),
    );

    let soon = now + chrono::Duration::days(30);
    // The audit module owns the four probes (`weak_secrets` / `reused_secrets` /
    // `stale_rotations` / `expiring`); `doctor` consumes the same Report so the two
    // commands can never drift. The existing `expiring` check name is preserved for
    // callers that already pin `akey doctor --json` shape.
    let report = crate::cmd::audit::run(&vault, now);
    for check in crate::cmd::audit::doctor_checks(&report) {
        let name = check["name"].as_str().unwrap_or("").to_string();
        let status = check["status"].as_str().unwrap_or("ok").to_string();
        let detail = check["detail"].as_str().unwrap_or("").to_string();
        let detail_msg = if detail.is_empty() {
            None
        } else {
            Some(detail.clone())
        };
        // Skip the timestamp-dependent expiring detail if the audit already reported
        // the same names; the audit probe is authoritative.
        if name == "expiring" {
            push(&name, &status, detail.clone(), detail_msg);
        } else {
            push(&name, &status, detail, detail_msg);
        }
    }
    let _ = soon; // the audit module owns the window

    let problems = checks.iter().filter(|c| c["status"] == "error").count();
    let human = table.join("\n");

    ctx.out.emit(
        human,
        &serde_json::json!({ "healthy": problems == 0, "errors": problems, "checks": checks }),
    )
}

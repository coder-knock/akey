//! `log` / `schema` / `completion`: audit output and CLI introspection.

use chrono::Utc;
use clap::CommandFactory;

use crate::audit;
use crate::cli::{Cli, CompletionArgs, LogArgs, SchemaArgs};
use crate::cmd::{Ctx, parse_duration};
use crate::error::Result;

pub fn log(ctx: &Ctx, args: &LogArgs) -> Result<()> {
    let cutoff = match &args.since {
        Some(raw) => Some(Utc::now() - parse_duration(raw)?),
        None => None,
    };
    let records = audit::tail(&ctx.paths, args.limit.max(1))?;
    let filtered: Vec<_> = records
        .into_iter()
        .filter(|r| cutoff.is_none_or(|c| r.ts >= c))
        .filter(|r| {
            args.item
                .as_deref()
                .is_none_or(|i| r.subject.as_deref() == Some(i))
        })
        .collect();

    let human = if filtered.is_empty() {
        crate::msg!("no audit records", "没有审计记录")
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
    ctx.out
        .emit(human, &serde_json::json!({ "records": filtered }))
}

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
        crate::msg!(
            "akey schema (use --json for the machine-readable form)",
            "akey schema（使用 --json 获取机器可读形式）"
        ),
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

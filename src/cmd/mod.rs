//! 命令分发与共享上下文。

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::Parser;

use crate::cli::{Cli, Command, SyncArgs};
use crate::error::{Error, Result};
use crate::output::{Format, Output};
use crate::paths::Paths;
use crate::sync::{SyncOutcome, sync};
use crate::vault::model::{Entry, Reveal, TokenMeta, Vault};
use crate::vault::store::Store;

pub mod admin;
pub mod deliver;
pub mod entries;

/// 一次命令调用的共享上下文。**不**要求仓库已初始化——`schema` / `completion` / `--help`
/// 必须能在任何状态下工作。
pub struct Ctx {
    pub out: Output,
    pub paths: Paths,
    repo_override: Option<PathBuf>,
    pub dry_run: bool,
    pub assume_yes: bool,
    pub debug: bool,
    token: Option<String>,
}

impl Ctx {
    pub fn new(cli: &Cli) -> Result<Ctx> {
        let json = cli.json || cli.format == Format::Json;
        let color = !cli.no_color && !json && std::io::stdout().is_terminal();
        let format = if json { Format::Json } else { cli.format };
        Ok(Ctx {
            out: Output::new(format, cli.quiet, color),
            paths: Paths::new(crate::paths::resolve_home(cli.home.as_deref())?),
            repo_override: cli.repo.clone(),
            dry_run: cli.dry_run,
            assume_yes: cli.yes,
            debug: cli.debug,
            token: cli.token.clone().filter(|t| !t.is_empty()),
        })
    }

    /// 打开本机金库上下文。
    pub fn store(&self) -> Result<Store> {
        let mut store = Store::open(self.paths.clone())?;
        if let Some(repo) = &self.repo_override {
            store.config.repo = repo.clone();
        }
        Ok(store)
    }

    pub fn show_progress(&self) -> bool {
        !self.out.quiet()
    }

    /// 破坏性或把明文带出本机边界之外的操作用它挡一道。
    pub fn confirm(&self, what: &str) -> Result<()> {
        if self.assume_yes {
            return Ok(());
        }
        Err(Error::Usage(format!(
            "refusing to {what} without --yes (this writes plaintext outside the vault)"
        )))
    }

    /// 校验 `AKEY_TOKEN` / `--token` 并返回其元数据；无令牌时返回 `None`。
    ///
    /// **不做作用域检查**——作用域判断需要知道条目名，交给 [`Ctx::authorize`]。
    pub fn active_token<'v>(&self, vault: &'v Vault) -> Result<Option<&'v TokenMeta>> {
        let Some(raw) = &self.token else {
            return Ok(None);
        };
        let normalized = crate::crypto::token::normalize(raw)?;
        let now = chrono::Utc::now();
        for meta in vault.tokens.values() {
            if meta.is_active(now) && crate::crypto::token::verify(&normalized, meta).is_ok() {
                return Ok(Some(meta));
            }
        }
        Err(Error::locked(
            "AKEY_TOKEN does not match any active token in this vault",
        ))
    }

    /// 校验令牌并检查它是否有权访问 `entry_name`。
    ///
    /// 无令牌时返回 `None`（本机身份即最高权限）。
    pub fn authorize<'v>(
        &self,
        vault: &'v Vault,
        entry_name: &str,
    ) -> Result<Option<&'v TokenMeta>> {
        let Some(meta) = self.active_token(vault)? else {
            return Ok(None);
        };
        crate::crypto::token::authorize(meta, entry_name, chrono::Utc::now())?;
        Ok(Some(meta))
    }

    /// 明文暴露闸门：条目策略、环境开关、令牌策略三重检查。
    pub fn gate_reveal(&self, vault: &Vault, entry: Option<&Entry>) -> Result<()> {
        if no_reveal_env() {
            return Err(Error::denied(
                "AKEY_NO_REVEAL is set; use `akey run` to inject without exposing the value",
            ));
        }
        if let Some(entry) = entry
            && entry.reveal == Reveal::Deny
        {
            return Err(Error::denied(format!(
                "entry '{}' is marked reveal=deny",
                entry.name
            )));
        }
        if let Some(meta) = self.active_token(vault)? {
            // 先判作用域：令牌根本没资格碰这个条目时，报"越权"比报"不允许取明文"准确得多。
            // agent 只读 error.code，含糊的 code 会让它去改 reveal 策略——而那是错的下一步。
            if let Some(entry) = entry {
                crate::crypto::token::authorize(meta, &entry.name, chrono::Utc::now())?;
            }
            if meta.deny_reveal {
                return Err(Error::denied(format!(
                    "token '{}' was issued with --deny-reveal",
                    meta.name
                )));
            }
        }
        Ok(())
    }

    /// 写操作闸门。
    ///
    /// 能力令牌是**只读凭据**（对标 1Password service account）。若放行写操作，
    /// 一个只被授权读单个条目的 agent 就能改库或删条目——作用域形同虚设。
    pub fn gate_write(&self) -> Result<()> {
        match &self.token {
            Some(_) => Err(Error::denied(
                "this command is running with AKEY_TOKEN, which is a read-only capability; \
                 run it with the local device identity instead",
            )),
            None => Ok(()),
        }
    }

    /// 检查一批文本里出现的每个引用，确认当前令牌有权访问其条目。
    ///
    /// `akey run` / `akey inject` 不经过 `gate_reveal`（它们不把明文交给调用者），
    /// 但**作用域必须照样生效**——否则被限制在单条目的令牌只要把值注入
    /// `sh -c 'cat'` 就能读到任何条目。
    pub fn authorize_references(&self, vault: &Vault, texts: &[String]) -> Result<()> {
        if self.token.is_none() {
            return Ok(());
        }
        for text in texts {
            for raw in crate::reference::extract_references(text) {
                let reference = crate::reference::Reference::parse_in(
                    &raw,
                    &|name| std::env::var(name).ok(),
                )?;
                self.authorize(vault, &reference.item)?;
            }
        }
        Ok(())
    }

    /// 令牌作用域内的条目名集合；无令牌或无限制时返回 `None`（= 全部可见）。
    pub fn scoped_names(&self, vault: &Vault) -> Result<Option<Vec<String>>> {
        Ok(self.active_token(vault)?.and_then(|meta| meta.allow.clone()))
    }
}

/// `AKEY_NO_REVEAL` 只要非空且不是 `0`/`false` 即生效。
fn no_reveal_env() -> bool {
    match std::env::var("AKEY_NO_REVEAL") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false"
        }
        Err(_) => false,
    }
}

/// 解析 `<n><unit>` 形式的时长：`s` `m` `h` `d` `w`，无单位按秒。负数与非法输入 → `Usage`。
///
/// 被 `--expiring 30d`、`--ttl 30d` 共用，所以只有这一份实现。
pub fn parse_duration(raw: &str) -> Result<chrono::Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::usage("empty duration"));
    }
    let (digits, unit) = raw.split_at(
        raw.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(raw.len()),
    );
    let value: i64 = digits
        .parse()
        .map_err(|_| Error::usage(format!("invalid duration '{raw}': expected e.g. 30d, 12h, 90s")))?;
    let seconds = match unit.trim() {
        "" | "s" | "sec" | "secs" => value,
        "m" | "min" | "mins" => value * 60,
        "h" | "hr" | "hrs" => value * 3600,
        "d" | "day" | "days" => value * 86_400,
        "w" | "wk" | "weeks" => value * 604_800,
        other => {
            return Err(Error::usage(format!(
                "invalid duration unit '{other}': use s, m, h, d or w"
            )));
        }
    };
    Ok(chrono::Duration::seconds(seconds))
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let ctx = match Ctx::new(&cli) {
        Ok(ctx) => ctx,
        Err(err) => {
            let fallback = Output::human();
            fallback.error(&err);
            return err.exit_code();
        }
    };
    match dispatch(&ctx, cli.command) {
        Ok(()) => 0,
        Err(err) => {
            ctx.out.error(&err);
            err.exit_code()
        }
    }
}

fn dispatch(ctx: &Ctx, command: Command) -> Result<()> {
    match command {
        Command::Init(args) => admin::init(ctx, &args),
        Command::Devices(args) => admin::devices(ctx, &args),
        Command::Recovery(args) => admin::recovery(ctx, &args),
        Command::Token(args) => admin::token(ctx, &args),
        Command::Whoami => admin::whoami(ctx),
        Command::Doctor(args) => admin::doctor(ctx, &args),
        Command::Schema(args) => admin::schema(ctx, &args),
        Command::Completion(args) => admin::completion(ctx, &args),
        Command::Log(args) => admin::log(ctx, &args),

        Command::Get(args) => entries::get(ctx, &args),
        Command::Set(args) => entries::set(ctx, &args),
        Command::Edit(args) => entries::edit(ctx, &args),
        Command::Rm(args) => entries::rm(ctx, &args),
        Command::Restore(args) => entries::restore(ctx, &args),
        Command::Cp(args) => entries::cp(ctx, &args),
        Command::Mv(args) => entries::mv(ctx, &args),
        Command::List(args) => entries::list(ctx, &args),
        Command::Template(args) => entries::template(ctx, &args),
        Command::Conflicts(args) => entries::conflicts(ctx, &args),
        Command::Resolve(args) => entries::resolve(ctx, &args),

        Command::Read(args) => deliver::read(ctx, &args),
        Command::Run(args) => deliver::run(ctx, &args),
        Command::Inject(args) => deliver::inject(ctx, &args),
        Command::Export(args) => deliver::export(ctx, &args),
        Command::Import(args) => deliver::import(ctx, &args),
        Command::Doc(args) => deliver::doc(ctx, &args),
        Command::Mcp => deliver::mcp(ctx),

        Command::Sync(args) => sync_cmd(ctx, &args),
    }
}

fn sync_cmd(ctx: &Ctx, args: &SyncArgs) -> Result<()> {
    let store = ctx.store()?;
    if ctx.dry_run {
        return ctx.out.emit(
            "dry run: would sync with the configured remote",
            &serde_json::json!({ "action": "sync", "mode": format!("{:?}", args.mode()).to_lowercase() }),
        );
    }
    let outcome = sync(&store, args.mode())?;

    crate::audit::record(
        &ctx.paths,
        store.identity.name(),
        crate::audit::Action::Sync,
        store.config.remote.as_deref(),
        outcome.as_str(),
    )?;

    // 冲突要走**纯错误路径**：失败的命令不得往 stdout 写东西。
    // 合并本身已经提交并推送成功，但需要人来挑一边——agent 应当从退出码察觉。
    if let SyncOutcome::Merged { conflicts, .. } = &outcome
        && !conflicts.is_empty()
    {
        let names: Vec<&str> = conflicts.iter().map(|c| c.name.as_str()).collect();
        return Err(Error::Conflict(format!(
            "merged and pushed, but {} conflicting entr{} need review: {}",
            conflicts.len(),
            if conflicts.len() == 1 { "y" } else { "ies" },
            names.join(", ")
        )));
    }

    let human = match &outcome {
        SyncOutcome::NoRemote => "no remote configured; local vault only".to_string(),
        SyncOutcome::UpToDate => "already up to date".to_string(),
        SyncOutcome::Pulled { commits } => format!("pulled {commits} commit(s)"),
        SyncOutcome::Pushed { commits } => format!("pushed {commits} commit(s)"),
        SyncOutcome::Merged { conflicts, .. } if conflicts.is_empty() => {
            "merged both sides; no conflicts".to_string()
        }
        SyncOutcome::Merged { conflicts, .. } => format!(
            "merged with {} conflict(s); run `akey conflicts` to review",
            conflicts.len()
        ),
        SyncOutcome::Status { ahead, behind } => {
            format!("{ahead} commit(s) ahead, {behind} commit(s) behind")
        }
    };

    let data = serde_json::json!({
        "outcome": outcome.as_str(),
        "summary": human,
        "remote": store.config.remote,
        "conflicts": match &outcome {
            SyncOutcome::Merged { conflicts, .. } => conflicts
                .iter()
                .map(|c| serde_json::json!({
                    "name": c.name,
                    "kind": format!("{:?}", c.kind),
                    "conflict_id": c.conflict_id.to_string(),
                }))
                .collect::<Vec<_>>(),
            _ => vec![],
        },
    });

    ctx.out.emit(human, &data)?;
    Ok(())
}

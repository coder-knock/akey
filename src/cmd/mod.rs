//! Command dispatch and the shared context.

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

/// Shared context for one command invocation. It does **not** require an initialised
/// repository — `schema` / `completion` / `--help` must work in any state.
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

    /// Open the local vault context.
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

    /// Guards destructive operations, or ones that carry plaintext outside this machine's
    /// boundary.
    pub fn confirm(&self, what: &str) -> Result<()> {
        if self.assume_yes {
            return Ok(());
        }
        Err(Error::Usage(crate::msg!(
            "refusing to {} without --yes (this writes plaintext outside the vault)",
            "未提供 --yes 时拒绝{}（这会把明文写到金库之外）",
            what
        )))
    }

    /// Validate `AKEY_TOKEN` / `--token` and return its metadata; `None` when no token is
    /// set.
    ///
    /// **No scope check here** — scoping needs the entry name, so it belongs to
    /// [`Ctx::authorize`].
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
        Err(Error::locked(crate::msg!(
            "AKEY_TOKEN does not match any active token in this vault",
            "AKEY_TOKEN 与本金库中任何有效令牌都不匹配"
        )))
    }

    /// Validate the token and check whether it may access `entry_name`.
    ///
    /// `None` when no token is set (the local device identity is the highest authority).
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

    /// The plaintext-exposure gate: a threefold check of entry policy, environment switch,
    /// and token policy.
    pub fn gate_reveal(&self, vault: &Vault, entry: Option<&Entry>) -> Result<()> {
        if no_reveal_env() {
            return Err(Error::denied(crate::msg!(
                "AKEY_NO_REVEAL is set; use `akey run` to inject without exposing the value",
                "已设置 AKEY_NO_REVEAL；请使用 `akey run` 注入，不要暴露明文"
            )));
        }
        if let Some(entry) = entry
            && entry.reveal == Reveal::Deny
        {
            return Err(Error::denied(crate::msg!(
                "entry '{}' is marked reveal=deny",
                "条目 '{}' 已标记 reveal=deny",
                entry.name
            )));
        }
        if let Some(meta) = self.active_token(vault)? {
            // Check scope first: when the token has no claim on this entry at all,
            // reporting "out of scope" is far more accurate than "plaintext not allowed".
            // An agent reads only error.code, and a vague code sends it off to change the
            // reveal policy — which is the wrong next step.
            if let Some(entry) = entry {
                crate::crypto::token::authorize(meta, &entry.name, chrono::Utc::now())?;
            }
            if meta.deny_reveal {
                return Err(Error::denied(crate::msg!(
                    "token '{}' was issued with --deny-reveal",
                    "令牌 '{}' 签发时带了 --deny-reveal",
                    meta.name
                )));
            }
        }
        Ok(())
    }

    /// The write gate.
    ///
    /// A capability token is a **read-only credential** (modelled on 1Password service
    /// accounts). Letting writes through would mean an agent authorized to read a single
    /// entry could modify the vault or delete entries — scoping would be a sham.
    pub fn gate_write(&self) -> Result<()> {
        match &self.token {
            Some(_) => Err(Error::denied(crate::msg!(
                "this command is running with AKEY_TOKEN, which is a read-only capability; \
                 run it with the local device identity instead",
                "本命令正以 AKEY_TOKEN 运行，它是只读能力；请改用本机设备身份运行"
            ))),
            None => Ok(()),
        }
    }

    /// Check every reference appearing in a batch of texts and confirm the current token
    /// may access its entry.
    ///
    /// `akey run` / `akey inject` do not pass through `gate_reveal` (they do not hand
    /// plaintext to the caller), but **scoping must still apply** — otherwise a token
    /// restricted to a single entry could read any entry by injecting a value into
    /// `sh -c 'cat'`.
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

    /// The set of entry names inside the token's scope; `None` when there is no token or no
    /// restriction (= everything visible).
    pub fn scoped_names(&self, vault: &Vault) -> Result<Option<Vec<String>>> {
        Ok(self.active_token(vault)?.and_then(|meta| meta.allow.clone()))
    }

    /// Diagnostic lines for `--debug`. Always on stderr, and they **report locations only**,
    /// never values.
    ///
    /// This flag used to be dead (assigned but never read), which for a tool whose agents
    /// must diagnose themselves amounted to the docs lying. Now it at least answers "which
    /// home, which repository am I actually operating on".
    pub fn debug_banner(&self) {
        if !self.debug {
            return;
        }
        eprintln!("debug: home  = {}", self.paths.home.display());
        eprintln!(
            "debug: repo  = {}",
            self.repo_override
                .as_deref()
                .map_or_else(|| "(from config.toml)".to_string(), |p| p.display().to_string())
        );
        eprintln!("debug: format = {}", if self.out.is_json() { "json" } else { "human" });
        eprintln!(
            "debug: token  = {}",
            if self.token.is_some() { "present (value withheld)" } else { "none" }
        );
    }

    /// Whether the current principal is forbidden from receiving plaintext.
    ///
    /// When true, every path where plaintext could reach the caller must be closed,
    /// including `--no-masking`.
    pub fn plaintext_forbidden(&self, vault: &Vault) -> Result<bool> {
        if no_reveal_env() {
            return Ok(true);
        }
        Ok(self
            .active_token(vault)?
            .is_some_and(|meta| meta.deny_reveal))
    }

    /// Run every reference appearing in the texts through the reveal gate for its entry.
    ///
    /// `inject` must use this. The design once grouped `inject` and `run` together ("does
    /// not hand plaintext to the caller") — true for `run` (the plaintext goes to a **child
    /// process**, and the child's echo is masked), but **not** for `inject`: what it renders
    /// is written straight to the caller's stdout, making it the batch form of `read`.
    /// Without this gate, `AKEY_NO_REVEAL` and a token's `--deny-reveal` can both be bypassed
    /// with one `printf 'x=akey://a/b' | akey inject`.
    pub fn gate_references_reveal(&self, vault: &Vault, texts: &[String]) -> Result<()> {
        for text in texts {
            for raw in crate::reference::extract_references(text) {
                let reference =
                    crate::reference::Reference::parse_in(&raw, &|name| std::env::var(name).ok())?;
                let entry = vault.find(&reference.item)?;
                self.gate_reveal(vault, Some(entry))?;
            }
        }
        Ok(())
    }
}

/// `AKEY_NO_REVEAL` takes effect as long as it is non-empty and is not `0`/`false`.
fn no_reveal_env() -> bool {
    match std::env::var("AKEY_NO_REVEAL") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false"
        }
        Err(_) => false,
    }
}

/// Parse a duration of the form `<n><unit>`: `s` `m` `h` `d` `w`, with a bare number
/// meaning seconds. Negative and malformed input → `Usage`.
///
/// Shared by `--expiring 30d` and `--ttl 30d`, so this is the single implementation.
pub fn parse_duration(raw: &str) -> Result<chrono::Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::usage(crate::msg!("empty duration", "时长为空")));
    }
    let (digits, unit) = raw.split_at(
        raw.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(raw.len()),
    );
    let value: i64 = digits.parse().map_err(|_| {
        Error::usage(crate::msg!(
            "invalid duration '{}': expected e.g. 30d, 12h, 90s",
            "非法时长 '{}'：应为 30d、12h、90s",
            raw
        ))
    })?;
    let seconds = match unit.trim() {
        "" | "s" | "sec" | "secs" => value,
        "m" | "min" | "mins" => value * 60,
        "h" | "hr" | "hrs" => value * 3600,
        "d" | "day" | "days" => value * 86_400,
        "w" | "wk" | "weeks" => value * 604_800,
        other => {
            return Err(Error::usage(crate::msg!(
                "invalid duration unit '{}': use s, m, h, d or w",
                "非法时长单位 '{}'：请使用 s、m、h、d 或 w",
                other
            )));
        }
    };
    Ok(chrono::Duration::seconds(seconds))
}

pub fn run() -> i32 {
    // Localize before parsing. `--help` is produced by the parse, so the language has to be
    // settled first — hence the argv pre-scan. Precedence is `--lang`, then `$AKEY_LANG`, then
    // the locale variables, then English.
    match crate::i18n::Lang::resolve(crate::i18n::lang_from_argv(std::env::args().skip(1)).as_deref())
    {
        Ok(lang) => crate::i18n::set_lang(lang),
        Err(err) => {
            // Reported in English, because the request itself was for a language that does not
            // exist. Goes through `Output` like every other failure that happens before a
            // `Ctx` exists, rather than a bare stderr line.
            let err = Error::usage(err.to_string());
            Output::human().error(&err);
            return err.exit_code();
        }
    }

    let cli = Cli::parse();
    let ctx = match Ctx::new(&cli) {
        Ok(ctx) => ctx,
        Err(err) => {
            let fallback = Output::human();
            fallback.error(&err);
            return err.exit_code();
        }
    };
    ctx.debug_banner();
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

    // Conflicts must take the **pure-error path**: a failing command must not write to
    // stdout. The merge itself is already committed and pushed, but a human has to pick a
    // side — an agent should notice that from the exit code.
    if let SyncOutcome::Merged { conflicts, .. } = &outcome
        && !conflicts.is_empty()
    {
        let names: Vec<&str> = conflicts.iter().map(|c| c.name.as_str()).collect();
        // English pluralises the noun and Chinese does not, so the noun is the localized unit
        // and the count and names stay separate arguments in both languages.
        let noun = if conflicts.len() == 1 {
            crate::msg!("entry", "条目")
        } else {
            crate::msg!("entries", "条目")
        };
        return Err(Error::Conflict(crate::msg!(
            "merged and pushed, but {} conflicting {} need review: {}",
            "已合并并推送，但 {} 个冲突{}需复核：{}",
            conflicts.len(),
            noun,
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

    // A key sitting in recipients.json that this machine never approved is exactly what a
    // remote-write attacker produces. Surface it loudly: encryption will not use it, but the
    // user has to be the one who decides whether it is a device they actually added.
    let pending = store.pending_recipients()?;

    let data = serde_json::json!({
        "outcome": outcome.as_str(),
        "summary": human,
        "remote": store.config.remote,
        "pending_recipients": pending
            .iter()
            .map(|(name, key)| serde_json::json!({ "name": name, "pubkey": key }))
            .collect::<Vec<_>>(),
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

    if !pending.is_empty() {
        let mut listed = Vec::new();
        for (name, key) in &pending {
            listed.push(format!("{name} ({key})"));
        }
        let joined = listed.join(", ");
        ctx.out.warn(&format!(
            "{} recipient(s) in the repository are not trusted by this machine and will NOT \
             receive ciphertext: {joined}. Run `akey devices trust <name>` if you added them, \
             or `akey doctor` to investigate.",
            pending.len()
        ));
    }
    Ok(())
}

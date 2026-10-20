//! Every vault operation the GUI can perform, as a named method.
//!
//! This is the layer the views call. It exists so that the exact CLI invocation for each
//! user action is written down **once** and can be asserted by a test — in particular the
//! rule that a secret travels on stdin and never in argv (`REQUIREMENTS.md` FR-31).
//!
//! Nothing here decides whether an operation is permitted. The CLI already does that, and
//! its answer arrives as the envelope in [`Outcome`].

use crate::backend::{Backend, BackendError, EXIT_LOCKED, Outcome};
use zeroize::Zeroizing;

/// Filters the list view can apply. Maps to the CLI's own `list` flags, so the GUI never
/// filters in a way the CLI would not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    pub tags: Vec<String>,
    pub category: Option<String>,
    /// Window such as `30d`. Validated by the CLI.
    pub expiring: Option<String>,
    pub favorite: bool,
    /// Include soft-deleted entries.
    pub all: bool,
}

impl ListFilter {
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["list".to_string()];
        if !self.tags.is_empty() {
            args.push("--tags".into());
            args.push(self.tags.join(","));
        }
        if let Some(category) = &self.category {
            args.push("--category".into());
            args.push(category.clone());
        }
        if let Some(window) = &self.expiring {
            args.push("--expiring".into());
            args.push(window.clone());
        }
        if self.favorite {
            args.push("--favorite".into());
        }
        if self.all {
            args.push("--all".into());
        }
        args
    }

    pub fn is_unfiltered(&self) -> bool {
        self == &ListFilter::default()
    }
}

/// Which side of a conflict to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictSide {
    /// The local version (the entry that kept its name).
    Ours,
    /// The remote version (the `<name>.conflict.<short-id>` copy).
    Theirs,
}

impl ConflictSide {
    pub fn flag(self) -> &'static str {
        match self {
            ConflictSide::Ours => "--ours",
            ConflictSide::Theirs => "--theirs",
        }
    }
}

/// How the vault was set up on this machine — the answer to the start-up probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// The vault is present and this device can open it.
    Ready(Box<crate::model::Whoami>),
    /// Exit 4: no identity here. The UI shows the `akey init` instruction and stops.
    Uninitialized {
        message: String,
        hint: Option<String>,
    },
    /// Exit 4 for a reason other than "never initialised" — a revoked device, a wrong
    /// identity. Distinguished so the message can be the CLI's own.
    Locked {
        message: String,
        hint: Option<String>,
    },
    /// The vault is encrypted to a format this CLI is too old to read.
    UnsupportedFormat { message: String },
}

impl Startup {
    pub fn is_ready(&self) -> bool {
        matches!(self, Startup::Ready(_))
    }

    pub fn whoami(&self) -> Option<&crate::model::Whoami> {
        match self {
            Startup::Ready(who) => Some(who),
            _ => None,
        }
    }
}

/// The result of a sync, where "nothing to parse" is itself a meaningful outcome.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncResult {
    /// Present when the CLI exited 0.
    pub report: Option<crate::model::SyncReport>,
    /// The CLI exited 5: the merge is committed and pushed, and a human must pick a side
    /// for each conflict copy. Empty stdout is part of the contract, not a bug.
    pub conflicts_pending: bool,
}

impl SyncResult {
    pub fn needing_resolution(&self) -> bool {
        self.conflicts_pending
    }

    pub fn summary(&self) -> String {
        if self.conflicts_pending {
            return "conflicts need resolution".to_string();
        }
        match &self.report {
            Some(report) if report.summary.is_empty() => report.outcome.clone(),
            Some(report) => report.summary.clone(),
            None => String::new(),
        }
    }
}

#[derive(Clone)]
pub struct Akey {
    backend: Backend,
}

impl Akey {
    pub fn new(backend: Backend) -> Self {
        Akey { backend }
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    fn run(&self, args: &[&str]) -> Result<Outcome, BackendError> {
        self.backend.run(args)
    }

    /// Run a mutating command and preserve the CLI's failure as a failure.
    ///
    /// `Backend::run` intentionally models a non-zero exit as `Outcome::Failure`, but UI
    /// handlers use Rust's `Result` to decide whether to show success. Letting a failure
    /// remain inside `Ok(...)` made denied writes look successful.
    fn mutate(&self, args: &[&str]) -> Result<Outcome, BackendError> {
        require_success(args, self.run(args)?)
    }

    // ─────────────────────────── start-up ───────────────────────────

    /// Probe whether this machine can use a vault, and how.
    ///
    /// `whoami` is chosen over `doctor` because it is the cheapest call that distinguishes
    /// "never initialised" (exit 4, no config) from "present but unusable" (exit 4 for
    /// another reason). `doctor` is run separately, after the window is open.
    pub fn startup(&self) -> Result<Startup, BackendError> {
        match self.run(&["whoami"])? {
            Outcome::Ok(data) => {
                let who: crate::model::Whoami =
                    serde_json::from_value(data).map_err(|e| BackendError::MalformedEnvelope {
                        args: "whoami".into(),
                        detail: format!("data did not match the whoami payload: {e}"),
                    })?;
                Ok(Startup::Ready(Box::new(who)))
            }
            Outcome::Failure {
                exit: EXIT_LOCKED,
                error,
            } => {
                if error.code == "locked" && error.reason.as_deref() == Some("uninitialized") {
                    Ok(Startup::Uninitialized {
                        message: error.message,
                        hint: error.hint,
                    })
                } else {
                    Ok(Startup::Locked {
                        message: error.message,
                        hint: error.hint,
                    })
                }
            }
            Outcome::Failure { error, .. } if error.code == "unsupported" => {
                Ok(Startup::UnsupportedFormat {
                    message: error.message,
                })
            }
            Outcome::Failure { error, .. } => Ok(Startup::Locked {
                message: error.message,
                hint: error.hint,
            }),
        }
    }

    // ─────────────────────────── list / detail ───────────────────────────

    /// `akey list --json`. Metadata only: never a value.
    pub fn list(&self, filter: &ListFilter) -> Result<crate::model::EntryList, BackendError> {
        let args = filter.args();
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let data = self.ok_data(&borrowed)?;
        decode(data, "list")
    }

    /// `akey get <item> --json`. Concealed fields arrive redacted by the CLI.
    pub fn detail(&self, item: &str) -> Result<crate::model::EntryDetail, BackendError> {
        let data = self.ok_data(&["get", item])?;
        decode(data, "get")
    }

    /// `akey get <item> --field <field> --reveal --json`. The **only** call that yields
    /// plaintext, deliberately narrowed to one field so unrelated secrets never enter the
    /// GUI process.
    ///
    /// Whether it is allowed is decided by the CLI: entry `reveal=deny`, `AKEY_NO_REVEAL`,
    /// and a token's `--deny-reveal` all produce exit 7. The GUI does not pre-judge and
    /// does not retry another way.
    pub fn reveal(
        &self,
        item: &str,
        field: &str,
    ) -> Result<crate::model::EntryDetail, BackendError> {
        let data = self.ok_data(&["get", item, "--field", field, "--reveal"])?;
        decode(data, "get --field --reveal")
    }

    // ─────────────────────────── writes ───────────────────────────

    /// `akey set <item> --category <c> --stdin`, with the value on stdin.
    ///
    /// The value is **never** an argument. `field` selects which field receives it; when
    /// absent the CLI targets the category's default secret field.
    pub fn set_secret(
        &self,
        item: &str,
        category: &str,
        field: Option<&str>,
        value: &str,
    ) -> Result<Outcome, BackendError> {
        let mut args: Vec<String> = vec![
            "set".into(),
            item.into(),
            "--category".into(),
            category.into(),
            "--stdin".into(),
        ];
        if let Some(field) = field {
            args.push("--secret-field".into());
            args.push(field.to_string());
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let payload = Zeroizing::new(match field {
            Some(field) => format!("{field}={value}\n"),
            None => format!("{value}\n"),
        });
        let outcome = self.backend.run_with_stdin(&borrowed, &payload)?;
        require_success(&borrowed, outcome)
    }

    /// `akey set <item> <assignments…>` for **non-secret** fields only (host, port, url…).
    ///
    /// Callers must not route a secret here: an assignment is an argument, and arguments
    /// are visible in `ps`. Use [`Akey::set_secret`].
    pub fn set_public_fields(
        &self,
        item: &str,
        assignments: &[String],
    ) -> Result<Outcome, BackendError> {
        let mut args: Vec<&str> = vec!["set", item];
        args.extend(assignments.iter().map(String::as_str));
        self.mutate(&args)
    }

    /// `akey edit <item> …` — metadata only; values are untouched.
    pub fn edit_meta(
        &self,
        item: &str,
        title: Option<&str>,
        tags: Option<&[String]>,
        favorite: Option<bool>,
    ) -> Result<Outcome, BackendError> {
        let mut args: Vec<String> = vec!["edit".into(), item.into()];
        if let Some(title) = title {
            args.push("--title".into());
            args.push(title.to_string());
        }
        if let Some(tags) = tags {
            args.push("--tags".into());
            args.push(tags.join(","));
        }
        match favorite {
            Some(true) => args.push("--favorite".into()),
            Some(false) => args.push("--unfavorite".into()),
            None => {}
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        self.mutate(&borrowed)
    }

    /// `akey edit <item> --reveal-policy allow|deny`.
    pub fn set_reveal_policy(&self, item: &str, allow: bool) -> Result<Outcome, BackendError> {
        self.mutate(&[
            "edit",
            item,
            "--reveal-policy",
            if allow { "allow" } else { "deny" },
        ])
    }

    /// `akey rm <item>`. Soft by default; `purge` is irreversible and the UI must confirm
    /// before reaching here.
    pub fn remove(&self, item: &str, purge: bool) -> Result<Outcome, BackendError> {
        if purge {
            self.mutate(&["rm", item, "--purge"])
        } else {
            self.mutate(&["rm", item])
        }
    }

    pub fn restore(&self, item: &str) -> Result<Outcome, BackendError> {
        self.mutate(&["restore", item])
    }

    // ─────────────────────────── sync ───────────────────────────

    /// `akey sync --json`.
    ///
    /// Exit 5 means "the merge and push succeeded, and conflict copies now exist" — the
    /// CLI deliberately writes nothing to stdout in that case (`DESIGN.md` §8: a failing
    /// command writes no data). So the two outcomes are modelled separately rather than
    /// pretending a report exists.
    pub fn sync(&self) -> Result<SyncResult, BackendError> {
        match self.run(&["sync"])? {
            Outcome::Ok(data) => Ok(SyncResult {
                report: Some(decode(data, "sync")?),
                conflicts_pending: false,
            }),
            Outcome::Failure { exit, error: _ } if exit == crate::backend::EXIT_CONFLICT => {
                Ok(SyncResult {
                    report: None,
                    conflicts_pending: true,
                })
            }
            Outcome::Failure { exit, error } => Err(BackendError::CommandFailed {
                args: "sync".into(),
                exit,
                error,
            }),
        }
    }

    pub fn conflicts(&self) -> Result<crate::model::Conflicts, BackendError> {
        let data = self.ok_data(&["conflicts"])?;
        decode(data, "conflicts")
    }

    pub fn resolve(&self, name: &str, side: ConflictSide) -> Result<Outcome, BackendError> {
        self.mutate(&["resolve", name, side.flag()])
    }

    // ─────────────────────────── devices / tokens ───────────────────────────

    pub fn devices(&self) -> Result<crate::model::DeviceList, BackendError> {
        let data = self.ok_data(&["devices", "list"])?;
        decode(data, "devices list")
    }

    /// Approve a device so it receives ciphertext. A human decision, made per machine.
    pub fn trust_device(&self, name: &str) -> Result<Outcome, BackendError> {
        self.mutate(&["devices", "trust", name])
    }

    pub fn untrust_device(&self, name: &str) -> Result<Outcome, BackendError> {
        self.mutate(&["devices", "untrust", name])
    }

    pub fn remove_device(&self, name: &str) -> Result<Outcome, BackendError> {
        self.mutate(&["devices", "rm", name])
    }

    pub fn tokens(&self) -> Result<crate::model::TokenList, BackendError> {
        let data = self.ok_data(&["token", "list"])?;
        decode(data, "token list")
    }

    /// Issue a capability token. The plaintext comes back **once**, in `data.token`; the
    /// caller must not persist it.
    pub fn create_token(
        &self,
        name: &str,
        allow: Option<&[String]>,
        deny_reveal: bool,
        ttl: &str,
    ) -> Result<Outcome, BackendError> {
        let mut args: Vec<String> = vec![
            "token".into(),
            "create".into(),
            "--name".into(),
            name.into(),
        ];
        if let Some(allow) = allow {
            args.push("--allow".into());
            args.push(allow.join(","));
        }
        if deny_reveal {
            args.push("--deny-reveal".into());
        }
        args.push("--ttl".into());
        args.push(ttl.to_string());
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        self.mutate(&borrowed)
    }

    pub fn revoke_token(&self, name: &str) -> Result<Outcome, BackendError> {
        self.mutate(&["token", "rm", name])
    }

    // ─────────────────────────── recovery ───────────────────────────

    pub fn recovery_status(&self) -> Result<crate::model::RecoveryStatus, BackendError> {
        let data = self.ok_data(&["recovery", "status"])?;
        decode(data, "recovery status")
    }

    /// Create the recovery passphrase (and the bootstrap identity) for the first time.
    /// The passphrase travels on **stdin**.
    pub fn recovery_set(
        &self,
        passphrase: &str,
        min_len: Option<u16>,
    ) -> Result<Outcome, BackendError> {
        self.recovery_passphrase_command(&["recovery", "set"], passphrase, min_len)
    }

    /// Replace the recovery passphrase. The **old** one goes on stdin; the new one cannot,
    /// because the CLI consumes stdin to EOF on its first read and there is only one
    /// stream. See [`Backend::run_with_stdin_and_env`].
    pub fn recovery_rotate(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
        min_len: Option<u16>,
    ) -> Result<Outcome, BackendError> {
        let mut args: Vec<String> = vec!["recovery".into(), "rotate".into()];
        if let Some(min_len) = min_len {
            args.push("--min-passphrase-len".into());
            args.push(min_len.to_string());
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let outcome = self.backend.run_with_stdin_and_env(
            &borrowed,
            old_passphrase,
            &[("AKEY_NEW_RECOVERY_PASSPHRASE", new_passphrase)],
        )?;
        require_success(&borrowed, outcome)
    }

    /// Verify a recovery passphrase without changing anything. Passphrase on **stdin**.
    pub fn recovery_unlock(&self, passphrase: &str) -> Result<Outcome, BackendError> {
        self.recovery_passphrase_command(&["recovery", "unlock"], passphrase, None)
    }

    fn recovery_passphrase_command(
        &self,
        base: &[&str],
        passphrase: &str,
        min_len: Option<u16>,
    ) -> Result<Outcome, BackendError> {
        let mut args: Vec<String> = base.iter().map(|s| s.to_string()).collect();
        if let Some(min_len) = min_len {
            args.push("--min-passphrase-len".into());
            args.push(min_len.to_string());
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let outcome = self.backend.run_with_stdin(&borrowed, passphrase)?;
        require_success(&borrowed, outcome)
    }

    // ─────────────────────────── diagnostics ───────────────────────────

    pub fn doctor(&self) -> Result<crate::model::Doctor, BackendError> {
        let data = self.ok_data(&["doctor"])?;
        decode(data, "doctor")
    }

    pub fn audit(&self) -> Result<crate::model::AuditReport, BackendError> {
        let data = self.ok_data(&["audit"])?;
        decode(data, "audit")
    }

    /// `akey generate <recipe>` — local, no vault required.
    pub fn generate(&self, recipe: &str) -> Result<String, BackendError> {
        let data = self.ok_data(&["generate", recipe])?;
        data.get("password")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| BackendError::MalformedEnvelope {
                args: "generate".into(),
                detail: "data.password was missing".into(),
            })
    }

    // ─────────────────────────── plumbing ───────────────────────────

    /// Run a read verb and require an `ok` envelope with a payload.
    ///
    /// A valid failure envelope stays a command failure; malformed output is reserved for
    /// actual protocol violations.
    fn ok_data(&self, args: &[&str]) -> Result<serde_json::Value, BackendError> {
        match self.run(args)? {
            Outcome::Ok(data) => Ok(data),
            Outcome::Failure { exit, error } => Err(BackendError::CommandFailed {
                args: args.join(" "),
                exit,
                error,
            }),
        }
    }
}

fn require_success(args: &[&str], outcome: Outcome) -> Result<Outcome, BackendError> {
    match outcome {
        ok @ Outcome::Ok(_) => Ok(ok),
        Outcome::Failure { exit, error } => Err(BackendError::CommandFailed {
            args: args.join(" "),
            exit,
            error,
        }),
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    data: serde_json::Value,
    what: &str,
) -> Result<T, BackendError> {
    serde_json::from_value(data).map_err(|e| BackendError::MalformedEnvelope {
        args: what.into(),
        detail: format!("data did not match the {what} payload: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::testing::{RecordingStub, canned};

    fn akey_with(bin: &std::path::Path) -> Akey {
        Akey::new(Backend::with_bin(bin))
    }

    #[test]
    fn list_filter_arguments_match_the_cli_flags() {
        let filter = ListFilter {
            tags: vec!["llm".into(), "prod".into()],
            category: Some("apikey".into()),
            expiring: Some("30d".into()),
            favorite: true,
            all: true,
        };
        assert_eq!(
            filter.args(),
            vec![
                "list",
                "--tags",
                "llm,prod",
                "--category",
                "apikey",
                "--expiring",
                "30d",
                "--favorite",
                "--all"
            ]
        );
        assert!(!filter.is_unfiltered());
        assert!(ListFilter::default().is_unfiltered());
        assert_eq!(ListFilter::default().args(), vec!["list"]);
    }

    #[test]
    fn conflict_side_maps_to_the_cli_flag() {
        assert_eq!(ConflictSide::Ours.flag(), "--ours");
        assert_eq!(ConflictSide::Theirs.flag(), "--theirs");
    }

    #[cfg(unix)]
    #[test]
    fn startup_ready_when_whoami_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":true,"data":{"device":"macbook","entries":3,"token_scope":null}}"#,
            0,
        );
        let startup = akey_with(&bin).startup().unwrap();
        assert!(startup.is_ready());
        assert_eq!(startup.whoami().unwrap().device, "macbook");
    }

    #[cfg(unix)]
    #[test]
    fn startup_maps_a_missing_vault_to_the_init_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"locked","reason":"uninitialized","message":"no vault at /h/repo; run `akey init` or `akey init --from <url>`","hint":"run `akey doctor`"}}"#,
            EXIT_LOCKED,
        );
        let startup = akey_with(&bin).startup().unwrap();
        assert!(
            matches!(startup, Startup::Uninitialized { .. }),
            "exit 4 from a missing vault is the init case: {startup:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_maps_a_missing_config_to_the_init_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"locked","reason":"uninitialized","message":"/h/config.toml 处没有配置；请运行 `akey init`","hint":"运行 `akey doctor`"}}"#,
            EXIT_LOCKED,
        );
        let startup = akey_with(&bin).startup().unwrap();
        assert!(matches!(startup, Startup::Uninitialized { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn startup_distinguishes_a_revoked_device_from_an_absent_vault() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"locked","message":"decryption failed; device 'old' may have been removed with `akey devices rm`"}}"#,
            EXIT_LOCKED,
        );
        let startup = akey_with(&bin).startup().unwrap();
        assert!(
            matches!(startup, Startup::Locked { .. }),
            "a revoked device is not 'never initialised': {startup:?}"
        );
        assert!(!startup.is_ready());
    }

    #[cfg(unix)]
    #[test]
    fn startup_reports_a_newer_vault_format_separately() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"unsupported","message":"vault format v9 is newer than this build supports (v2); upgrade akey"}}"#,
            1,
        );
        let startup = akey_with(&bin).startup().unwrap();
        assert!(matches!(startup, Startup::UnsupportedFormat { .. }));
    }

    /// Reveal must pass `--reveal` explicitly — there is no other path to plaintext.
    #[cfg(unix)]
    #[test]
    fn reveal_uses_the_explicit_flag_and_returns_the_detail() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(
            dir.path(),
            r#"{"ok":true,"data":{"id":"01A","name":"openai","fields":[{"id":"credential","type":"concealed","concealed":true,"value":"sk-real","reference":"akey://default/openai/credential"}]}}"#,
        );
        let detail = akey_with(&stub.bin).reveal("openai", "credential").unwrap();
        assert_eq!(detail.fields[0].shown_value(), "sk-real");
        assert!(
            stub.argv().contains(&"--reveal".to_string()),
            "the reveal path must be explicit: {:?}",
            stub.argv()
        );
        let argv = stub.argv();
        let field_flag = argv.iter().position(|arg| arg == "--field").unwrap();
        assert_eq!(
            argv.get(field_flag + 1).map(String::as_str),
            Some("credential")
        );
    }

    /// …whereas a plain `detail` must **not** ask for `--reveal`.
    #[cfg(unix)]
    #[test]
    fn detail_does_not_request_reveal() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(
            dir.path(),
            r#"{"ok":true,"data":{"id":"01A","name":"openai","fields":[]}}"#,
        );
        akey_with(&stub.bin).detail("openai").unwrap();
        assert!(
            !stub.argv().contains(&"--reveal".to_string()),
            "a plain get must not ask for plaintext: {:?}",
            stub.argv()
        );
    }

    /// FR-31: a secret reaches the child on **stdin**, and the argv carries only the
    /// field *name* and `--stdin`.
    #[cfg(unix)]
    #[test]
    fn set_secret_puts_the_value_on_stdin_and_never_in_argv() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        let akey = akey_with(&stub.bin);

        let secret = "sk-canary-NEVER-IN-ARGV";
        let outcome = akey
            .set_secret("openai", "apikey", Some("credential"), secret)
            .unwrap();
        assert!(outcome.is_ok());

        let argv = stub.argv();
        assert!(
            !argv.iter().any(|a| a.contains(secret)),
            "secret leaked into argv: {argv:?}"
        );
        assert!(argv.contains(&"--stdin".to_string()), "{argv:?}");
        assert!(argv.contains(&"--category".to_string()), "{argv:?}");
        assert!(argv.contains(&"credential".to_string()), "{argv:?}");
        assert_eq!(stub.stdin(), format!("credential={secret}\n"));
    }

    #[cfg(unix)]
    #[test]
    fn set_secret_without_a_field_sends_a_bare_value() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        akey_with(&stub.bin)
            .set_secret("wifi", "password", None, "wifi-secret-123")
            .unwrap();
        // A bare value targets the category's default secret field, chosen by the CLI.
        assert_eq!(stub.stdin(), "wifi-secret-123\n");
        assert!(!stub.argv_joined().contains("--secret-field"));
    }

    #[cfg(unix)]
    #[test]
    fn recovery_unlock_never_uses_the_environment_variable() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        // The stub only echoes success; what matters is that the passphrase arrived on
        // stdin rather than in the environment or argv.
        let passphrase = "correct horse battery staple";
        akey_with(&stub.bin).recovery_unlock(passphrase).unwrap();
        assert!(
            !stub.argv_joined().contains(passphrase),
            "passphrase leaked into argv"
        );
        assert_eq!(stub.stdin(), passphrase);
    }

    #[cfg(unix)]
    #[test]
    fn edit_meta_maps_each_flag() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        akey_with(&stub.bin)
            .edit_meta(
                "openai",
                Some("OpenAI prod"),
                Some(&["llm".to_string(), "prod".to_string()]),
                Some(true),
            )
            .unwrap();
        let argv = stub.argv();
        assert_eq!(
            argv,
            vec![
                "--json",
                "edit",
                "openai",
                "--title",
                "OpenAI prod",
                "--tags",
                "llm,prod",
                "--favorite"
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn edit_meta_with_unfavorite_uses_the_negative_flag() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        akey_with(&stub.bin)
            .edit_meta("openai", None, None, Some(false))
            .unwrap();
        assert!(stub.argv().contains(&"--unfavorite".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn reveal_policy_maps_to_allow_and_deny() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        let akey = akey_with(&stub.bin);
        akey.set_reveal_policy("openai", false).unwrap();
        assert!(stub.argv().contains(&"deny".to_string()));
        assert!(!stub.argv().contains(&"allow".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn remove_only_purges_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        let akey = akey_with(&stub.bin);
        akey.remove("openai", false).unwrap();
        assert!(!stub.argv().contains(&"--purge".to_string()));
        akey.remove("openai", true).unwrap();
        assert!(stub.argv().contains(&"--purge".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn mutation_failures_are_not_reported_as_rust_success() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"denied","message":"write denied"}}"#,
            crate::backend::EXIT_DENIED,
        );
        let error = akey_with(&bin).remove("openai", false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("denied"), "{message}");
        assert!(message.contains("write denied"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn create_token_maps_scope_and_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        akey_with(&stub.bin)
            .create_token(
                "ci-narrow",
                Some(&["openai".to_string(), "anthropic".to_string()]),
                true,
                "30d",
            )
            .unwrap();
        let argv = stub.argv();
        assert_eq!(
            argv,
            vec![
                "--json",
                "token",
                "create",
                "--name",
                "ci-narrow",
                "--allow",
                "openai,anthropic",
                "--deny-reveal",
                "--ttl",
                "30d"
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_token_without_a_scope_omits_the_allow_flag() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        akey_with(&stub.bin)
            .create_token("wide", None, false, "7d")
            .unwrap();
        let argv = stub.argv();
        assert!(!argv.contains(&"--allow".to_string()), "{argv:?}");
        assert!(!argv.contains(&"--deny-reveal".to_string()), "{argv:?}");
    }

    #[cfg(unix)]
    #[test]
    fn devices_and_tokens_decode_their_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":true,"data":{"devices":[{"name":"macbook","this_device":true,"active":true}]}}"#,
            0,
        );
        let devices = akey_with(&bin).devices().unwrap();
        assert!(devices.devices[0].this_device);

        let dir2 = tempfile::tempdir().unwrap();
        let bin2 = canned(
            dir2.path(),
            r#"{"ok":true,"data":{"tokens":[{"name":"ci","allow":["openai"],"active":true}]}}"#,
            0,
        );
        let tokens = akey_with(&bin2).tokens().unwrap();
        assert_eq!(tokens.tokens[0].name, "ci");
    }

    /// `sync` exits 5 when a merge produced conflicts — the push already succeeded, so the
    /// GUI must treat that as "done, with conflicts to show", not as a failure. The CLI
    /// writes nothing to stdout in that case, so there is no report to parse.
    #[cfg(unix)]
    #[test]
    fn sync_accepts_exit_5_as_a_successful_merge_needing_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"conflict","message":"2 conflict copies created"}}"#,
            crate::backend::EXIT_CONFLICT,
        );
        let result = akey_with(&bin).sync().unwrap();
        assert!(result.conflicts_pending);
        assert!(result.needing_resolution());
        assert!(result.report.is_none(), "exit 5 carries no stdout payload");
        assert_eq!(result.summary(), "conflicts need resolution");
    }

    #[cfg(unix)]
    #[test]
    fn sync_success_carries_a_report() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":true,"data":{"outcome":"no_remote","summary":"no remote configured; local vault only","conflicts":[],"pending_recipients":[]}}"#,
            0,
        );
        let result = akey_with(&bin).sync().unwrap();
        assert!(!result.conflicts_pending);
        assert_eq!(result.report.as_ref().unwrap().outcome, "no_remote");
        assert_eq!(result.summary(), "no remote configured; local vault only");
    }

    #[cfg(unix)]
    #[test]
    fn sync_still_rejects_a_genuine_failure() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"sync_failed","message":"remote unreachable"}}"#,
            6,
        );
        let err = akey_with(&bin).sync().unwrap_err();
        assert!(err.to_string().contains("sync_failed"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rotate_sends_the_old_on_stdin_and_the_new_in_the_env() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        let old = "old-passphrase-long-enough";
        let new = "new-passphrase-long-enough";
        akey_with(&stub.bin)
            .recovery_rotate(old, new, Some(16))
            .unwrap();
        let argv = stub.argv();
        assert!(
            !argv.iter().any(|a| a.contains(old) || a.contains(new)),
            "{argv:?}"
        );
        assert!(
            argv.contains(&"--min-passphrase-len".to_string()),
            "{argv:?}"
        );
        assert!(argv.contains(&"16".to_string()), "{argv:?}");
        assert_eq!(stub.stdin(), old, "the old passphrase rides stdin");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_set_passes_the_minimum_length_flag() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);
        let passphrase = "a-long-enough-passphrase";
        akey_with(&stub.bin)
            .recovery_set(passphrase, Some(20))
            .unwrap();
        let argv = stub.argv();
        assert_eq!(
            argv,
            vec!["--json", "recovery", "set", "--min-passphrase-len", "20"]
        );
        assert_eq!(stub.stdin(), passphrase);
    }

    #[cfg(unix)]
    #[test]
    fn generate_returns_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":true,"data":{"password":"AqAXqaYkPnbpaHBN"}}"#,
            0,
        );
        assert_eq!(
            akey_with(&bin).generate("letters,16").unwrap(),
            "AqAXqaYkPnbpaHBN"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generate_without_a_password_key_is_a_malformed_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(dir.path(), r#"{"ok":true,"data":{}}"#, 0);
        let err = akey_with(&bin).generate("").unwrap_err();
        assert!(err.to_string().contains("password"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn audit_decodes_an_empty_payload_as_clean() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(dir.path(), r#"{"ok":true,"data":{}}"#, 0);
        assert!(akey_with(&bin).audit().unwrap().is_clean());
    }

    #[cfg(unix)]
    #[test]
    fn detail_does_not_carry_plaintext_for_a_concealed_field() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":true,"data":{"id":"01A","name":"openai","fields":[{"id":"credential","type":"concealed","concealed":true,"value":"********","reference":"akey://default/openai/credential"}]}}"#,
            0,
        );
        let detail = akey_with(&bin).detail("openai").unwrap();
        assert!(detail.fields[0].is_placeholder());
    }
}

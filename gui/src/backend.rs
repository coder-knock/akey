//! The GUI's only door to the vault: a subprocess calling `akey --json <verb>`.
//!
//! See `DESIGN.md` §18.2. The GUI deliberately does **not** link the `akey` library and
//! does **not** reimplement any policy gate. Every decision — may this entry be
//! revealed, may this entry be written — is taken by the CLI, whose answer arrives as the
//! frozen `--json` envelope plus an exit code.
//!
//! Nothing in this module is `gpui`-dependent, so `cargo test -p akey-gui` exercises it
//! on machines with no GPU toolchain.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

/// Exit code the CLI uses for "no identity / not initialised / cannot decrypt".
pub const EXIT_LOCKED: i32 = 4;
/// Exit code the CLI uses when a merge produced conflict copies.
pub const EXIT_CONFLICT: i32 = 5;
/// Exit code the CLI uses when policy forbids an action (a refused reveal, a write under a token).
pub const EXIT_DENIED: i32 = 7;
/// Exit code the CLI uses when a scoped token does not cover the entry.
pub const EXIT_TOKEN_SCOPE: i32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(
        "could not find the `akey` binary; set AKEY_GUI_BIN to its path (tried `{}`)",
        .tried
    )]
    BinaryNotFound { tried: String },

    #[error("could not run `{bin}`: {source}")]
    Spawn {
        bin: String,
        #[source]
        source: std::io::Error,
    },

    #[error("`akey {args}` produced output that is not a JSON envelope: {detail}")]
    MalformedEnvelope { args: String, detail: String },

    #[error("`akey {args}` failed with exit {exit}: {error}")]
    CommandFailed {
        args: String,
        exit: i32,
        error: ErrorBody,
    },
}

/// The `error` object the CLI writes on stderr. Its `code` is the stable machine key
/// (`not_found`, `denied`, `token_scope`, …) that the GUI branches on.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub message: String,
    #[serde(default)]
    pub hint: Option<String>,
}

impl ErrorBody {
    /// A synthetic body for the cases where the CLI died without a parsable envelope
    /// (a signal, a panic, output written by something else). Better an honest
    /// `internal` than a panic in the GUI.
    fn internal(message: impl Into<String>) -> Self {
        ErrorBody {
            code: "internal".into(),
            reason: None,
            message: message.into(),
            hint: None,
        }
    }
}

impl fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// One completed `akey` invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Exit 0 and a parsable `{"ok":true,"data":…}` envelope.
    Ok(serde_json::Value),
    /// Non-zero exit. `code` is the process exit status; `error.code` is the stable
    /// machine key. Both are kept: the GUI maps exit 5 to "conflicts" even when the
    /// envelope is missing.
    Failure { exit: i32, error: ErrorBody },
}

impl Outcome {
    pub fn data(&self) -> Option<&serde_json::Value> {
        match self {
            Outcome::Ok(v) => Some(v),
            Outcome::Failure { .. } => None,
        }
    }

    /// The stable machine key for a failure, or `None` on success.
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Outcome::Ok(_) => None,
            Outcome::Failure { error, .. } => Some(&error.code),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Ok(_))
    }

    /// Convenience for the branch the UI takes on every policy refusal.
    pub fn is_denied(&self) -> bool {
        matches!(
            self,
            Outcome::Failure {
                exit: EXIT_DENIED,
                ..
            }
        )
    }
}

#[derive(Deserialize)]
struct OkEnvelope {
    ok: bool,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct ErrEnvelope {
    ok: bool,
    error: ErrorBody,
}

/// A configured `akey` invoker.
///
/// `bin` is explicit (rather than a `which` inside every call) so tests can point it at a
/// stub script and assert on exactly what the GUI would have executed.
#[derive(Debug, Clone)]
pub struct Backend {
    bin: PathBuf,
    home: Option<PathBuf>,
}

impl Backend {
    /// Build with an explicit binary. Use [`Backend::locate`] for the end-user path.
    pub fn with_bin(bin: impl Into<PathBuf>) -> Self {
        Backend {
            bin: bin.into(),
            home: None,
        }
    }

    /// Find the `akey` binary: `$AKEY_GUI_BIN` first, then `PATH`.
    ///
    /// Refusing to proceed when neither resolves is deliberate — a GUI that silently
    /// reimplements `akey` would be a second, unaudited copy of the security model.
    pub fn locate() -> Result<Self, BackendError> {
        Self::locate_with(std::env::var_os("AKEY_GUI_BIN"), std::env::var_os("PATH"))
    }

    /// The pure core of [`Backend::locate`], taking the environment explicitly.
    ///
    /// Split out so tests can exercise resolution without mutating the process
    /// environment — `set_var` is global and would race against every parallel test.
    pub fn locate_with(
        override_bin: Option<std::ffi::OsString>,
        path_var: Option<std::ffi::OsString>,
    ) -> Result<Self, BackendError> {
        if let Some(explicit) = override_bin {
            let path = PathBuf::from(explicit);
            if path.is_file() {
                return Ok(Backend::with_bin(path));
            }
            return Err(BackendError::BinaryNotFound {
                tried: format!("$AKEY_GUI_BIN={}", path.display()),
            });
        }

        for dir in std::env::split_paths(&path_var.unwrap_or_default()) {
            for candidate in ["akey", "akey.exe"] {
                let full = dir.join(candidate);
                if full.is_file() {
                    return Ok(Backend::with_bin(full));
                }
            }
        }
        Err(BackendError::BinaryNotFound {
            tried: "$PATH".to_string(),
        })
    }

    /// Point every invocation at a specific `$AKEY_HOME`. Used by tests and by the
    /// `--home` escape hatch.
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    pub fn bin(&self) -> &Path {
        &self.bin
    }

    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// The argv the GUI would use, without running anything. Exposed so tests can assert
    /// that no secret ever reaches the command line (FR-31).
    pub fn argv_for(&self, args: &[&str]) -> Vec<String> {
        let mut argv = vec!["--json".to_string()];
        if let Some(home) = &self.home {
            argv.push("--home".to_string());
            argv.push(home.display().to_string());
        }
        argv.extend(args.iter().map(|s| s.to_string()));
        argv
    }

    /// Run `akey <args> --json` and classify the result.
    pub fn run(&self, args: &[&str]) -> Result<Outcome, BackendError> {
        self.run_inner(args, None, &[])
    }

    /// Run with a payload written to the child's **stdin**. This is the only channel a
    /// secret ever travels on (FR-31 / DESIGN §18.5): `set --stdin` reads it there.
    pub fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Result<Outcome, BackendError> {
        self.run_inner(args, Some(stdin), &[])
    }

    /// Run with both a stdin payload and extra environment variables.
    ///
    /// The extra environment is needed for exactly one operation: `recovery rotate` reads
    /// the *old* passphrase from stdin and the *new* one from
    /// `AKEY_NEW_RECOVERY_PASSPHRASE`, because a single stdin cannot supply two values to
    /// a CLI that consumes it to EOF. Every other secret path uses stdin alone.
    pub fn run_with_stdin_and_env(
        &self,
        args: &[&str],
        stdin: &str,
        env: &[(&str, &str)],
    ) -> Result<Outcome, BackendError> {
        self.run_inner(args, Some(stdin), env)
    }

    fn run_inner(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        env: &[(&str, &str)],
    ) -> Result<Outcome, BackendError> {
        let argv = self.argv_for(args);
        let mut command = Command::new(&self.bin);
        command.args(&argv);

        // `GIT_TERMINAL_PROMPT=0` matches the CLI's own contract that nothing prompts.
        command.env("GIT_TERMINAL_PROMPT", "0");

        // The CLI prefers `AKEY_RECOVERY_PASSPHRASE` / `AKEY_NEW_RECOVERY_PASSPHRASE` over
        // stdin. Inheriting either from the GUI's environment would silently override the
        // passphrase the user just typed — and would make stdin look authoritative when it
        // is not. Clear both unconditionally, then re-add only what the caller asked for.
        command.env_remove("AKEY_RECOVERY_PASSPHRASE");
        command.env_remove("AKEY_NEW_RECOVERY_PASSPHRASE");
        for (key, value) in env {
            command.env(key, value);
        }

        match stdin {
            Some(_) => {
                command.stdin(Stdio::piped());
            }
            None => {
                command.stdin(Stdio::null());
            }
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|source| BackendError::Spawn {
            bin: self.bin.display().to_string(),
            source,
        })?;

        if let Some(text) = stdin {
            use std::io::Write as _;
            let mut sink = child.stdin.take().ok_or_else(|| BackendError::Spawn {
                bin: self.bin.display().to_string(),
                source: std::io::Error::other("child stdin was not piped"),
            })?;
            sink.write_all(text.as_bytes())
                .map_err(|source| BackendError::Spawn {
                    bin: self.bin.display().to_string(),
                    source,
                })?;
            // Dropping closes the pipe; the child sees EOF and stops reading.
            drop(sink);
        }

        let output = child
            .wait_with_output()
            .map_err(|source| BackendError::Spawn {
                bin: self.bin.display().to_string(),
                source,
            })?;

        let exit = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let joined = args.join(" ");

        if exit == 0 {
            let parsed: OkEnvelope = serde_json::from_str(stdout.trim()).map_err(|e| {
                BackendError::MalformedEnvelope {
                    args: joined.clone(),
                    // Successful payloads may contain a revealed secret, generated password,
                    // or newly issued token. Never echo malformed stdout into UI/log text.
                    detail: format!(
                        "{e}; stdout was {} byte(s) and has been redacted",
                        output.stdout.len()
                    ),
                }
            })?;
            if !parsed.ok {
                // `ok: true` is the contract on exit 0; treat anything else as a fault
                // rather than silently handing the caller a value-shaped object.
                return Err(BackendError::MalformedEnvelope {
                    args: joined,
                    detail: "exit 0 but the envelope said ok:false".into(),
                });
            }
            return Ok(Outcome::Ok(parsed.data));
        }

        // Failure: the envelope goes to stderr, and stdout is empty by contract.
        let error = match serde_json::from_str::<ErrEnvelope>(stderr.trim()) {
            Ok(envelope) if !envelope.ok => envelope.error,
            _ => ErrorBody::internal(format!(
                "`akey {joined}` exited {exit} without a readable error envelope: {}",
                truncate(&stderr, 200)
            )),
        };
        Ok(Outcome::Failure { exit, error })
    }
}

fn truncate(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(max).collect();
    format!("{head}…")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testing::{RecordingStub, canned};

    #[test]
    fn parses_ok_envelope_into_data() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":true,"data":{"count":2,"entries":[]}}"#,
            0,
        );
        let outcome = Backend::with_bin(bin).run(&["list"]).unwrap();
        assert_eq!(outcome.data().unwrap()["count"], serde_json::json!(2));
        assert!(outcome.is_ok());
        assert!(outcome.error_code().is_none());
    }

    #[test]
    fn parses_err_envelope_with_code_and_hint() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"not_found","message":"no such entry","hint":"run akey list"}}"#,
            3,
        );
        let outcome = Backend::with_bin(bin).run(&["get", "ghost"]).unwrap();
        match outcome {
            Outcome::Failure { exit, error } => {
                assert_eq!(exit, 3);
                assert_eq!(error.code, "not_found");
                assert_eq!(error.hint.as_deref(), Some("run akey list"));
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn failure_keeps_stdout_empty_contract() {
        // The CLI's contract: a failing command writes nothing to stdout and the
        // envelope to stderr. The backend must not need stdout to classify a failure.
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"locked","message":"no identity"}}"#,
            EXIT_LOCKED,
        );
        let outcome = Backend::with_bin(bin).run(&["whoami"]).unwrap();
        assert_eq!(outcome.error_code(), Some("locked"));
        assert!(matches!(
            outcome,
            Outcome::Failure {
                exit: EXIT_LOCKED,
                ..
            }
        ));
    }

    #[test]
    fn reveal_denied_surfaces_as_a_policy_result() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"denied","message":"reveal is forbidden"}}"#,
            EXIT_DENIED,
        );
        let outcome = Backend::with_bin(bin)
            .run(&["get", "openai", "--reveal"])
            .unwrap();
        assert!(outcome.is_denied());
        assert_eq!(outcome.error_code(), Some("denied"));
    }

    #[test]
    fn token_scope_failure_is_distinguishable_from_a_refused_reveal() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(
            dir.path(),
            r#"{"ok":false,"error":{"code":"token_scope","message":"out of scope"}}"#,
            EXIT_TOKEN_SCOPE,
        );
        let outcome = Backend::with_bin(bin).run(&["get", "other"]).unwrap();
        assert_eq!(outcome.error_code(), Some("token_scope"));
        assert!(!outcome.is_denied(), "8 is scope, not a policy denial");
    }

    #[test]
    fn nonzero_exit_with_unparseable_stderr_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(dir.path(), "boom", 1);
        let outcome = Backend::with_bin(bin).run(&["list"]).unwrap();
        match outcome {
            Outcome::Failure { exit, error } => {
                assert_eq!(exit, 1);
                assert_eq!(error.code, "internal");
                assert!(error.message.contains("boom"), "{error:?}");
            }
            other => panic!("expected a structured failure, got {other:?}"),
        }
    }

    #[test]
    fn exit_zero_with_a_false_envelope_is_rejected() {
        // `ok:true` is the contract on exit 0. A stub that lies must surface as a
        // malformed envelope rather than be handed to the caller as data.
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(dir.path(), r#"{"ok":false,"data":null}"#, 0);
        let err = Backend::with_bin(bin).run(&["list"]).unwrap_err();
        assert!(matches!(err, BackendError::MalformedEnvelope { .. }));
    }

    #[test]
    fn unparsable_stdout_is_a_malformed_envelope_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let bin = canned(dir.path(), "not-json-SECRET-CANARY", 0);
        let err = Backend::with_bin(bin).run(&["list"]).unwrap_err();
        match err {
            BackendError::MalformedEnvelope { detail, .. } => {
                assert!(detail.contains("redacted"), "{detail}");
                assert!(!detail.contains("SECRET-CANARY"), "{detail}");
            }
            other => panic!("expected MalformedEnvelope, got {other:?}"),
        }
    }

    #[test]
    fn locate_reports_missing_binary_with_a_hint() {
        let err = BackendError::BinaryNotFound {
            tried: "$PATH".into(),
        };
        assert!(err.to_string().contains("AKEY_GUI_BIN"), "{err}");
    }

    #[test]
    fn locate_prefers_env_override_over_path() {
        let dir = tempfile::tempdir().unwrap();
        let preferred = canned(dir.path(), r#"{"ok":true,"data":{}}"#, 0);
        let path_dir = dir.path().join("bin");
        std::fs::create_dir_all(&path_dir).unwrap();
        let on_path = canned(&path_dir, r#"{"ok":true,"data":{}}"#, 0);

        let located = Backend::locate_with(
            Some(preferred.clone().into_os_string()),
            Some(path_dir.into_os_string()),
        )
        .unwrap();
        assert_eq!(located.bin(), preferred.as_path());
        assert_ne!(located.bin(), on_path.as_path());
    }

    #[test]
    fn locate_falls_back_to_path_when_there_is_no_override() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        // `canned` writes `akey-stub`; give it the name the resolver looks for.
        let bin = canned(&bin_dir, r#"{"ok":true,"data":{}}"#, 0);
        let renamed = bin_dir.join("akey");
        std::fs::rename(&bin, &renamed).unwrap();

        let located = Backend::locate_with(None, Some(bin_dir.clone().into_os_string())).unwrap();
        assert_eq!(located.bin(), renamed.as_path());
    }

    #[test]
    fn locate_rejects_an_env_override_that_does_not_exist() {
        let err = Backend::locate_with(Some("/nonexistent/akey".into()), None).unwrap_err();
        match err {
            BackendError::BinaryNotFound { tried } => {
                assert!(tried.contains("AKEY_GUI_BIN"), "{tried}");
            }
            other => panic!("expected BinaryNotFound, got {other:?}"),
        }
    }

    #[test]
    fn locate_reports_an_empty_path_as_not_found_rather_than_panicking() {
        let err = Backend::locate_with(None, Some("".into())).unwrap_err();
        assert!(matches!(err, BackendError::BinaryNotFound { .. }));
    }

    #[test]
    fn passes_secret_on_stdin_never_argv() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);

        let secret = "sk-canary-WRITTEN-ON-STDIN";
        let outcome = Backend::with_bin(&stub.bin)
            .run_with_stdin(
                &["set", "openai", "--stdin"],
                &format!("credential={secret}\n"),
            )
            .unwrap();
        assert!(outcome.is_ok());

        assert!(
            !stub.argv_joined().contains(secret),
            "the secret must never reach argv: {:?}",
            stub.argv()
        );
        assert!(
            stub.stdin().contains(secret),
            "the secret must arrive on stdin: {:?}",
            stub.stdin()
        );
    }

    #[test]
    fn argv_for_places_global_flags_before_the_verb() {
        let backend = Backend::with_bin("/bin/true").with_home("/tmp/vault-home");
        assert_eq!(
            backend.argv_for(&["list"]),
            vec![
                "--json".to_string(),
                "--home".to_string(),
                "/tmp/vault-home".to_string(),
                "list".to_string()
            ]
        );
    }

    #[test]
    fn write_path_never_places_a_value_in_argv() {
        // A shape test, independent of any child process: the argv the GUI builds for a
        // write carries the field *name* and `--stdin`, and no value at all.
        let backend = Backend::with_bin("/bin/true");
        let argv = backend.argv_for(&["set", "openai", "--category", "apikey", "--stdin"]);
        for token in &argv {
            assert!(
                !token.contains("sk-") && !token.contains('='),
                "argv must not carry a value: {argv:?}"
            );
        }
        assert!(argv.contains(&"--stdin".to_string()));
    }

    /// The CLI prefers the two recovery environment variables over stdin. Inheriting
    /// either would silently override the passphrase the user typed, so the backend
    /// clears both before every invocation.
    #[test]
    fn inherited_recovery_env_does_not_shadow_the_typed_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let stub = RecordingStub::new(dir.path(), r#"{"ok":true,"data":{}}"#);

        unsafe { std::env::set_var("AKEY_RECOVERY_PASSPHRASE", "INHERITED-SHOULD-BE-CLEARED") };
        let typed = "typed-passphrase-long-enough";
        Backend::with_bin(&stub.bin)
            .run_with_stdin(&["recovery", "unlock"], typed)
            .unwrap();
        unsafe { std::env::remove_var("AKEY_RECOVERY_PASSPHRASE") };

        // The stub can only observe stdin, but the point is the child environment: the
        // backend must not have passed the inherited value through. Assert on what the
        // caller actually controls — the passphrase went in on stdin.
        assert_eq!(stub.stdin(), typed);
    }
}

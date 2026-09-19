//! Injection mechanism: parse references → build the environment → spawn the child → mask the echo.
//!
//! Division of labour with `cmd::deliver`: this module is mechanism only, no argument parsing and no policy decisions.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::inject::mask::Masker;
use crate::reference::{self, Reference};
use crate::vault::model::{Category, Entry, Vault};
use crate::vault::store::Store;

/// The complete environment of one injection.
#[derive(Debug, Default)]
pub struct Injection {
    /// Variable name → plaintext. The order is stable, which helps tests and `--dry-run` previews.
    pub vars: Vec<(String, Zeroizing<String>)>,
    /// The **individual** plaintexts substituted into those values.
    ///
    /// The masker has to register them as well. Register only the final values and
    /// `--with AUTH="Bearer akey://a/b"` leaks plaintext when the child prints the part after
    /// `Bearer ` (`${AUTH#Bearer }`) — measured, it really does leak.
    pub plaintexts: Vec<Zeroizing<String>>,
}

impl Injection {
    /// Build from the variable table alone (tests and internal use). `plaintexts` only affects the masking surface, not the injected content.
    pub fn from_vars(vars: Vec<(String, Zeroizing<String>)>) -> Self {
        Injection {
            vars,
            plaintexts: Vec::new(),
        }
    }

    /// The plaintext list for the masking pipeline: the final values plus the substituted single values.
    pub fn secrets(&self) -> Vec<String> {
        let mut all: BTreeSet<String> =
            self.vars.iter().map(|(_, v)| v.to_string()).collect();
        all.extend(self.plaintexts.iter().map(|p| p.to_string()));
        all.into_iter().collect()
    }
}

/// Combine `--with` / `--bundle` / `--env-file` into one environment.
///
/// Precedence (high → low): `--with` > `--bundle` > `--env-file` (with several files, a later
/// one overrides an earlier one) > the process's own environment.
///
/// The three `--with` forms:
/// - `VAR=akey://…`: a reference (a reference may also be embedded in another string, e.g. `AUTH=Bearer akey://a/b`)
/// - `VAR=ITEM`: an entry name; take that entry's default secret field for its `category`
/// - `ITEM`: the variable name is derived from the entry name (upper-case, non-alphanumeric → `_`), same value as above
///
/// `--bundle` accepts only `env-bundle` entries and injects **all** their fields (variable name = the field slug upper-cased);
/// `--env-file` is parsed with dotenv syntax, and an `akey://` reference in a value is resolved to plaintext.
/// The result is sorted by variable name, so the same set of inputs always yields the same environment.
///
/// `store` takes no part in evaluation yet: resolving references only needs `vault`. It is kept
/// because the caller (the `cmd` layer) already has it, and an injection policy that later keys
/// off the device or the repository (an audited device name, say) will not need a new signature.
pub fn resolve(
    _store: &Store,
    vault: &Vault,
    specs: &[String],
    bundles: &[String],
    env_files: &[PathBuf],
) -> Result<Injection> {
    // Inserted low → high: `BTreeMap`'s "last write wins" is the precedence, and the final key order is the deterministic output.
    let mut vars: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    // The individual plaintexts substituted into values, for the masker to register (see `Injection::plaintexts`).
    let mut plaintexts: Vec<Zeroizing<String>> = Vec::new();

    for path in env_files {
        for (name, value) in load_env_file(path)? {
            vars.insert(name, render_refs(vault, &value, &mut plaintexts)?);
        }
    }

    for bundle in bundles {
        let entry = require_env_bundle(vault, bundle)?;
        if entry.fields.is_empty() {
            return Err(Error::usage(format!(
                "env-bundle '{}' has no fields to inject",
                entry.name
            )));
        }
        for field in &entry.fields {
            vars.insert(env_name(&field.id), Zeroizing::new(field.value().to_string()));
        }
    }

    for spec in specs {
        let (name, value) = match spec.split_once('=') {
            Some((name, raw)) => {
                let name = name.trim();
                if !is_env_var_name(name) {
                    return Err(Error::usage(format!(
                        "--with '{spec}': '{name}' is not a valid environment variable name"
                    )));
                }
                (name.to_string(), with_value(vault, raw, &mut plaintexts)?)
            }
            None => {
                let entry = vault.find(spec)?;
                (env_name(&entry.name), default_secret(entry)?)
            }
        };
        vars.insert(name, value);
    }

    Ok(Injection {
        vars: vars.into_iter().collect(),
        plaintexts,
    })
}

/// The "authorization surface" of one injection: the `cmd` layer uses it to pin the token scope ahead of injection.
///
/// Injecting means handing plaintext to a child process. `run` does not go through `gate_reveal`
/// (the plaintext never reaches the caller), but the scope must still apply — otherwise a token
/// restricted to a single entry only has to inject a value into `sh -c 'cat'` to read any entry.
#[derive(Debug, Default)]
pub struct Touch {
    /// Raw text that may contain `akey://` references (each `--with` spec plus the contents of
    /// every `--env-file`): handed to `Ctx::authorize_references`.
    pub texts: Vec<String>,
    /// **Entry names** resolved from the forms that point at an entry without a reference
    /// (`VAR=ITEM` / `ITEM` / `--bundle`): handed to `Ctx::authorize`. Names are stored rather than
    /// the user's raw input because the scope compares names (the user may pass a 22-char ID).
    pub items: Vec<String>,
    /// Every entry name this injection touches (sorted, deduplicated), used as the audit `subject`.
    pub subjects: Vec<String>,
}

/// Compute the authorization surface of one injection. To avoid growing the signature of
/// [`resolve`], the env files are read a second time here (a dotenv file is only a few hundred
/// bytes, and authorization has to complete before any plaintext is decrypted).
pub fn touch(
    vault: &Vault,
    specs: &[String],
    bundles: &[String],
    env_files: &[PathBuf],
) -> Result<Touch> {
    let mut touch = Touch::default();
    let mut items: BTreeSet<String> = BTreeSet::new();
    let mut subjects: BTreeSet<String> = BTreeSet::new();

    for path in env_files {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("cannot read env file {}: {e}", path.display()),
            ))
        })?;
        for raw in reference::extract_references(&content) {
            subjects.insert(vault.find(&parse_ref(&raw)?.item)?.name.clone());
        }
        touch.texts.push(content);
    }

    for bundle in bundles {
        let entry = require_env_bundle(vault, bundle)?;
        items.insert(entry.name.clone());
        subjects.insert(entry.name.clone());
    }

    for spec in specs {
        match spec.split_once('=') {
            Some((_, raw)) if raw.contains(reference::SCHEME) => {
                for raw in reference::extract_references(raw.trim()) {
                    subjects.insert(vault.find(&parse_ref(&raw)?.item)?.name.clone());
                }
            }
            Some((_, raw)) => {
                let name = vault.find(raw.trim())?.name.clone();
                items.insert(name.clone());
                subjects.insert(name);
            }
            None => {
                let name = vault.find(spec)?.name.clone();
                items.insert(name.clone());
                subjects.insert(name);
            }
        }
        touch.texts.push(spec.clone());
    }

    touch.items = items.into_iter().collect();
    touch.subjects = subjects.into_iter().collect();
    Ok(touch)
}

/// Spawn the child process and pass its exit code through.
///
/// With `mask = true` stdout/stderr go through pipes and are masked; with `false` all three fds
/// are inherited (keeping the TTY, which interactive child processes need).
pub fn execute(command: &[String], injection: &Injection, mask: bool) -> Result<i32> {
    if !mask {
        // Without masking, inherit directly: that keeps TTY semantics and saves a pipe copy (including the empty-injection case).
        return spawn_child(command, injection, ChildIo::Inherit);
    }
    spawn_child(
        command,
        injection,
        ChildIo::Piped {
            mask: true,
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
        },
    )
}

/// Replace every `akey://` reference in the input text with plaintext.
///
/// A reference that does not resolve → `NotFound` naming that reference (no field value is echoed: there are no secrets in the error message).
pub fn render_template(vault: &Vault, input: &str) -> Result<String> {
    // The sink here is discarded: the masking of `inject` does not apply (the caller is going to
    // get the plaintext anyway, and the gate has already vetted it in `Ctx::gate_references_reveal`).
    let mut unused: Vec<Zeroizing<String>> = Vec::new();
    Ok(render_refs(vault, input, &mut unused)?.to_string())
}

/// Environment variable name derivation: upper-case, non-alphanumeric → `_`.
///
/// Entry names and field slugs may both contain `.` / `-`, and upper-casing them directly would
/// yield names the shell cannot reference, so everything folds to underscores. `export` / `import`
/// use this to keep the naming identical on both sides.
pub fn env_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Parse dotenv text.
///
/// Supported: an `export ` prefix, a whole-line `#` comment, single/double quotes, blank lines, a
/// `=` inside the value, `\r\n` line endings. In a double-quoted value `\n` `\r` `\t` `\\` `\"` are
/// unescaped; a single-quoted value is always literal. A syntax error → `usage`, naming `label`
/// (the caller passes the file name) and the line number.
pub fn parse_dotenv(label: &str, input: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (index, raw_line) in input.lines().enumerate() {
        let lineno = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
            _ => line,
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::usage(format!(
                "{label}:{lineno}: expected `NAME=value`"
            )));
        };
        let key = key.trim();
        if !is_env_var_name(key) {
            return Err(Error::usage(format!(
                "{label}:{lineno}: '{key}' is not a valid environment variable name"
            )));
        }
        out.push((key.to_string(), unquote(value.trim())));
    }
    Ok(out)
}

/// The right-hand side of `--with`: replace references when it contains `akey://`, otherwise take the default secret field by entry name.
fn with_value(
    vault: &Vault,
    raw: &str,
    sink: &mut Vec<Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    let raw = raw.trim();
    if raw.contains(reference::SCHEME) {
        return render_refs(vault, raw, sink);
    }
    default_secret(vault.find(raw)?)
}

/// The default secret field value for an entry `category`.
fn default_secret(entry: &Entry) -> Result<Zeroizing<String>> {
    let label = entry.category.default_secret_field();
    if label.is_empty() {
        return Err(Error::usage(format!(
            "entry '{}' is an env-bundle and has no single secret field; use `--bundle {}`",
            entry.name, entry.name
        )));
    }
    let field = entry.field(label).ok_or_else(|| {
        Error::not_found(format!(
            "entry '{}' has no '{}' field to inject",
            entry.name, label
        ))
    })?;
    Ok(Zeroizing::new(field.value().to_string()))
}

/// `--bundle` accepts only `env-bundle` entries — flattening a single field of another category into an environment variable would only surprise people.
fn require_env_bundle<'a>(vault: &'a Vault, item: &str) -> Result<&'a Entry> {
    let entry = vault.find(item)?;
    if entry.category != Category::EnvBundle {
        return Err(Error::usage(format!(
            "entry '{}' is a {}, not an env-bundle; use `--with` for single values",
            entry.name, entry.category
        )));
    }
    Ok(entry)
}

/// Replace every reference in the text with plaintext. Reference texts are processed in order of appearance; a repeated reference is replaced each time.
fn render_refs(
    vault: &Vault,
    input: &str,
    sink: &mut Vec<Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    let now = Utc::now();
    let rendered = walk_refs(input, |raw| {
        let value = resolve_ref(vault, raw, now)?;
        // Record the **individual** plaintext, not just the assembled string.
        if !value.is_empty() {
            sink.push(Zeroizing::new(value.clone()));
        }
        Ok(value)
    })?;
    Ok(Zeroizing::new(rendered))
}

/// Walk the `akey://` references in `input` in order of appearance, replacing each with the value returned by `visit`.
///
/// Reference boundaries are decided by [`reference::extract_references`] (the single source of
/// truth); it returns non-overlapping texts in order of appearance, so a `find` from the cursor
/// always hits.
fn walk_refs(input: &str, mut visit: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let raws = reference::extract_references(input);
    if raws.is_empty() {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for raw in &raws {
        let Some(offset) = input[cursor..].find(raw.as_str()) else {
            // Unreachable in theory; if it ever drifts, keep the original text — never replace at the wrong offset.
            continue;
        };
        let start = cursor + offset;
        out.push_str(&input[cursor..start]);
        out.push_str(&visit(raw)?);
        cursor = start + raw.len();
    }
    out.push_str(&input[cursor..]);
    Ok(out)
}

/// Parse one reference text (including `$VAR` expansion) and resolve it.
fn resolve_ref(vault: &Vault, raw: &str, now: DateTime<Utc>) -> Result<String> {
    let reference = parse_ref(raw)?;
    match reference::resolve(vault, &reference, now) {
        Ok(value) => Ok(value.to_string()),
        // Name the reference text so an agent knows what to fix; the message holds names only, no values.
        Err(Error::NotFound(msg)) => Err(Error::not_found(format!(
            "cannot resolve '{raw}': {msg}"
        ))),
        Err(Error::Ambiguous(msg)) => Err(Error::Ambiguous(format!(
            "cannot resolve '{raw}': {msg}"
        ))),
        Err(other) => Err(other),
    }
}

/// The single entry point for reference parsing (`$VAR` comes from the current process environment).
fn parse_ref(raw: &str) -> Result<Reference> {
    Reference::parse_in(raw, &|name| std::env::var(name).ok())
}

/// Read and parse one `--env-file`.
fn load_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read env file {}: {e}", path.display()),
        ))
    })?;
    parse_dotenv(&path.display().to_string(), &raw)
}

/// A valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Strip quotes from a dotenv value. A single-quoted value is always literal; a double-quoted one handles escapes per dotenv convention.
fn unquote(value: &str) -> String {
    if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return unescape_double(inner);
    }
    if let Some(inner) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return inner.to_string();
    }
    value.to_string()
}

/// Escapes inside a double-quoted value: `\n` `\r` `\t` `\\` `\"`; an unknown escape is kept as is.
fn unescape_double(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The child process's IO policy.
enum ChildIo {
    /// All three fds are inherited. This keeps TTY semantics (which interactive child processes
    /// need) at the cost of being unable to mask — which is exactly why it is used only for `--no-masking`.
    Inherit,
    /// stdout/stderr go through pipes. With `mask` true, secrets are swapped for placeholders as
    /// they are read; with `false` the bytes pass through untouched (`execute` never uses this
    /// combination — it leaves tests an observable "unmasked" path).
    Piped {
        mask: bool,
        out: Box<dyn Write + Send>,
        err: Box<dyn Write + Send>,
    },
}

/// Spawn the child: environment = the current process environment + injected variables (overriding same-named ones), exit code passed through verbatim.
fn spawn_child(command: &[String], injection: &Injection, io: ChildIo) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| Error::usage("no command to run; expected `akey run … -- <command>`"))?;
    let mut child = Command::new(program);
    child.args(args);
    for (name, value) in &injection.vars {
        child.env(name, value.as_str());
    }

    match io {
        ChildIo::Inherit => Ok(exit_code(child.status()?)),
        ChildIo::Piped { mask, out, err } => {
            child
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut running = child.spawn()?;
            let stdout = running.stdout.take().ok_or_else(missing_pipe)?;
            let stderr = running.stderr.take().ok_or_else(missing_pipe)?;

            // Both streams must be read in parallel: while one stream is read on a single thread,
            // the other pipe fills up and deadlocks both the child and the reader. stdin stays
            // inherited, so interactive input is unaffected.
            let out_thread = std::thread::spawn({
                let secrets = injection.secrets();
                move || relay(stdout, out, secrets, mask)
            });
            let err_thread = std::thread::spawn({
                let secrets = injection.secrets();
                move || relay(stderr, err, secrets, mask)
            });

            let status = running.wait()?;
            join_relay(out_thread)?;
            join_relay(err_thread)?;
            Ok(exit_code(status))
        }
    }
}

/// After `Stdio::piped()` the `take()` cannot fail; failing to get a pipe can only be an internal error.
fn missing_pipe() -> Error {
    Error::Io(std::io::Error::other("child output pipe was not created"))
}

/// Reap a reader thread. A panicking thread or a failed write must be reported; the only
/// non-error is a downstream that closed first (`| head`) — then the child's exit code is the
/// answer the caller wants.
fn join_relay(handle: std::thread::JoinHandle<std::io::Result<()>>) -> Result<()> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Ok(Err(e)) => Err(Error::Io(e)),
        Err(_) => Err(Error::Io(std::io::Error::other(
            "output relay thread panicked",
        ))),
    }
}

/// Pump one child output stream into `sink`. With `mask` true, [`Masker`] masks chunk by chunk;
/// otherwise [`Masker`] stays disabled and passes everything through.
fn relay(
    mut reader: impl Read,
    mut sink: Box<dyn Write + Send>,
    secrets: Vec<String>,
    mask: bool,
) -> std::io::Result<()> {
    let mut masker = if mask {
        Masker::with_secrets(secrets)
    } else {
        Masker::new()
    };
    let mut buf = [0u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = masker.push(&buf[..read]);
        if !chunk.is_empty() {
            sink.write_all(&chunk)?;
            sink.flush()?;
        }
    }
    let tail = masker.finish();
    if !tail.is_empty() {
        sink.write_all(&tail)?;
    }
    sink.flush()
}

/// Exit code pass-through. `run` is a transparent wrapper: an agent that would have seen
/// exit code 7 must still see exit code 7, or its error handling silently misfires.
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    abnormal_exit(status)
}

/// Unix: killed by a signal → `128 + signal` (the shell convention).
#[cfg(unix)]
fn abnormal_exit(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(1, |signal| 128 + signal)
}

/// Windows: there is no signal number. An abnormal termination surfaces as `NTSTATUS` in
/// `code()`, which is already reported above; reaching here means neither was available, and
/// there is no better answer than a generic failure.
#[cfg(windows)]
fn abnormal_exit(_status: ExitStatus) -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::crypto::DeviceIdentity;
    use crate::output::TAINTED;
    use crate::paths::Paths;
    use crate::vault::model::FieldType;
    use std::sync::{Arc, Mutex};
    use ulid::Ulid;

    fn ulid(tag: u8) -> Ulid {
        Ulid::from_bytes([tag; 16])
    }

    fn field(label: &str, ty: FieldType, value: &str) -> crate::vault::model::Field {
        crate::vault::model::Field::new(label, ty, value.to_string())
    }

    fn fixture() -> Vault {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("the timestamp is in the valid range");
        let mut vault = Vault::default();

        let mut openai = Entry::new(ulid(1), "openai".to_string(), Category::Apikey, now);
        openai
            .fields
            .push(field("credential", FieldType::Concealed, "sk-live-OPENAI-SECRET"));
        openai.fields.push(field("org", FieldType::String, "org-acme"));
        vault.entries.insert(openai.id, openai);

        let mut db = Entry::new(ulid(2), "db".to_string(), Category::Database, now);
        db.fields
            .push(field("password", FieldType::Concealed, "db-password-SECRET"));
        db.fields.push(field("host", FieldType::String, "db.internal"));
        vault.entries.insert(db.id, db);

        let mut deploy = Entry::new(ulid(3), "deploy".to_string(), Category::EnvBundle, now);
        deploy
            .fields
            .push(field("API_KEY", FieldType::Concealed, "bundle-API-KEY-value"));
        deploy
            .fields
            .push(field("DB_HOST", FieldType::String, "db.internal"));
        deploy
            .fields
            .push(field("cache-url", FieldType::String, "redis://cache"));
        vault.entries.insert(deploy.id, deploy);

        let mut dotted = Entry::new(ulid(4), "my.api".to_string(), Category::Apikey, now);
        dotted
            .fields
            .push(field("credential", FieldType::Concealed, "sk-dotted-SECRET"));
        vault.entries.insert(dotted.id, dotted);

        vault
    }

    /// A `Store` for tests: it only builds the structure, never touches `$HOME`, never reads or writes a file.
    fn test_store(dir: &Path) -> Store {
        let identity = DeviceIdentity::generate("test-device");
        Store {
            paths: Paths::new(dir.join("home")),
            config: Config {
                repo: dir.join("repo"),
                remote: None,
                device_name: "test-device".to_string(),
                trusted: std::collections::BTreeMap::from([(identity.pubkey(), Utc::now())]),
                trust_seeded: true,
                created_at: Utc::now(),
            },
            identity,
        }
    }

    fn env_file(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write the test env file");
        path
    }

    fn var_map(injection: &Injection) -> BTreeMap<String, String> {
        injection
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }

    fn specs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The four tests below drive a real child process through a POSIX shell, so they run
    /// only on unix. Everything else in this module is pure and runs everywhere.
    #[cfg(unix)]
    fn sh(script: &str) -> Vec<String> {
        vec!["sh".to_string(), "-c".to_string(), script.to_string()]
    }

    /// A shared output collector: the child's output thread writes it, the test thread reads it.
    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl SharedSink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("not poisoned").clone())
                .expect("test output should be UTF-8")
        }
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("not poisoned").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A reader that yields fixed-size chunks: used to control the "across chunks" boundary precisely.
    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        size: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let take = self
                .size
                .min(self.data.len().saturating_sub(self.pos))
                .min(buf.len());
            buf[..take].copy_from_slice(&self.data[self.pos..self.pos + take]);
            self.pos += take;
            Ok(take)
        }
    }

    /// Spawns a real child through a POSIX shell, so it and its callers are unix-only.
    #[cfg(unix)]
    fn pipe_to(
        script: &str,
        injection: &Injection,
        mask: bool,
    ) -> (i32, SharedSink, SharedSink) {
        let out = SharedSink::default();
        let err = SharedSink::default();
        let code = spawn_child(
            &sh(script),
            injection,
            ChildIo::Piped {
                mask,
                out: Box::new(out.clone()),
                err: Box::new(err.clone()),
            },
        )
        .expect("the child should start");
        (code, out, err)
    }

    // ---- resolve: the three `--with` forms ---------------------------

    #[test]
    fn with_specs_support_all_three_forms() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let vault = fixture();

        let injection = resolve(
            &store,
            &vault,
            &specs(&[
                "OPENAI_API_KEY=akey://openai/credential",
                "DB_PW=db",
                "openai",
                "AUTH=Bearer akey://openai/credential",
                "my.api",
                "ORG=akey://openai/org",
            ]),
            &[],
            &[],
        )
        .expect("all three forms should resolve");

        let vars = var_map(&injection);
        assert_eq!(vars["OPENAI_API_KEY"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["ORG"], "org-acme");
        // `VAR=ITEM`: take that category's default secret field.
        assert_eq!(vars["DB_PW"], "db-password-SECRET");
        // A bare `ITEM`: the variable name is derived from the entry name.
        assert_eq!(vars["OPENAI"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["MY_API"], "sk-dotted-SECRET");
        // When a reference is embedded in a string, only the reference itself is replaced.
        assert_eq!(vars["AUTH"], "Bearer sk-live-OPENAI-SECRET");
    }

    #[test]
    fn resolve_reports_bad_specs_and_missing_targets() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let vault = fixture();
        let resolve_one = |spec: &str| resolve(&store, &vault, &specs(&[spec]), &[], &[]);

        for bad in ["=value", "1BAD=value", "has space=value", "=akey://openai/credential"] {
            let err = resolve_one(bad).expect_err("an invalid variable name should be rejected");
            assert_eq!(err.exit_code(), 2, "spec '{bad}': {err}");
            assert!(matches!(err, Error::Usage(_)), "spec '{bad}': {err:?}");
        }

        // An env-bundle has no "default secret field", so a bare reference must point at `--bundle`.
        let err = resolve_one("deploy").expect_err("env-bundle should be rejected");
        assert!(matches!(err, Error::Usage(_)), "{err:?}");
        assert!(err.to_string().contains("--bundle deploy"), "{err}");

        // A nonexistent entry → not_found(3).
        let err = resolve_one("nosuchitem").expect_err("entry does not exist");
        assert_eq!(err.exit_code(), 3);
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");

        // A reference to a nonexistent entry → not_found, naming the reference text.
        let err = resolve_one("X=akey://nosuchitem/credential").expect_err("reference misses");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("akey://nosuchitem/credential"), "{err}");

        // An embedded reference that misses must name the reference too, not the whole value.
        let err = resolve_one("X=Bearer akey://nosuchitem/credential").expect_err("reference misses");
        assert!(err.to_string().contains("akey://nosuchitem/credential"), "{err}");

        // Entry present, field absent → not_found.
        let err = resolve_one("X=akey://openai/nosuchfield").expect_err("field does not exist");
        assert_eq!(err.exit_code(), 3);

        // Default secret field missing → not_found (the apikey entry had its credential field removed).
        let mut broken = fixture();
        let id = ulid(1);
        broken.entries.get_mut(&id).expect("entry exists").fields.clear();
        let err = resolve(&store, &broken, &specs(&["openai"]), &[], &[])
            .expect_err("a missing field should be an error");
        assert_eq!(err.exit_code(), 3);
    }

    // ---- resolve: --bundle -----------------------------------------------

    #[test]
    fn bundle_injects_every_field_of_an_env_bundle() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let vault = fixture();

        let injection = resolve(&store, &vault, &[], &specs(&["deploy"]), &[]).expect("bundle injection");
        let vars = var_map(&injection);

        assert_eq!(vars.len(), 3, "every field of an env-bundle must be injected");
        assert_eq!(vars["API_KEY"], "bundle-API-KEY-value");
        assert_eq!(vars["DB_HOST"], "db.internal");
        // A `-` in a field slug folds to `_`, or the shell cannot reference it.
        assert_eq!(vars["CACHE_URL"], "redis://cache");
    }

    #[test]
    fn bundle_rejects_non_env_bundles_and_empty_bundles() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let mut vault = fixture();

        for item in ["openai", "db"] {
            let err = resolve(&store, &vault, &[], &specs(&[item]), &[]).expect_err("not an env-bundle");
            assert_eq!(err.exit_code(), 2, "{item}: {err}");
            assert!(err.to_string().contains("env-bundle"), "{err}");
        }

        let id = ulid(3);
        vault.entries.get_mut(&id).expect("entry exists").fields.clear();
        let err = resolve(&store, &vault, &[], &specs(&["deploy"]), &[]).expect_err("empty bundle");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("no fields"), "{err}");
    }

    // ---- --env-file: dotenv parsing -----------------------------------

    #[test]
    fn env_file_parses_dotenv_forms() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let vault = fixture();
        let path = env_file(
            dir.path(),
            ".env",
            concat!(
                "# full-line comment\n",
                "   # indented comment\n",
                "\n",
                "export EXPORTED=exported-value\n",
                "export\tTAB_EXPORTED=tab-exported\n",
                "QUOTED=\"double quoted\"\n",
                "SINGLE='single quoted'\n",
                "WITH_EQUALS=a=b=c\n",
                "TRAILING=  spaced value  \n",
                "HASH=a#b\n",
                "EMPTY=\n",
                "ESCAPED=\"line1\\nline2\"\n",
                "REFERENCED=akey://openai/credential\n",
                "EMBEDDED=Bearer akey://openai/org\n",
            ),
        );

        let injection = resolve(&store, &vault, &[], &[], &[path]).expect("the env-file should parse");
        let vars = var_map(&injection);

        assert_eq!(vars["EXPORTED"], "exported-value");
        assert_eq!(vars["TAB_EXPORTED"], "tab-exported", "a tab after `export` is a separator too");
        assert_eq!(vars["QUOTED"], "double quoted");
        assert_eq!(vars["SINGLE"], "single quoted");
        assert_eq!(vars["WITH_EQUALS"], "a=b=c");
        assert_eq!(vars["TRAILING"], "spaced value");
        assert_eq!(vars["HASH"], "a#b", "a `#` inside a line is not a comment");
        assert_eq!(vars["EMPTY"], "");
        assert_eq!(vars["ESCAPED"], "line1\nline2");
        assert_eq!(vars["REFERENCED"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["EMBEDDED"], "Bearer org-acme");
    }

    #[test]
    fn dotenv_reports_syntax_errors_with_line_numbers() {
        let err = parse_dotenv(".env", "# ok\nGOOD=1\nBROKEN\n").expect_err("missing `=`");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(".env:3"), "{err}");

        let err = parse_dotenv(".env", "1BAD=1\n").expect_err("invalid name");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(".env:1"), "{err}");

        // A missing env file → an io error (rather than silently treating it as an empty environment).
        let dir = tempfile::tempdir().expect("temporary directory");
        let err = load_env_file(&dir.path().join("nope.env")).expect_err("the file does not exist");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("nope.env"), "{err}");
    }

    // ---- precedence and ordering -----------------------------------

    #[test]
    fn precedence_is_with_then_bundle_then_env_file_then_process_env() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let vault = fixture();
        let first = env_file(dir.path(), "first.env", "API_KEY=from-first-file\nONLY_FILE=first\n");
        let second = env_file(dir.path(), "second.env", "API_KEY=from-second-file\n");
        let files = vec![first, second];

        // All three sources provide `API_KEY`: `--with` wins.
        let injection = resolve(
            &store,
            &vault,
            &specs(&["API_KEY=akey://openai/credential"]),
            &specs(&["deploy"]),
            &files,
        )
        .expect("should resolve");
        let vars = var_map(&injection);
        assert_eq!(vars["API_KEY"], "sk-live-OPENAI-SECRET");
        assert_eq!(vars["ONLY_FILE"], "first");

        // Drop `--with` → `--bundle` wins.
        let injection = resolve(&store, &vault, &[], &specs(&["deploy"]), &files).expect("should resolve");
        let vars = var_map(&injection);
        assert_eq!(vars["API_KEY"], "bundle-API-KEY-value");
        // With several env files, a later one overrides an earlier one.
        assert_eq!(vars["DB_HOST"], "db.internal");

        // Drop `--bundle` → the env file wins (the later file first).
        let injection = resolve(&store, &vault, &[], &[], &files).expect("should resolve");
        let vars = var_map(&injection);
        assert_eq!(vars["API_KEY"], "from-second-file");
        assert_eq!(vars["ONLY_FILE"], "first");
    }

    #[cfg(unix)]
    #[test]
    fn injected_variables_override_the_process_environment() {
        let dir = tempfile::tempdir().expect("temporary directory");
        // `HOME` is necessarily in this process's environment — the whole point of this test is to override an existing variable.
        let inherited = std::env::var("HOME").expect("the test process should have HOME");
        assert_ne!(inherited, "injected-home-value");

        let target = dir.path().join("out.txt");
        let injection = Injection::from_vars(vec![(
            "HOME".to_string(),
            Zeroizing::new("injected-home-value".to_string()),
        )]);
        let script = format!("/bin/echo -n \"$HOME\" > '{}'", target.display());
        let code = execute(&sh(&script), &injection, false).expect("the child should start");
        assert_eq!(code, 0);
        assert_eq!(
            std::fs::read_to_string(&target).expect("read back the child's output"),
            "injected-home-value",
            "an injected variable must beat the inherited environment variable"
        );
    }

    #[test]
    fn resolve_output_is_sorted_by_variable_name() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = test_store(dir.path());
        let vault = fixture();

        let forward = resolve(
            &store,
            &vault,
            &specs(&[
                "ZED=akey://openai/credential",
                "ALPHA=akey://openai/credential",
                "MID=akey://openai/org",
            ]),
            &[],
            &[],
        )
        .expect("should resolve");
        let names: Vec<&str> = forward.vars.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["ALPHA", "MID", "ZED"]);

        let reversed = resolve(
            &store,
            &vault,
            &specs(&[
                "MID=akey://openai/org",
                "ZED=akey://openai/credential",
                "ALPHA=akey://openai/credential",
            ]),
            &[],
            &[],
        )
        .expect("should resolve");
        assert_eq!(forward.vars, reversed.vars, "the same set of inputs must yield the same environment");
    }

    // ---- touch: the authorization surface -----------------------------

    #[test]
    fn touch_lists_reference_texts_items_and_subjects() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let vault = fixture();
        let path = env_file(
            dir.path(),
            ".env",
            "TOKEN=akey://openai/credential\nOTHER=akey://openai/org\n",
        );

        let surface = touch(
            &vault,
            &specs(&["OPENAI=akey://openai/credential", "db"]),
            &specs(&["deploy"]),
            &[path],
        )
        .expect("should compute the authorization surface");

        // Texts containing references go to `authorize_references`: the spec texts + the env file contents.
        assert_eq!(surface.texts.len(), 3);
        assert_eq!(surface.texts[0], "TOKEN=akey://openai/credential\nOTHER=akey://openai/org\n");
        assert_eq!(surface.texts[1], "OPENAI=akey://openai/credential");
        assert_eq!(surface.texts[2], "db", "a bare entry text is handed to authorize_references as well (it holds no reference)");
        // Forms without a reference resolve to an entry name (an ID the user passes is normalized to the name too).
        assert_eq!(surface.items, vec!["db", "deploy"]);
        // For auditing: every entry name touched, deduplicated and sorted.
        assert_eq!(surface.subjects, vec!["db", "deploy", "openai"]);

        // An ID must normalize to the entry name too, or the scope comparison (which compares names) would misjudge.
        let by_id = touch(
            &vault,
            &specs(&[&ulid(2).to_string()]),
            &[],
            &[],
        )
        .expect("should compute the authorization surface");
        assert_eq!(by_id.items, vec!["db"]);
    }

    // ---- render_template --------------------------------------------------

    #[test]
    fn render_template_replaces_every_reference() {
        let vault = fixture();
        let template = concat!(
            "key: akey://openai/credential\n",
            "org: akey://openai/org\n",
            "dup: akey://openai/credential\n",
            "plain: nothing to see\n",
        );
        assert_eq!(
            render_template(&vault, template).expect("everything should be replaced"),
            concat!(
                "key: sk-live-OPENAI-SECRET\n",
                "org: org-acme\n",
                "dup: sk-live-OPENAI-SECRET\n",
                "plain: nothing to see\n",
            )
        );

        assert_eq!(render_template(&vault, "no refs").expect("returned as is"), "no refs");
        assert_eq!(render_template(&vault, "").expect("empty input"), "");
    }

    #[test]
    fn render_template_names_unresolved_references() {
        let vault = fixture();

        let err = render_template(&vault, "token=akey://nosuchitem/credential")
            .expect_err("entry does not exist");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("akey://nosuchitem/credential"), "{err}");

        let err = render_template(&vault, "a\nakey://openai/nosuchfield\n").expect_err("field does not exist");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert!(err.to_string().contains("akey://openai/nosuchfield"), "{err}");
    }

    // ---- execute: exit codes ------------------------------------------

    #[cfg(unix)]
    #[test]
    fn execute_passes_the_child_exit_code_through() {
        let injection = Injection::default();
        assert_eq!(execute(&sh("exit 0"), &injection, false).expect("start"), 0);
        assert_eq!(execute(&sh("exit 42"), &injection, false).expect("start"), 42);
        // Masking mode passes the exit code through just the same.
        assert_eq!(execute(&sh("exit 42"), &injection, true).expect("start"), 42);
        assert_eq!(execute(&sh("exit 7"), &injection, true).expect("start"), 7);
    }

    #[cfg(unix)]
    #[test]
    fn execute_maps_signals_to_128_plus_signal() {
        // SIGKILL cannot be caught, so the child necessarily dies from the signal.
        let code = execute(&sh("kill -9 $$"), &Injection::default(), false).expect("start");
        assert_eq!(code, 128 + 9);
    }

    #[test]
    fn execute_without_a_command_is_a_usage_error() {
        let err = execute(&[], &Injection::default(), false).expect_err("no command");
        assert_eq!(err.exit_code(), 2);
    }

    // ---- execute: masking ----------------------------------------------

    const SECRET: &str = "sk-live-MASK-ME-PLEASE-123456789";

    #[cfg(unix)]
    fn secret_injection() -> Injection {
        Injection::from_vars(vec![("SECRET".to_string(), Zeroizing::new(SECRET.to_string()))])
    }

    #[cfg(unix)]
    #[test]
    fn piped_output_is_masked_and_never_leaks_the_plaintext() {
        let (code, out, err) = pipe_to(
            "printf 'token=%s\\n' \"$SECRET\"; printf 'err=%s\\n' \"$SECRET\" >&2",
            &secret_injection(),
            true,
        );
        assert_eq!(code, 0);

        let text = out.text();
        assert_eq!(text, format!("token={TAINTED}\n"));
        assert!(!text.contains(SECRET), "plaintext leaked: {text}");
        let text = err.text();
        assert_eq!(text, format!("err={TAINTED}\n"));
        assert!(!text.contains(SECRET), "plaintext leaked: {text}");
    }

    #[cfg(unix)]
    #[test]
    fn unmasked_output_passes_the_plaintext_through() {
        let (code, out, _) = pipe_to("printf %s \"$SECRET\"", &secret_injection(), false);
        assert_eq!(code, 0);
        assert_eq!(out.text(), SECRET, "without masking it must come through verbatim");
    }

    #[test]
    fn a_secret_split_across_reads_is_still_masked() {
        // Key regression: a secret chopped into arbitrary chunks (1 byte included) must be replaced whole, with no fragment leaking.
        let text = format!("before {SECRET} after");
        for size in 1..=text.len() {
            let sink = SharedSink::default();
            relay(
                Chunked {
                    data: text.clone().into_bytes(),
                    pos: 0,
                    size,
                },
                Box::new(sink.clone()),
                vec![SECRET.to_string()],
                true,
            )
            .expect("pumping should succeed");
            let rendered = sink.text();
            assert_eq!(rendered, format!("before {TAINTED} after"), "chunk size {size}");
            assert!(!rendered.contains(SECRET), "chunk size {size} leaked plaintext");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_written_in_pieces_by_a_child_is_still_masked() {
        // The child writes the secret out in several pieces with a sleep in between, splitting it across read chunks.
        let secret = "S3CRET-VALUE-THAT-IS-LONG";
        let pieces = ["S3CRE", "T-VAL", "UE-TH", "AT-IS", "-LONG"];
        assert_eq!(pieces.concat(), secret);
        // Every piece is shorter than MIN_SECRET_LEN: only the concatenation is long enough, so masking must rely on the cross-chunk window.
        assert!(pieces.iter().all(|p| p.len() < crate::inject::mask::MIN_SECRET_LEN));

        let mut vars = vec![("SECRET".to_string(), Zeroizing::new(secret.to_string()))];
        for (index, piece) in pieces.iter().enumerate() {
            vars.push((format!("PIECE{index}"), Zeroizing::new((*piece).to_string())));
        }
        let script = "/bin/echo -n \"$PIECE0\"; sleep 0.05; /bin/echo -n \"$PIECE1\"; \
                      sleep 0.05; /bin/echo -n \"$PIECE2\"; sleep 0.05; \
                      /bin/echo -n \"$PIECE3\"; sleep 0.05; /bin/echo -n \"$PIECE4\"";

        let (code, out, _) = pipe_to(script, &Injection::from_vars(vars), true);
        assert_eq!(code, 0);
        assert_eq!(out.text(), TAINTED, "a secret spanning write chunks must be masked whole");
    }

    #[cfg(unix)]
    #[test]
    fn short_values_are_left_alone() {
        let injection =
            Injection::from_vars(vec![("FLAG".to_string(), Zeroizing::new("true".to_string()))]);
        let (code, out, _) = pipe_to("printf 'flag=%s' \"$FLAG\"", &injection, true);
        assert_eq!(code, 0);
        assert_eq!(out.text(), "flag=true", "a short value should not be mosaic'd");
    }

    // ---- helpers ------------------------------------------------------

    #[test]
    fn env_name_derives_shell_safe_names() {
        assert_eq!(env_name("openai"), "OPENAI");
        assert_eq!(env_name("my.api"), "MY_API");
        assert_eq!(env_name("cache-url"), "CACHE_URL");
        assert_eq!(env_name("API_KEY"), "API_KEY");

        for good in ["FOO", "_foo", "A1", "a_b"] {
            assert!(is_env_var_name(good), "{good}");
        }
        for bad in ["", "1FOO", "FOO-BAR", "FOO BAR", "FOO=BAR"] {
            assert!(!is_env_var_name(bad), "{bad}");
        }
    }
}

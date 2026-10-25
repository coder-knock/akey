use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::resolve::{is_env_var_name, load_env_file};
use super::spawn::{ChildIo, relay, spawn_child};
use super::*;
use crate::config::Config;
use crate::crypto::DeviceIdentity;
use crate::error::Error;
use crate::output::TAINTED;
use crate::paths::Paths;
use crate::vault::model::{Category, Entry, FieldType, Vault};
use crate::vault::store::Store;

fn ulid(tag: u8) -> Ulid {
    Ulid::from_bytes([tag; 16])
}

fn field(label: &str, ty: FieldType, value: &str) -> crate::vault::model::Field {
    crate::vault::model::Field::new(label, ty, value.to_string())
}

fn fixture() -> Vault {
    let now =
        DateTime::from_timestamp(1_700_000_000, 0).expect("the timestamp is in the valid range");
    let mut vault = Vault::default();

    let mut openai = Entry::new(ulid(1), "openai".to_string(), Category::Apikey, now);
    openai.fields.push(field(
        "credential",
        FieldType::Concealed,
        "sk-live-OPENAI-SECRET",
    ));
    openai
        .fields
        .push(field("org", FieldType::String, "org-acme"));
    vault.entries.insert(openai.id, openai);

    let mut db = Entry::new(ulid(2), "db".to_string(), Category::Database, now);
    db.fields.push(field(
        "password",
        FieldType::Concealed,
        "db-password-SECRET",
    ));
    db.fields
        .push(field("host", FieldType::String, "db.internal"));
    vault.entries.insert(db.id, db);

    let mut deploy = Entry::new(ulid(3), "deploy".to_string(), Category::EnvBundle, now);
    deploy.fields.push(field(
        "API_KEY",
        FieldType::Concealed,
        "bundle-API-KEY-value",
    ));
    deploy
        .fields
        .push(field("DB_HOST", FieldType::String, "db.internal"));
    deploy
        .fields
        .push(field("cache-url", FieldType::String, "redis://cache"));
    vault.entries.insert(deploy.id, deploy);

    let mut dotted = Entry::new(ulid(4), "my.api".to_string(), Category::Apikey, now);
    dotted.fields.push(field(
        "credential",
        FieldType::Concealed,
        "sk-dotted-SECRET",
    ));
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
fn pipe_to(script: &str, injection: &Injection, mask: bool) -> (i32, SharedSink, SharedSink) {
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

    for bad in [
        "=value",
        "1BAD=value",
        "has space=value",
        "=akey://openai/credential",
    ] {
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
    assert!(
        err.to_string().contains("akey://nosuchitem/credential"),
        "{err}"
    );

    // An embedded reference that misses must name the reference too, not the whole value.
    let err = resolve_one("X=Bearer akey://nosuchitem/credential").expect_err("reference misses");
    assert!(
        err.to_string().contains("akey://nosuchitem/credential"),
        "{err}"
    );

    // Entry present, field absent → not_found.
    let err = resolve_one("X=akey://openai/nosuchfield").expect_err("field does not exist");
    assert_eq!(err.exit_code(), 3);

    // Default secret field missing → not_found (the apikey entry had its credential field removed).
    let mut broken = fixture();
    let id = ulid(1);
    broken
        .entries
        .get_mut(&id)
        .expect("entry exists")
        .fields
        .clear();
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

    let injection =
        resolve(&store, &vault, &[], &specs(&["deploy"]), &[]).expect("bundle injection");
    let vars = var_map(&injection);

    assert_eq!(
        vars.len(),
        3,
        "every field of an env-bundle must be injected"
    );
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
        let err =
            resolve(&store, &vault, &[], &specs(&[item]), &[]).expect_err("not an env-bundle");
        assert_eq!(err.exit_code(), 2, "{item}: {err}");
        assert!(err.to_string().contains("env-bundle"), "{err}");
    }

    let id = ulid(3);
    vault
        .entries
        .get_mut(&id)
        .expect("entry exists")
        .fields
        .clear();
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
    assert_eq!(
        vars["TAB_EXPORTED"], "tab-exported",
        "a tab after `export` is a separator too"
    );
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
    let first = env_file(
        dir.path(),
        "first.env",
        "API_KEY=from-first-file\nONLY_FILE=first\n",
    );
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
    let injection =
        resolve(&store, &vault, &[], &specs(&["deploy"]), &files).expect("should resolve");
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
    assert_eq!(
        forward.vars, reversed.vars,
        "the same set of inputs must yield the same environment"
    );
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
    assert_eq!(
        surface.texts[0],
        "TOKEN=akey://openai/credential\nOTHER=akey://openai/org\n"
    );
    assert_eq!(surface.texts[1], "OPENAI=akey://openai/credential");
    assert_eq!(
        surface.texts[2], "db",
        "a bare entry text is handed to authorize_references as well (it holds no reference)"
    );
    // Forms without a reference resolve to an entry name (an ID the user passes is normalized to the name too).
    assert_eq!(surface.items, vec!["db", "deploy"]);
    // For auditing: every entry name touched, deduplicated and sorted.
    assert_eq!(surface.subjects, vec!["db", "deploy", "openai"]);

    // An ID must normalize to the entry name too, or the scope comparison (which compares names) would misjudge.
    let by_id = touch(&vault, &specs(&[&ulid(2).to_string()]), &[], &[])
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

    assert_eq!(
        render_template(&vault, "no refs").expect("returned as is"),
        "no refs"
    );
    assert_eq!(render_template(&vault, "").expect("empty input"), "");
}

#[test]
fn render_template_names_unresolved_references() {
    let vault = fixture();

    let err = render_template(&vault, "token=akey://nosuchitem/credential")
        .expect_err("entry does not exist");
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    assert_eq!(err.exit_code(), 3);
    assert!(
        err.to_string().contains("akey://nosuchitem/credential"),
        "{err}"
    );

    let err = render_template(&vault, "a\nakey://openai/nosuchfield\n")
        .expect_err("field does not exist");
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    assert!(
        err.to_string().contains("akey://openai/nosuchfield"),
        "{err}"
    );
}

// ---- execute: exit codes ------------------------------------------

#[cfg(unix)]
#[test]
fn execute_passes_the_child_exit_code_through() {
    let injection = Injection::default();
    assert_eq!(execute(&sh("exit 0"), &injection, false).expect("start"), 0);
    assert_eq!(
        execute(&sh("exit 42"), &injection, false).expect("start"),
        42
    );
    // Masking mode passes the exit code through just the same.
    assert_eq!(
        execute(&sh("exit 42"), &injection, true).expect("start"),
        42
    );
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
    Injection::from_vars(vec![(
        "SECRET".to_string(),
        Zeroizing::new(SECRET.to_string()),
    )])
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
    assert_eq!(
        out.text(),
        SECRET,
        "without masking it must come through verbatim"
    );
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
        assert_eq!(
            rendered,
            format!("before {TAINTED} after"),
            "chunk size {size}"
        );
        assert!(
            !rendered.contains(SECRET),
            "chunk size {size} leaked plaintext"
        );
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
    assert!(
        pieces
            .iter()
            .all(|p| p.len() < crate::inject::mask::MIN_SECRET_LEN)
    );

    let mut vars = vec![("SECRET".to_string(), Zeroizing::new(secret.to_string()))];
    for (index, piece) in pieces.iter().enumerate() {
        vars.push((
            format!("PIECE{index}"),
            Zeroizing::new((*piece).to_string()),
        ));
    }
    let script = "/bin/echo -n \"$PIECE0\"; sleep 0.05; /bin/echo -n \"$PIECE1\"; \
                  sleep 0.05; /bin/echo -n \"$PIECE2\"; sleep 0.05; \
                  /bin/echo -n \"$PIECE3\"; sleep 0.05; /bin/echo -n \"$PIECE4\"";

    let (code, out, _) = pipe_to(script, &Injection::from_vars(vars), true);
    assert_eq!(code, 0);
    assert_eq!(
        out.text(),
        TAINTED,
        "a secret spanning write chunks must be masked whole"
    );
}

#[cfg(unix)]
#[test]
fn short_values_are_left_alone() {
    let injection = Injection::from_vars(vec![(
        "FLAG".to_string(),
        Zeroizing::new("true".to_string()),
    )]);
    let (code, out, _) = pipe_to("printf 'flag=%s' \"$FLAG\"", &injection, true);
    assert_eq!(code, 0);
    assert_eq!(
        out.text(),
        "flag=true",
        "a short value should not be mosaic'd"
    );
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

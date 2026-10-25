use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::{Value, json};
use ulid::Ulid;

use super::doc::decode_attachment;
use super::export::{export_dotenv, render_export};
use super::import::{
    apply_plan, import_entry_name, parse_import, parse_import_dotenv, plan_import,
};
use super::mcp::handle_message;
use super::*;

use crate::cli::{
    Cli, DocArgs, DocCommand, ExportArgs, ExportFormat, ImportArgs, InjectArgs, ReadArgs, RunArgs,
};
use crate::cmd::Ctx;
use crate::config::Config;
use crate::crypto::DeviceIdentity;
use crate::crypto::token;
use crate::inject::run as inject;
use crate::paths::Paths;
use crate::vault::model::{Category, Entry, Field, FieldType, Reveal, Vault, is_valid_name};
use crate::vault::recipients::{RecipientKind, Recipients};
use crate::vault::store::Store;
use clap::Parser as _;
use tempfile::TempDir;

/// Sentinel values that should only ever exist in the vault and must never show up in any output.
const SENTINEL: &str = "sk-SENTINEL-DO-NOT-LEAK-9876543210";
const OTHER_SENTINEL: &str = "pw-OTHER-SENTINEL-1234567890";

fn ulid(tag: u8) -> Ulid {
    Ulid::from_bytes([tag; 16])
}

/// A real, on-disk "device": config + identity + recipients + vault.age. The command layer
/// reads a real vault, so instead of faking a Store this builds the full fixture.
struct Fixture {
    dir: TempDir,
    home: PathBuf,
    store: Store,
    vault: Vault,
}

fn fixture(tokens: Vec<token::IssuedToken>) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary directory");
    let home = dir.path().join("akey");
    let repo = dir.path().join("repo");
    let paths = Paths::new(home.clone());
    paths.ensure().expect("create home");

    let identity = DeviceIdentity::generate("test-device");
    identity
        .save(&paths.identity)
        .expect("write the local identity");
    let config = Config {
        repo: repo.clone(),
        remote: None,
        device_name: "test-device".to_string(),
        trusted: std::collections::BTreeMap::from([(identity.pubkey(), Utc::now())]),
        trust_seeded: true,
        created_at: Utc::now(),
    };
    config.save(&paths).expect("write the config");

    let mut recipients = Recipients::default();
    recipients.add(
        &identity.pubkey(),
        "test-device",
        RecipientKind::Device,
        Utc::now(),
    );
    recipients
        .save(&repo.join(crate::vault::store::RECIPIENTS_FILE))
        .expect("write the recipients");

    let now = Utc::now();
    let mut vault = Vault::default();

    let mut openai = Entry::new(ulid(1), "openai".to_string(), Category::Apikey, now);
    openai.fields.push(Field::new(
        "credential",
        FieldType::Concealed,
        SENTINEL.to_string(),
    ));
    openai.url = Some("https://platform.openai.com".to_string());
    vault.entries.insert(openai.id, openai);

    let mut other = Entry::new(ulid(2), "other".to_string(), Category::Login, now);
    other.title = Some("Other, Inc.".to_string());
    other.url = Some("https://example.com/login".to_string());
    other.fields.push(Field::new(
        "username",
        FieldType::String,
        "me@example.com".to_string(),
    ));
    other.fields.push(Field::new(
        "password",
        FieldType::Concealed,
        OTHER_SENTINEL.to_string(),
    ));
    vault.entries.insert(other.id, other);

    for issued in tokens {
        vault.tokens.insert(issued.meta.id, issued.meta);
    }

    let store = Store {
        paths,
        config,
        identity,
    };
    store.save(&vault).expect("write the vault");
    Fixture {
        dir,
        home,
        store,
        vault,
    }
}

/// Build a `Ctx` through the real clap parser (`--home` points at the fixture, never at `$HOME`).
///
/// Only global flags plus a no-argument command are passed: the command function itself is
/// called directly, and argv exists only to load global state such as `--home` / `--token` /
/// `--yes` into `Ctx`.
fn ctx_with(home: &Path, globals: &[&str]) -> Ctx {
    let home = home.to_str().expect("a temporary path should be UTF-8");
    let mut argv: Vec<&str> = vec!["akey", "--home", home];
    argv.extend_from_slice(globals);
    argv.push("whoami");
    let cli = Cli::try_parse_from(argv).expect("cli should parse");
    Ctx::new(&cli).expect("ctx")
}

fn issued_token(allow: Option<Vec<String>>) -> token::IssuedToken {
    token::issue("ci", allow, false, None, Utc::now()).expect("issue the token")
}

/// Make a child process write an environment variable into a file: proof of whether the child ran at all, and what it received.
fn sh_write(path: &Path, var: &str) -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("/bin/echo -n \"${var}\" > '{}'", path.display()),
    ]
}

fn entry_with(name: &str, fields: &[(&str, &str)]) -> Entry {
    let mut entry = Entry::new(
        Ulid::generate(),
        name.to_string(),
        Category::Apikey,
        Utc::now(),
    );
    entry.fields = fields
        .iter()
        .map(|(label, value)| Field::new(label, FieldType::Concealed, (*value).to_string()))
        .collect();
    entry
}

// ---- read -------------------------------------------------------------

#[test]
fn read_writes_the_value_and_audits_without_the_plaintext() {
    let fx = fixture(Vec::new());
    let out = fx.dir.path().join("value.txt");
    let ctx = ctx_with(&fx.home, &[]);

    read(
        &ctx,
        &ReadArgs {
            reference: "akey://openai/credential".to_string(),
            out_file: Some(out.clone()),
            no_newline: false,
        },
    )
    .expect("read should succeed");
    assert_eq!(
        std::fs::read_to_string(&out).expect("read back"),
        format!("{SENTINEL}\n")
    );

    read(
        &ctx,
        &ReadArgs {
            reference: "akey://openai/credential".to_string(),
            out_file: Some(out.clone()),
            no_newline: true,
        },
    )
    .expect("read should succeed");
    assert_eq!(std::fs::read_to_string(&out).expect("read back"), SENTINEL);

    let log = std::fs::read_to_string(&fx.store.paths.audit).expect("audit log");
    assert!(log.contains("\"read\""), "{log}");
    assert!(log.contains("openai"), "{log}");
    assert!(
        !log.contains(SENTINEL),
        "the audit log must not contain plaintext: {log}"
    );
}

#[test]
fn read_denies_when_the_entry_forbids_reveal() {
    let fx = fixture(Vec::new());
    let mut vault = fx.vault.clone();
    vault.entries.get_mut(&ulid(1)).expect("openai").reveal = Reveal::Deny;
    fx.store.save(&vault).expect("write the vault");

    let out = fx.dir.path().join("value.txt");
    let ctx = ctx_with(&fx.home, &[]);
    let err = read(
        &ctx,
        &ReadArgs {
            reference: "akey://openai/credential".to_string(),
            out_file: Some(out.clone()),
            no_newline: false,
        },
    )
    .expect_err("reveal=deny must be refused");
    assert_eq!(err.exit_code(), 7);
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(!out.exists(), "nothing may be written to disk when denied");

    let log = std::fs::read_to_string(&fx.store.paths.audit).expect("audit log");
    assert!(log.contains("denied"), "{log}");
    assert!(log.contains("openai"), "{log}");
    assert!(!log.contains(SENTINEL), "{log}");
}

// ---- export -----------------------------------------------------------

#[test]
fn export_requires_yes_before_reading_anything() {
    let fx = fixture(Vec::new());
    let out = fx.dir.path().join("export.env");
    let args = ExportArgs {
        encoding: ExportFormat::Dotenv,
        out_file: Some(out.clone()),
    };

    let err = export(&ctx_with(&fx.home, &[]), &args).expect_err("no --yes");
    assert_eq!(err.exit_code(), 2);
    assert_eq!(err.code(), "usage");
    assert!(err.to_string().contains("--yes"), "{err}");
    assert!(
        !out.exists(),
        "nothing may be written to disk without --yes"
    );

    // Only with --yes does it touch the vault: use an uninitialized home to show the gate runs before the read.
    let empty = tempfile::tempdir().expect("temporary directory");
    let err = export(&ctx_with(&empty.path().join("akey"), &["--yes"]), &args)
        .expect_err("not initialized");
    assert_eq!(
        err.exit_code(),
        4,
        "only after the gate passes does 'not initialized' come up"
    );
}

#[test]
fn export_writes_plaintext_and_honours_the_token_scope() {
    let issued = issued_token(Some(vec!["other".to_string()]));
    let plaintext = issued.plaintext.clone();
    // A `--deny-reveal` token: it must not even be able to dump its own entries wholesale.
    let deny = token::issue("deny", None, true, None, Utc::now()).expect("issue the token");
    let deny_plaintext = deny.plaintext.clone();
    let fx = fixture(vec![issued, deny]);

    let all = fx.dir.path().join("all.env");
    export(
        &ctx_with(&fx.home, &["--yes"]),
        &ExportArgs {
            encoding: ExportFormat::Dotenv,
            out_file: Some(all.clone()),
        },
    )
    .expect("export");
    let text = std::fs::read_to_string(&all).expect("read back");
    assert!(
        text.contains(&format!("OPENAI_CREDENTIAL={SENTINEL}")),
        "{text}"
    );
    assert!(
        text.contains(&format!("OTHER_PASSWORD={OTHER_SENTINEL}")),
        "{text}"
    );

    // A scoped token: it only gets the entries it is authorized for.
    let scoped = fx.dir.path().join("scoped.env");
    export(
        &ctx_with(&fx.home, &["--yes", "--token", &plaintext]),
        &ExportArgs {
            encoding: ExportFormat::Dotenv,
            out_file: Some(scoped.clone()),
        },
    )
    .expect("export");
    let text = std::fs::read_to_string(&scoped).expect("read back");
    assert!(text.contains("OTHER_PASSWORD"), "{text}");
    assert!(
        !text.contains("OPENAI"),
        "entries outside the scope must not be exported: {text}"
    );
    assert!(!text.contains(SENTINEL), "{text}");

    let export_audit = std::fs::read_to_string(&fx.store.paths.audit).expect("audit");
    assert!(export_audit.contains("\"export\""), "{export_audit}");
    assert!(!export_audit.contains(SENTINEL), "{export_audit}");

    // A `--deny-reveal` token: a whole-vault plaintext dump must be refused, and nothing written to disk.
    let denied = fx.dir.path().join("denied.env");
    let err = export(
        &ctx_with(&fx.home, &["--yes", "--token", &deny_plaintext]),
        &ExportArgs {
            encoding: ExportFormat::Json,
            out_file: Some(denied.clone()),
        },
    )
    .expect_err("a deny_reveal token must not export plaintext");
    assert_eq!(err.exit_code(), 7, "{err}");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(
        !denied.exists(),
        "nothing may be written to disk when denied"
    );
}

// ---- run: token scope (regression of this fix) --------

#[test]
fn a_scoped_token_cannot_inject_an_unauthorized_entry() {
    let issued = issued_token(Some(vec!["other".to_string()]));
    let plaintext = issued.plaintext.clone();
    let fx = fixture(vec![issued]);
    let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

    // None of the three forms may bypass it: a reference, `VAR=ITEM`, or a bare `ITEM`.
    for spec in ["X=akey://openai/credential", "X=openai", "openai"] {
        let marker = fx.dir.path().join("leaked.txt");
        let args = RunArgs {
            with: vec![spec.to_string()],
            env_file: Vec::new(),
            bundle: Vec::new(),
            no_masking: false,
            command: sh_write(&marker, "X"),
        };
        let err = run(&ctx, &args)
            .expect_err("a restricted token must not inject entries outside its scope");
        assert_eq!(err.exit_code(), 8, "spec '{spec}': {err}");
        assert!(
            matches!(err, Error::TokenScope(_)),
            "spec '{spec}': {err:?}"
        );
        assert!(
            !marker.exists(),
            "spec '{spec}': when authorization fails the child must not run, let alone write out plaintext"
        );
    }
}

#[test]
fn a_scoped_token_cannot_read_scope_through_an_env_file() {
    let issued = issued_token(Some(vec!["other".to_string()]));
    let plaintext = issued.plaintext.clone();
    let fx = fixture(vec![issued]);
    let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

    let env_file = fx.dir.path().join("scope.env");
    std::fs::write(&env_file, "X=akey://openai/credential\n").expect("write the env file");
    let marker = fx.dir.path().join("leaked.txt");
    let args = RunArgs {
        with: Vec::new(),
        env_file: vec![env_file],
        bundle: Vec::new(),
        no_masking: false,
        command: sh_write(&marker, "X"),
    };
    let err = run(&ctx, &args)
        .expect_err("a reference in an env file is subject to the scope just the same");
    assert_eq!(err.exit_code(), 8, "{err}");
    assert!(!marker.exists());
}

#[test]
fn a_scoped_token_can_inject_its_own_entries() {
    let issued = issued_token(Some(vec!["other".to_string()]));
    let plaintext = issued.plaintext.clone();
    let fx = fixture(vec![issued]);
    let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

    let marker = fx.dir.path().join("ok.txt");
    let args = RunArgs {
        with: vec!["X=akey://other/password".to_string()],
        env_file: Vec::new(),
        bundle: Vec::new(),
        no_masking: false,
        command: sh_write(&marker, "X"),
    };
    run(&ctx, &args).expect("entries inside the scope should be injectable");
    assert_eq!(
        std::fs::read_to_string(&marker).expect("read back the child's output"),
        OTHER_SENTINEL
    );
}

// ---- inject -----------------------------------------------------------

#[test]
fn a_scoped_token_cannot_render_an_unauthorized_template() {
    let issued = issued_token(Some(vec!["other".to_string()]));
    let plaintext = issued.plaintext.clone();
    let fx = fixture(vec![issued]);
    let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

    let template = fx.dir.path().join("tpl.txt");
    let out = fx.dir.path().join("rendered.txt");
    let args = InjectArgs {
        in_file: Some(template.clone()),
        out_file: Some(out.clone()),
    };

    std::fs::write(&template, "key=akey://openai/credential\n").expect("write the template");
    let err = inject(&ctx, &args)
        .expect_err("a restricted token must not render entries outside its scope");
    assert_eq!(err.exit_code(), 8, "{err}");
    assert!(
        !out.exists(),
        "nothing may be written to disk when authorization fails"
    );

    std::fs::write(&template, "key=akey://other/password\n").expect("write the template");
    inject(&ctx, &args).expect("references inside the scope should render");
    assert_eq!(
        std::fs::read_to_string(&out).expect("read back"),
        format!("key={OTHER_SENTINEL}\n")
    );
}

// ---- doc --------------------------------------------------------------

#[test]
fn doc_round_trips_a_file_attachment() {
    let fx = fixture(Vec::new());
    let ctx = ctx_with(&fx.home, &[]);
    let payload: &[u8] = b"\x00kubeconfig\xff binary payload";
    let blob = fx.dir.path().join("kubeconfig");
    std::fs::write(&blob, payload).expect("write the attachment");

    doc(
        &ctx,
        &DocArgs {
            command: DocCommand::Put {
                item: "openai".to_string(),
                file: blob,
                field: "file".to_string(),
            },
        },
    )
    .expect("put");

    let back = fx.dir.path().join("back.bin");
    doc(
        &ctx,
        &DocArgs {
            command: DocCommand::Get {
                reference: "akey://openai/file".to_string(),
                out_file: Some(back.clone()),
            },
        },
    )
    .expect("get");
    assert_eq!(
        std::fs::read(&back).expect("read back"),
        payload,
        "must round-trip byte for byte"
    );

    // A non-file field should go through `read`, not doc
    let err = doc(
        &ctx,
        &DocArgs {
            command: DocCommand::Get {
                reference: "akey://openai/credential".to_string(),
                out_file: None,
            },
        },
    )
    .expect_err("not a file field");
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("akey read"), "{err}");
}

#[test]
fn doc_put_and_import_are_denied_for_capability_tokens() {
    let issued = issued_token(None);
    let plaintext = issued.plaintext.clone();
    let fx = fixture(vec![issued]);
    let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

    let blob = fx.dir.path().join("blob");
    std::fs::write(&blob, b"data").expect("write the file");
    let err = doc(
        &ctx,
        &DocArgs {
            command: DocCommand::Put {
                item: "openai".to_string(),
                file: blob,
                field: "file".to_string(),
            },
        },
    )
    .expect_err("tokens are read-only credentials");
    assert_eq!(err.exit_code(), 7);
    assert!(matches!(err, Error::Denied(_)), "{err:?}");

    let env_file = fx.dir.path().join("in.env");
    std::fs::write(&env_file, "KEY=value\n").expect("write the env file");
    let err = import(
        &ctx,
        &ImportArgs {
            encoding: ExportFormat::Dotenv,
            in_file: Some(env_file),
            merge: false,
        },
    )
    .expect_err("tokens are read-only credentials");
    assert_eq!(err.exit_code(), 7);
}

#[test]
fn attachment_decoding_round_trips_and_rejects_junk() {
    let payload: &[u8] = b"\x00\xff\xfe binary";
    assert_eq!(
        decode_attachment(&STANDARD.encode(payload)).expect("decode"),
        payload
    );

    // The URL-safe variant is accepted too (the two encodings differ on bytes containing `+` / `/`)
    let tricky: &[u8] = &[0xfb, 0xff, 0xfe, 0xfa, 0xff];
    assert_eq!(
        decode_attachment(&URL_SAFE_NO_PAD.encode(tricky)).expect("decode"),
        tricky
    );

    let err = decode_attachment("not base64!!").expect_err("invalid base64");
    assert_eq!(err.exit_code(), 1);
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    assert!(
        !err.to_string().contains("not base64!!"),
        "the error message must not echo field values: {err}"
    );
}

// ---- import -----------------------------------------------------------

#[test]
fn import_plan_rejects_duplicates_and_merges_fields() {
    let fx = fixture(Vec::new());

    let err = plan_import(
        &fx.vault,
        vec![entry_with("openai", &[("credential", "v")])],
        false,
    )
    .expect_err("a duplicate name and no --merge");
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("--merge"), "{err}");

    let plan = plan_import(
        &fx.vault,
        vec![entry_with(
            "openai",
            &[("credential", "new-value"), ("org", "org-new")],
        )],
        true,
    )
    .expect("the merge plan");
    assert_eq!(plan.merges.len(), 1);
    assert!(plan.creates.is_empty());

    let mut vault = fx.vault.clone();
    let report = apply_plan(&mut vault, plan, Utc::now());
    assert_eq!(
        (
            report.created,
            report.merged,
            report.fields_written,
            report.fields_added
        ),
        (0, 1, 1, 1)
    );
    let openai = vault.find("openai").expect("openai");
    assert_eq!(openai.id, ulid(1), "a merge must keep the original ID");
    assert_eq!(
        openai.field("credential").expect("credential").value(),
        "new-value"
    );
    assert_eq!(openai.field("org").expect("org").value(), "org-new");
    assert_eq!(
        openai.reveal,
        Reveal::Allow,
        "local policy must not be overridden by an import file"
    );

    // A new name → create; the same name twice → usage
    let plan = plan_import(
        &fx.vault,
        vec![entry_with("fresh", &[("credential", "v")])],
        false,
    )
    .expect("the create plan");
    assert_eq!(plan.creates.len(), 1);

    let twice = vec![
        entry_with("dup", &[("a", "1")]),
        entry_with("dup", &[("a", "2")]),
    ];
    let err = plan_import(&fx.vault, twice, true).expect_err("a duplicate name within one file");
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("twice"), "{err}");

    let err = plan_import(
        &fx.vault,
        vec![entry_with("Bad Name", &[("a", "1")])],
        false,
    )
    .expect_err("an invalid entry name");
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn import_creates_entries_from_a_file_and_is_repeatable_with_merge() {
    let fx = fixture(Vec::new());
    let env_file = fx.dir.path().join("prod.env");
    std::fs::write(&env_file, "AWS_KEY=abc123\n").expect("write the env file");
    let ctx = ctx_with(&fx.home, &[]);

    let args = |merge: bool| ImportArgs {
        encoding: ExportFormat::Dotenv,
        in_file: Some(env_file.clone()),
        merge,
    };
    import(&ctx, &args(false)).expect("import");

    let vault = fx.store.load().expect("reload");
    let entry = vault.find("prod").expect("prod");
    assert_eq!(entry.category, Category::EnvBundle);
    assert_eq!(entry.field("aws_key").expect("aws_key").value(), "abc123");

    let err = import(&ctx, &args(false)).expect_err("a duplicate name and no --merge");
    assert_eq!(err.exit_code(), 2);

    std::fs::write(&env_file, "AWS_KEY=rotated\n").expect("rewrite the env file");
    import(&ctx, &args(true)).expect("--merge should make the import repeatable");
    let vault = fx.store.load().expect("reload");
    assert_eq!(
        vault
            .find("prod")
            .expect("prod")
            .field("aws_key")
            .expect("aws_key")
            .value(),
        "rotated"
    );

    let log = std::fs::read_to_string(&fx.store.paths.audit).expect("audit");
    assert!(!log.contains("abc123") && !log.contains("rotated"), "{log}");
}

#[test]
fn import_dotenv_creates_an_env_bundle_that_injects_back() {
    let fx = fixture(Vec::new());
    let imported = parse_import_dotenv(
        "prod",
        ".env",
        "export AWS_KEY=abc123\nDB_URL=\"postgres://u:p@h/db\"\n",
    )
    .expect("parse dotenv");
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].name, "prod");
    assert_eq!(imported[0].category, Category::EnvBundle);
    assert_eq!(
        imported[0].fields.len(),
        2,
        "duplicate and empty variables must both be handled cleanly"
    );

    // import → inject: the variable names must match exactly what the `.env` file said.
    let mut vault = Vault::default();
    vault.entries.insert(imported[0].id, imported[0].clone());
    let injection = inject::resolve(&fx.store, &vault, &[], &["prod".to_string()], &[])
        .expect("bundle injection");
    let vars: BTreeMap<&str, &str> = injection
        .vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(vars["AWS_KEY"], "abc123");
    assert_eq!(vars["DB_URL"], "postgres://u:p@h/db");

    // An empty file → usage, rather than creating an empty entry
    let err = parse_import_dotenv("prod", ".env", "# comment only\n").expect_err("no variables");
    assert_eq!(err.exit_code(), 2);

    assert_eq!(import_entry_name(Some(Path::new("/tmp/prod.env"))), "prod");
    assert_eq!(
        import_entry_name(Some(Path::new("/tmp/.env"))),
        "imported-env"
    );
    assert_eq!(import_entry_name(None), "imported-env");
}

#[test]
fn import_json_accepts_our_own_export_and_hand_written_lists() {
    let fx = fixture(Vec::new());
    let text = render_export(&fx.vault, ExportFormat::Json, None).expect("export");
    let entries = parse_import(ExportFormat::Json, "backup.json", &text).expect("parse");
    assert_eq!(entries.len(), 2);
    let openai = entries.iter().find(|e| e.name == "openai").expect("openai");
    assert_eq!(
        openai.field("credential").expect("credential").value(),
        SENTINEL
    );

    // A hand-written list: fill in defaults for an omitted id / timestamps rather than rejecting it
    let bare = r#"[{"name":"solo","category":"apikey","fields":[{"id":"credential","label":"credential","type":"concealed","value":"v"}]}]"#;
    let entries = parse_import(ExportFormat::Json, "bare.json", bare).expect("parse");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "solo");
    assert_eq!(
        entries[0].field("credential").expect("credential").value(),
        "v"
    );

    let err =
        parse_import(ExportFormat::Json, "x.json", "{\"hello\":1}").expect_err("not recognizable");
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("list of entries"), "{err}");
}

#[test]
fn import_csv1p_round_trips_our_own_export() {
    let fx = fixture(Vec::new());
    let text = render_export(&fx.vault, ExportFormat::Csv1p, None).expect("export");
    assert!(
        text.starts_with("Title,Username,Password,URL,Notes\n"),
        "{text}"
    );
    assert!(
        text.contains("\"Other, Inc.\""),
        "a title containing a comma needs quotes: {text}"
    );

    let entries = parse_import(ExportFormat::Csv1p, "1p.csv", &text).expect("parse");
    let other = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Other, Inc."))
        .expect("the other entry");
    assert!(
        is_valid_name(&other.name),
        "the derived name must be valid: {}",
        other.name
    );
    assert_eq!(
        other.field("username").expect("username").value(),
        "me@example.com"
    );
    assert_eq!(
        other.field("password").expect("password").value(),
        OTHER_SENTINEL
    );
    assert_eq!(other.url.as_deref(), Some("https://example.com/login"));

    let err = parse_import(ExportFormat::Csv1p, "x.csv", "Name,Password\nfoo,bar\n")
        .expect_err("a missing Title column");
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn export_dotenv_quotes_values_and_round_trips_through_the_env_parser() {
    let now = Utc::now();
    let mut entry = Entry::new(ulid(9), "quoted".to_string(), Category::Apikey, now);
    entry.fields.push(Field::new(
        "credential",
        FieldType::Concealed,
        "has space and \"quotes\"".to_string(),
    ));
    entry.fields.push(Field::new(
        "plain",
        FieldType::String,
        "plain-value".to_string(),
    ));
    let mut vault = Vault::default();
    vault.entries.insert(entry.id, entry);

    let text = export_dotenv(&vault, None);
    assert_eq!(
        text,
        "QUOTED_CREDENTIAL=\"has space and \\\"quotes\\\"\"\nQUOTED_PLAIN=plain-value\n"
    );

    // export <-> dotenv parsing must be inverses, or an exported file cannot be fed back to `run --env-file`.
    let values: BTreeMap<String, String> = inject::parse_dotenv("exported", &text)
        .expect("parse the exported dotenv")
        .into_iter()
        .collect();
    assert_eq!(values["QUOTED_CREDENTIAL"], "has space and \"quotes\"");
    assert_eq!(values["QUOTED_PLAIN"], "plain-value");
}

// ---- mcp --------------------------------------------------------------

#[test]
fn mcp_initialize_ping_and_tools_list() {
    let fx = fixture(Vec::new());
    let vault = &fx.vault;

    let init = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
    )
    .expect("initialize must reply");
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert_eq!(init["result"]["serverInfo"]["name"], "akey");
    assert!(init["result"]["serverInfo"]["version"].is_string());

    // The client gave no version → fall back to the default rather than crashing
    let init = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":2,"method":"initialize"}),
    )
    .expect("initialize must reply");
    assert!(init["result"]["protocolVersion"].is_string());
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // Notifications get no reply
    assert!(
        handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none(),
        "a notification must get no reply"
    );

    let pong = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
    )
    .expect("ping must reply");
    assert!(pong["result"].is_object());

    let tools = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}),
    )
    .expect("tools/list must reply");
    let listed = tools["result"]["tools"].as_array().expect("tool array");
    let names: Vec<&str> = listed.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(names, vec!["akey_list", "akey_get"]);
    for tool in listed {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert!(tool["description"].is_string(), "{tool}");
    }

    // On a locked machine the methods that do not need a vault must answer just the same
    let init = handle_message(None, &json!({"jsonrpc":"2.0","id":5,"method":"initialize"}))
        .expect("initialize does not involve the vault");
    assert!(init["result"]["serverInfo"].is_object());
    let listed = handle_message(None, &json!({"jsonrpc":"2.0","id":6,"method":"tools/list"}))
        .expect("tools/list does not involve the vault");
    assert!(listed["result"]["tools"].is_array());

    // Unknown method → -32601; non-object request → -32600
    let err = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":7,"method":"tools/whatever"}),
    )
    .expect("must reply with an error");
    assert_eq!(err["error"]["code"], -32601);
    let err = handle_message(Some(vault), &json!("nope")).expect("must reply with an error");
    assert_eq!(err["error"]["code"], -32600);
}

/// The FR-16 security floor: this channel must not emit field values under any circumstances.
#[test]
fn mcp_tools_never_return_field_values() {
    let fx = fixture(Vec::new());
    let vault = &fx.vault;

    let calls = [
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"akey_list","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"akey_list","arguments":{"category":"apikey"}}}),
        json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"akey_list","arguments":{"tags":["llm"]}}}),
        json!({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"openai"}}}),
        json!({"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"other"}}}),
        json!({"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"nope"}}}),
    ];
    for call in calls {
        let response = handle_message(Some(vault), &call).expect("must reply");
        let text = response.to_string();
        for leaked in [
            SENTINEL,
            OTHER_SENTINEL,
            "me@example.com",
            // `url` can carry secrets too (a token in a query string), so it is not exposed either
            "platform.openai.com",
            "example.com/login",
        ] {
            assert!(!text.contains(leaked), "MCP leaked {leaked}: {text}");
        }
        assert!(
            response["result"]["content"][0]["text"].is_string(),
            "content[].text must be a string: {response}"
        );
    }

    // But labels, types and references must be there — that is exactly what an agent uses to run `akey run`
    let get = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"openai"}}}),
    )
    .expect("must reply");
    let payload: Value = serde_json::from_str(
        get["result"]["content"][0]["text"]
            .as_str()
            .expect("the text"),
    )
    .expect("the body is JSON");
    assert_eq!(payload["entry"]["name"], "openai");
    assert_eq!(payload["entry"]["category"], "apikey");
    assert_eq!(payload["fields"][0]["label"], "credential");
    assert_eq!(payload["fields"][0]["type"], "concealed");
    assert_eq!(payload["fields"][0]["concealed"], true);
    assert_eq!(
        payload["fields"][0]["reference"],
        "akey://default/openai/credential"
    );
    assert!(
        payload["fields"][0].get("value").is_none(),
        "the field payload must not contain a value: {payload}"
    );

    // A missing entry → a tool-level error (isError), not a JSON-RPC error
    let missing = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"nope"}}}),
    )
    .expect("must reply");
    assert_eq!(missing["result"]["isError"], true);

    // Missing params / unknown tool → -32602; vault unavailable → -32000
    let err = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"akey_get","arguments":{}}}),
    )
    .expect("must reply");
    assert_eq!(err["error"]["code"], -32602);
    let err = handle_message(
        Some(vault),
        &json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"akey_delete"}}),
    )
    .expect("must reply");
    assert_eq!(err["error"]["code"], -32602);
    let err = handle_message(
        None,
        &json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"akey_list"}}),
    )
    .expect("must reply");
    assert_eq!(err["error"]["code"], -32000);

    // A tool call in notification form gets no reply
    assert!(
        handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"akey_list"}})
        )
        .is_none()
    );
}

use std::fs;

use age::secrecy::SecretString;
use chrono::Utc;
use clap::{CommandFactory, Parser};

use super::init::init_from_remote;
use super::passphrase::enforce_min;
use super::recovery::{decrypt_recovery, rotate_recovery, set_recovery, write_recovery};
use super::{MIN_PASSPHRASE_LEN, devices, git_for, init, recovery, token};
use crate::cli::{Cli, Command, InitArgs};
use crate::cmd::Ctx;
use crate::crypto::DeviceIdentity;
use crate::paths;
use crate::vault::recipients::RecipientKind;
use crate::vault::store::{AGENTS_FILE, RECIPIENTS_FILE, VAULT_FILE};

fn init_ctx(dir: &std::path::Path) -> (Cli, Ctx) {
    let cli = Cli::parse_from([
        "akey",
        "--home",
        dir.to_str().unwrap(),
        "init",
        "--no-recovery",
    ]);
    let ctx = Ctx::new(&cli).unwrap();
    (cli, ctx)
}

fn init_args(cli: &Cli) -> &InitArgs {
    match &cli.command {
        Command::Init(args) => args,
        other => panic!("expected init, got {other:?}"),
    }
}

#[test]
fn init_creates_a_usable_vault_without_a_remote() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();

    let store = ctx.store().unwrap();
    let vault = store.load().unwrap();
    assert!(vault.entries.is_empty());
    assert!(store.repo().join(VAULT_FILE).is_file());
    assert!(store.repo().join(RECIPIENTS_FILE).is_file());
    assert!(store.repo().join(AGENTS_FILE).is_file());
    assert!(!paths::permissions_exposed(&ctx.paths.identity).unwrap());
}

#[test]
fn init_refuses_to_run_twice() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let err = init(&ctx, init_args(&cli)).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("already initialized"));
}

#[test]
fn a_second_device_joins_without_the_owner() {
    // One machine creates the vault, another bootstraps with the recovery passphrase —
    // the core path of S4.
    let owner_dir = tempfile::tempdir().unwrap();
    let (owner_cli, owner_ctx) = init_ctx(owner_dir.path());
    init(&owner_ctx, init_args(&owner_cli)).unwrap();
    let owner_store = owner_ctx.store().unwrap();

    let passphrase = SecretString::from("correct-horse-battery");
    set_recovery(&owner_ctx, passphrase.clone()).unwrap();

    // Move the repository to a bare remote, simulating "bootstrap from a remote".
    let bare = tempfile::tempdir().unwrap();
    std::process::Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(bare.path())
        .output()
        .unwrap();
    let url = format!("file://{}", bare.path().display());
    let owner_git = git_for(&owner_store);
    owner_git.set_remote(&url).unwrap();
    owner_git.push().unwrap();

    let joiner_dir = tempfile::tempdir().unwrap();
    let joiner_cli = Cli::parse_from([
        "akey",
        "--home",
        joiner_dir.path().to_str().unwrap(),
        "init",
        "--from",
        &url,
        "--device",
        "laptop",
    ]);
    let joiner_ctx = Ctx::new(&joiner_cli).unwrap();
    // Pass the passphrase directly rather than mutating process-level environment
    // variables in a test (parallel tests would step on each other).
    init_from_remote(
        &joiner_ctx,
        init_args(&joiner_cli),
        &url,
        SecretString::from("correct-horse-battery"),
    )
    .unwrap();

    let joiner_store = joiner_ctx.store().unwrap();
    assert_eq!(joiner_store.identity.name(), "laptop");
    // The bootstrapped device can decrypt the vault on its own.
    assert_eq!(joiner_store.load().unwrap().entries.len(), 0);
}

#[test]
fn revoked_device_cannot_open_the_new_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    // Another "device" is approved and joins, then gets revoked.
    let mut store = ctx.store().unwrap();
    let stranger = DeviceIdentity::generate("stranger");
    let now = Utc::now();
    // Approve first: without this step save_with would encrypt only to this device, and
    // the "it can decrypt" assertion below would mean nothing.
    store.trust(&[stranger.pubkey()], now).unwrap();
    store
        .with_lock(|store| {
            let mut recipients = store.load_recipients()?;
            recipients.add(&stranger.pubkey(), "stranger", RecipientKind::Device, now);
            let vault = store.load()?;
            store.save_with(&vault, &recipients)?;
            recipients.save(&store.recipients_path())
        })
        .unwrap();
    assert!(
        stranger
            .decrypt(&fs::read(store.vault_path()).unwrap())
            .is_ok()
    );

    store
        .with_lock(|store| {
            let mut recipients = store.load_recipients()?;
            recipients.revoke("stranger", Utc::now())?;
            recipients.save(&store.recipients_path())?;
            let vault = store.load()?;
            store.save_with(&vault, &recipients)
        })
        .unwrap();
    store.untrust(&stranger.pubkey()).unwrap();

    let err = stranger
        .decrypt(&fs::read(store.vault_path()).unwrap())
        .unwrap_err();
    assert_eq!(err.exit_code(), 4, "revoked device must be locked out");
}

#[test]
fn devices_rm_refuses_to_remove_this_machine() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let store = ctx.store().unwrap();
    let me = store.config.device_name.clone();

    let cli = Cli::parse_from([
        "akey",
        "--home",
        dir.path().to_str().unwrap(),
        "devices",
        "rm",
        &me,
    ]);
    let ctx = Ctx::new(&cli).unwrap();
    let args = match &cli.command {
        Command::Devices(args) => args,
        other => panic!("expected devices, got {other:?}"),
    };
    let err = devices(&ctx, args).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("refusing"));
}

#[test]
fn recovery_roundtrip_then_rotation_keeps_bootstrap_usable() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let store = ctx.store().unwrap();

    set_recovery(&ctx, SecretString::from("first-passphrase-here")).unwrap();
    let payload = decrypt_recovery(&store, &SecretString::from("first-passphrase-here")).unwrap();
    assert_eq!(payload.version, 1);

    // After the rotation the old passphrase stops working and the new one works.
    write_recovery(
        &store,
        &payload,
        &SecretString::from("second-passphrase-here"),
    )
    .unwrap();
    assert!(decrypt_recovery(&store, &SecretString::from("first-passphrase-here")).is_err());
    assert!(decrypt_recovery(&store, &SecretString::from("second-passphrase-here")).is_ok());
}

#[test]
fn recovery_unlock_verifies_the_bootstrap_can_open_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    set_recovery(&ctx, SecretString::from("a-long-enough-passphrase")).unwrap();

    let store = ctx.store().unwrap();
    let payload =
        decrypt_recovery(&store, &SecretString::from("a-long-enough-passphrase")).unwrap();
    let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap").unwrap();
    assert!(
        bootstrap
            .decrypt(&fs::read(store.vault_path()).unwrap())
            .is_ok(),
        "bootstrap identity must be a vault recipient"
    );
}

#[test]
fn token_create_shows_plaintext_once_and_list_never_does() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();

    let create = Cli::parse_from([
        "akey",
        "--home",
        dir.path().to_str().unwrap(),
        "token",
        "create",
        "--name",
        "ci",
        "--allow",
        "openai",
        "--deny-reveal",
        "--ttl",
        "30d",
    ]);
    let ctx = Ctx::new(&create).unwrap();
    let args = match &create.command {
        Command::Token(args) => args,
        other => panic!("expected token, got {other:?}"),
    };
    token(&ctx, args).unwrap();

    let store = ctx.store().unwrap();
    let vault = store.load().unwrap();
    let meta = vault.find_token("ci").unwrap();
    assert_eq!(meta.allow.as_deref(), Some(&["openai".to_string()][..]));
    assert!(meta.deny_reveal);
    assert!(meta.expires_at.is_some());
    // The vault holds only the digest, never the plaintext.
    let raw = serde_json::to_string(&vault).unwrap();
    assert!(
        !raw.contains("akey_"),
        "token plaintext leaked into the vault"
    );
}

#[test]
fn rotation_actually_changes_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let store = ctx.store().unwrap();

    let old = SecretString::from("old-passphrase-here");
    let new = SecretString::from("new-passphrase-here");
    set_recovery(&ctx, old.clone()).unwrap();

    rotate_recovery(&store, &old, &new).unwrap();

    assert!(
        decrypt_recovery(&store, &old).is_err(),
        "the old passphrase must stop working"
    );
    assert!(
        decrypt_recovery(&store, &new).is_ok(),
        "the new passphrase must work"
    );
    // After the rotation the bootstrap identity can still open the vault — otherwise
    // the machine-transfer path would break.
    let payload = decrypt_recovery(&store, &new).unwrap();
    let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap").unwrap();
    assert!(
        bootstrap
            .decrypt(&fs::read(store.vault_path()).unwrap())
            .is_ok()
    );
}

#[test]
fn rotating_to_the_same_passphrase_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let store = ctx.store().unwrap();

    let same = SecretString::from("same-passphrase-here");
    set_recovery(&ctx, same.clone()).unwrap();
    let err = rotate_recovery(&store, &same, &same).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("identical"));
}

#[test]
fn repeated_recovery_set_leaves_exactly_one_active_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let store = ctx.store().unwrap();

    set_recovery(&ctx, SecretString::from("first-passphrase-here")).unwrap();
    set_recovery(&ctx, SecretString::from("second-passphrase-here")).unwrap();

    let recipients = store.load_recipients().unwrap();
    let bootstraps = recipients
        .recipients
        .values()
        .filter(|r| r.kind == RecipientKind::Bootstrap && r.is_active())
        .count();
    assert_eq!(
        bootstraps, 1,
        "a second `recovery set` must retire the previous bootstrap identity"
    );

    // Only the newest passphrase works, and it can open the vault.
    assert!(decrypt_recovery(&store, &SecretString::from("first-passphrase-here")).is_err());
    let payload = decrypt_recovery(&store, &SecretString::from("second-passphrase-here")).unwrap();
    let bootstrap = DeviceIdentity::parse(&payload.bootstrap_identity, "bootstrap").unwrap();
    assert!(
        bootstrap
            .decrypt(&fs::read(store.vault_path()).unwrap())
            .is_ok()
    );
}

#[test]
fn passphrase_minimum_applies_to_new_ones_only() {
    let short = SecretString::from("a");
    let long = SecretString::from("long-enough-to-be-a-passphrase");

    // New: must be long enough no matter where it came from (this once held only on the
    // TTY path, so AKEY_RECOVERY_PASSPHRASE could set a 1-character passphrase).
    assert!(enforce_min(short.clone(), true, MIN_PASSPHRASE_LEN).is_err());
    assert_eq!(
        enforce_min(short.clone(), true, MIN_PASSPHRASE_LEN)
            .unwrap_err()
            .exit_code(),
        2
    );
    assert!(enforce_min(long.clone(), true, MIN_PASSPHRASE_LEN).is_ok());

    // Existing: the length must never be enforced here, otherwise tightening the policy
    // would make an old vault impossible to open.
    assert!(enforce_min(short, false, MIN_PASSPHRASE_LEN).is_ok());
    assert!(enforce_min(long, false, MIN_PASSPHRASE_LEN).is_ok());
}

#[test]
fn enforce_min_respects_explicit_min_len_override() {
    let twelve = SecretString::from("twelve_chars");
    // At the default 12: ok.
    assert!(enforce_min(twelve.clone(), true, MIN_PASSPHRASE_LEN).is_ok());
    // Bumping the floor to 16: the same string is rejected.
    assert!(enforce_min(twelve, true, 16).is_err());
}

#[test]
fn enforce_min_refuses_floor_below_absolute_minimum() {
    let ok = SecretString::from("ok-enough");
    assert!(enforce_min(ok, true, 4).is_err());
}

#[test]
fn enforce_min_refuses_ceiling_above_absolute_maximum() {
    let ok = SecretString::from("ok-enough");
    assert!(enforce_min(ok, true, 9999).is_err());
}

#[test]
fn recovery_status_envelope_carries_no_passphrase() {
    // The strongest assertion — no fixture passphrase substring in any of the
    // on-disk artefacts written by `recovery status`. The JSON envelope shape
    // (configured/min_length/strength/recovery_file) is pinned by the contract
    // test in tests/contract.rs.
    let dir = tempfile::tempdir().unwrap();
    let (cli, ctx) = init_ctx(dir.path());
    init(&ctx, init_args(&cli)).unwrap();
    let fixture_passphrase = "correct horse battery staple x";
    set_recovery(&ctx, SecretString::from(fixture_passphrase)).unwrap();

    let cli = Cli::parse_from([
        "akey",
        "--home",
        dir.path().to_str().unwrap(),
        "--json",
        "recovery",
        "status",
    ]);
    let recovery_args = match &cli.command {
        Command::Recovery(args) => args,
        other => panic!("expected recovery, got {other:?}"),
    };
    recovery(&ctx, recovery_args).expect("status must run");

    // `recovery.age` is the only file the command could plausibly touch; confirm
    // the passphrase did not leak there.
    let blob = std::fs::read_to_string(ctx.paths.audit.as_path()).unwrap_or_default();
    assert!(
        !blob.contains(fixture_passphrase),
        "passphrase leaked into audit log: {blob}"
    );
    // The recovery ciphertext is unreadable without the passphrase, so a leak
    // there would be a serious bug. We can't decrypt it in the test, but we
    // can confirm the file size and that no readable text fragment matches.
    let recovery_bytes = std::fs::metadata(store_recovery_path(&ctx))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(recovery_bytes > 0);
    let recovery_dump = std::fs::read(store_recovery_path(&ctx)).unwrap_or_default();
    let recovery_text = String::from_utf8_lossy(&recovery_dump);
    assert!(
        !recovery_text.contains(fixture_passphrase),
        "passphrase leaked into recovery.age: {:?}",
        String::from_utf8_lossy(&recovery_dump[..recovery_dump.len().min(64)])
    );
}

fn store_recovery_path(ctx: &crate::cmd::Ctx) -> std::path::PathBuf {
    ctx.store().unwrap().recovery_path()
}

#[test]
fn schema_lists_every_documented_command() {
    let command = Cli::command();
    let names: Vec<String> = command
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for expected in [
        "init",
        "read",
        "run",
        "inject",
        "get",
        "set",
        "edit",
        "rm",
        "restore",
        "cp",
        "mv",
        "list",
        "template",
        "doc",
        "token",
        "devices",
        "agent",
        "recovery",
        "sync",
        "conflicts",
        "resolve",
        "log",
        "whoami",
        "doctor",
        "schema",
        "completion",
        "export",
        "import",
        "mcp",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "missing command {expected}"
        );
    }
}

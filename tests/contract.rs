//! CLI contract tests: envelope, exit codes, stdout/stderr separation, plaintext never leaking.
//!
//! These assertions come from `REQUIREMENTS.md` FR-3 / FR-4 and `DESIGN.md` §10, §12 —
//! they are the **public contract**, not implementation details.

mod common;

use common::{Device, bare_remote};

use tempfile::TempDir;

const CANARY: &str = "CANARY-3f9a7b2e";

fn with_entry() -> Device {
    let device = Device::initialized("testbox");
    device.set_secret("openai", "credential", CANARY);
    device
}

// --------------------------------------------------------------- envelope and stream separation

#[test]
fn json_success_is_a_single_ok_envelope_on_stdout() {
    let device = with_entry();
    let data = device.json_ok(&["list"]);
    assert!(data["entries"].is_array());

    // stdout must be **one** JSON document, with no diagnostics mixed in.
    let raw = device.stdout(&["--json", "list"]);
    assert_eq!(raw.trim().lines().count(), 1, "stdout must be one JSON document");
}

#[test]
fn failure_writes_nothing_to_stdout() {
    let device = with_entry();
    let (code, kind, stdout) = device.expect_failure(&["get", "no-such-entry"]);
    assert_eq!(code, 3);
    assert_eq!(kind, "not_found");
    assert!(
        stdout.trim().is_empty(),
        "a failing command must not write to stdout, got: {stdout}"
    );
}

#[test]
fn human_mode_keeps_diagnostics_off_stdout() {
    let device = with_entry();
    let out = device.run(&["get", "no-such-entry"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty(), "human mode must explain the failure on stderr");
}

// --------------------------------------------------------------- exit codes

#[test]
fn exit_codes_match_the_documented_contract() {
    let device = with_entry();

    assert_eq!(device.run(&["list"]).status.code(), Some(0), "ok");

    let bad_flag = device.run(&["--not-a-real-flag"]);
    assert_eq!(bad_flag.status.code(), Some(2), "usage");

    assert_eq!(device.expect_failure(&["get", "ghost"]).0, 3, "not_found");

    let empty = Device::blank();
    assert_eq!(empty.expect_failure(&["list"]).0, 4, "locked: no identity yet");

    let out = device
        .command()
        .env("AKEY_NO_REVEAL", "1")
        .args(["--json", "get", "openai", "--reveal"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "denied by AKEY_NO_REVEAL");
}

#[test]
fn token_scope_violation_is_exit_8() {
    let device = with_entry();
    device.set_secret("anthropic", "credential", "sk-other");

    let created = device.json_ok(&[
        "token",
        "create",
        "--name",
        "narrow",
        "--allow",
        "anthropic",
    ]);
    let token = created["token"].as_str().expect("plaintext shown once");

    let out = device
        .command()
        .env("AKEY_TOKEN", token)
        .args(["--json", "read", "akey://openai/credential"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(8), "token must not reach 'openai'");

    // Out-of-scope wins over "no reveal": when both apply, report the more precise one.
    let locked_down = device.json_ok(&[
        "token",
        "create",
        "--name",
        "narrow-no-reveal",
        "--allow",
        "anthropic",
        "--deny-reveal",
    ]);
    let locked_down_token = locked_down["token"].as_str().unwrap();
    let out = device
        .command()
        .env("AKEY_TOKEN", locked_down_token)
        .args(["--json", "read", "akey://openai/credential"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(8),
        "an out-of-scope entry must report token_scope, not a vague denial"
    );

    // Entries within scope still work.
    let out = device
        .command()
        .env("AKEY_TOKEN", token)
        .args(["--json", "read", "akey://anthropic/credential"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("sk-other"));
}

/// A token is a read-only credential: scope cannot be bypassed by write commands.
#[test]
fn a_token_cannot_write() {
    let device = with_entry();
    let created = device.json_ok(&["token", "create", "--name", "reader", "--allow", "openai"]);
    let token = created["token"].as_str().unwrap();

    for args in [
        vec!["rm", "openai"],
        vec!["mv", "openai", "renamed"],
        vec!["edit", "openai", "--title", "pwned"],
    ] {
        let out = device
            .command()
            .env("AKEY_TOKEN", token)
            .args(["--json"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(7),
            "`akey {}` must be denied under a token",
            args.join(" ")
        );
    }

    // The vault was not touched.
    assert_eq!(entry_names(&device), vec!["openai".to_string()]);
}

/// Key regression: scope must apply to injection too, otherwise `--allow` is meaningless.
#[test]
fn token_scope_cannot_be_bypassed_by_injection() {
    let device = with_entry();
    device.set_secret("anthropic", "credential", "sk-allowed");

    let created = device.json_ok(&[
        "token",
        "create",
        "--name",
        "narrow",
        "--allow",
        "anthropic",
    ]);
    let token = created["token"].as_str().unwrap();

    let out = device
        .command()
        .env("AKEY_TOKEN", token)
        .args([
            "run",
            "--with",
            "LEAK=akey://openai/credential",
            "--",
            "sh",
            "-c",
            "echo $LEAK",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(8), "scope must apply to injection too");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains(CANARY), "secret escaped through run: {stdout}");

    // In-scope entries can still be injected.
    let out = device
        .command()
        .env("AKEY_TOKEN", token)
        .args([
            "run",
            "--with",
            "OK=akey://anthropic/credential",
            "--",
            "sh",
            "-c",
            "test -n \"$OK\"",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn export_under_a_token_only_covers_the_scope() {
    let device = with_entry();
    device.set_secret("anthropic", "credential", "sk-allowed");

    let created = device.json_ok(&[
        "token",
        "create",
        "--name",
        "narrow",
        "--allow",
        "anthropic",
    ]);
    let token = created["token"].as_str().unwrap();

    let out = device
        .command()
        .env("AKEY_TOKEN", token)
        .args(["--json", "export", "--as", "json", "--yes"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("anthropic"));
    assert!(!stdout.contains(CANARY), "export leaked an out-of-scope entry");
}

/// A capability token is a read-only credential — **including being unable to change the
/// cryptographic boundary itself**.
///
/// The admin side used to be missed: a token scoped to a single entry could `token create` an
/// **unrestricted** token and then read the whole vault; it could also `recovery set` a recovery
/// passphrase for itself that the operator never sees. Both were reproduced.
#[test]
fn a_scoped_token_cannot_mutate_admin_state() {
    let device = with_entry();
    let created = device.json_ok(&["token", "create", "--name", "narrow", "--allow", "openai"]);
    let token = created["token"].as_str().unwrap();

    for args in [
        vec!["token", "create", "--name", "escalated"],
        vec!["devices", "add", "--name", "backdoor"],
        vec!["devices", "rename", "testbox", "renamed"],
        vec!["recovery", "set"],
        vec!["token", "rm", "narrow"],
    ] {
        let out = device
            .command()
            .env("AKEY_TOKEN", token)
            .env("AKEY_RECOVERY_PASSPHRASE", "attacker-chosen-passphrase")
            .args(["--json"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(7),
            "`akey {}` must be denied under a token",
            args.join(" ")
        );
    }

    // The vault was not modified: no new token and no planted recovery passphrase.
    let tokens = device.json_ok(&["token", "list"]);
    let names: Vec<&str> = tokens["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["narrow"]);
    assert!(!device.repo().join("recovery.age").exists(), "no backdoor passphrase");
}

fn entry_names(device: &Device) -> Vec<String> {
    let data = device.json_ok(&["list"]);
    let mut names: Vec<String> = data["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

// --------------------------------------------------------------- plaintext exposure control

/// `inject` hands the rendered result straight to the caller, so it is a **plaintext channel**,
/// not a peer of `run`.
///
/// These three cover the same root cause: the design doc once lumped inject together with run,
/// so the entry policy, `AKEY_NO_REVEAL`, and the token `--deny-reveal` gates were never fitted
/// to inject — a single `printf 'x=akey://openai/credential' | akey inject` could extract plaintext.
#[test]
fn inject_cannot_route_around_a_global_reveal_ban() {
    let device = with_entry();
    let template = "token=akey://openai/credential\n";

    let out = device.run_with_stdin_env(&["inject"], template, &[("AKEY_NO_REVEAL", "1")]);
    assert_eq!(out.status.code(), Some(7), "AKEY_NO_REVEAL must cover inject");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(CANARY),
        "plaintext escaped through inject"
    );
}

#[test]
fn inject_cannot_route_around_a_deny_reveal_token() {
    let device = with_entry();
    let created = device.json_ok(&["token", "create", "--name", "reader", "--deny-reveal"]);
    let token = created["token"].as_str().unwrap();

    let out = device.run_with_stdin_env(
        &["inject"],
        "token=akey://openai/credential\n",
        &[("AKEY_TOKEN", token)],
    );
    assert_eq!(out.status.code(), Some(7), "a deny-reveal token must cover inject");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(CANARY));
}

#[test]
fn inject_respects_a_per_entry_reveal_deny() {
    let device = with_entry();
    device.json_ok(&["edit", "openai", "--reveal-policy", "deny"]);

    let out = device.run_with_stdin(&["inject"], "token=akey://openai/credential\n");
    assert_eq!(out.status.code(), Some(7));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(CANARY));
}

/// Masking is how "run does not hand plaintext to the caller" is implemented, so the switch that turns it off must be bound by the same policy set.
#[test]
fn run_refuses_no_masking_while_reveal_is_forbidden() {
    let device = with_entry();
    let out = device
        .command()
        .env("AKEY_NO_REVEAL", "1")
        .args([
            "run",
            "--no-masking",
            "--with",
            "X=akey://openai/credential",
            "--",
            "sh",
            "-c",
            "echo $X",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(CANARY));

    // With masking on, the same run still works (you just cannot see the plaintext).
    let out = device.run(&[
        "run",
        "--with",
        "X=akey://openai/credential",
        "--",
        "sh",
        "-c",
        "echo $X",
    ]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("concealed by akey"));
}

/// `export` takes the whole vault out in the clear, so it must not carry along entries explicitly marked "never take plaintext".
#[test]
fn export_refuses_entries_marked_reveal_deny() {
    let device = with_entry();
    device.set_secret("quiet", "credential", "sk-quiet-canary");
    device.json_ok(&["edit", "quiet", "--reveal-policy", "deny"]);

    let (code, kind, stdout) = device.expect_failure(&["export", "--as", "json", "--yes"]);
    assert_eq!(code, 7, "export must not carry reveal=deny entries out in the clear");
    assert_eq!(kind, "denied");
    assert!(stdout.is_empty());

    // The hint names which entry — otherwise the user has no way in.
    let stderr = device.stderr(&["export", "--as", "json", "--yes"]);
    assert!(stderr.contains("quiet"), "the error must name the offending entry");

    // It only lets it through after an explicit change back to allow, and that is a **deliberate** step.
    device.json_ok(&["edit", "quiet", "--reveal-policy", "allow"]);
    device.json_ok(&["export", "--as", "json", "--yes"]);
}

#[test]
fn get_conceals_secrets_and_exposes_references_instead() {
    let device = with_entry();
    let data = device.json_ok(&["get", "openai"]);
    let rendered = serde_json::to_string(&data).unwrap();

    assert!(!rendered.contains(CANARY), "concealed value leaked: {rendered}");
    assert!(rendered.contains("********"), "expected a redaction placeholder");
    assert!(
        rendered.contains("akey://default/openai/credential"),
        "fields must carry a reference so an agent can point at a secret \
         without ever reading it: {rendered}"
    );
}

#[test]
fn get_reveal_shows_the_value_only_when_asked() {
    let device = with_entry();
    let data = device.json_ok(&["get", "openai", "--reveal"]);
    assert!(serde_json::to_string(&data).unwrap().contains(CANARY));
}

#[test]
fn list_never_carries_field_values() {
    let device = with_entry();
    let raw = device.stdout(&["--json", "list"]);
    assert!(raw.contains("openai"), "listing should name the entry");
    assert!(!raw.contains(CANARY), "listing leaked a value");
}

#[test]
fn entry_can_be_pinned_to_deny_reveal() {
    let device = with_entry();
    let out = device.run(&["edit", "openai", "--reveal-policy", "deny"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let (code, kind, _) = device.expect_failure(&["read", "akey://openai/credential"]);
    assert_eq!(code, 7);
    assert_eq!(kind, "denied");
}

// --------------------------------------------------------------- injection

#[test]
fn run_injects_a_secret_into_the_child_and_masks_any_echo() {
    let device = with_entry();

    // 1. The child process really got the plaintext.
    let out = device.run(&[
        "run",
        "--with",
        "OPENAI_API_KEY=akey://openai/credential",
        "--",
        "sh",
        "-c",
        "test -n \"$OPENAI_API_KEY\"",
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // 2. Echoing from the child is masked, so plaintext never reaches the caller's stdout.
    let out = device.run(&[
        "run",
        "--with",
        "OPENAI_API_KEY=akey://openai/credential",
        "--",
        "sh",
        "-c",
        "echo $OPENAI_API_KEY",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains(CANARY), "secret reached stdout: {stdout}");
    assert!(stdout.contains("concealed by akey"), "expected masking: {stdout}");
}

#[test]
fn run_passes_through_the_child_exit_code() {
    let device = with_entry();
    let out = device.run(&["run", "--", "sh", "-c", "exit 42"]);
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn run_reads_references_out_of_an_env_file() {
    let device = with_entry();
    let env_file = device.workspace.path().join(".env");
    std::fs::write(&env_file, "DB_PASSWORD=akey://openai/credential\n# a comment\n").unwrap();

    let out = device.run(&[
        "run",
        "--env-file",
        env_file.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "test -n \"$DB_PASSWORD\"",
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn inject_renders_a_template_without_printing_to_the_caller() {
    let device = with_entry();
    let template = device.workspace.path().join("tpl.txt");
    std::fs::write(&template, "token=akey://openai/credential\n").unwrap();
    let output = device.workspace.path().join("out.txt");

    let out = device.run(&[
        "inject",
        "-i",
        template.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(std::fs::read_to_string(&output).unwrap().contains(CANARY));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(CANARY));
}

// --------------------------------------------------------------- audit and bootstrap

#[test]
fn audit_log_records_actions_without_secrets() {
    let device = with_entry();
    device.run(&["read", "akey://openai/credential"]);

    let log_path = device.home_path().join("audit.log");
    let log = std::fs::read_to_string(&log_path).expect("audit log should exist");
    assert!(log.contains("openai"), "subject should be recorded");
    assert!(!log.contains(CANARY), "audit log leaked a secret");
}

#[test]
fn init_ships_agent_documentation_into_the_vault_repo() {
    let device = Device::initialized("testbox");
    let doc = std::fs::read_to_string(device.repo().join("AGENTS.md"))
        .expect("init must write AGENTS.md so a fresh agent can self-serve");
    assert!(doc.contains("akey run"), "the doc should teach the injection pattern");
}

#[test]
fn schema_is_machine_readable_and_complete() {
    let device = Device::initialized("testbox");
    let data = device.json_ok(&["schema"]);
    for key in ["name", "version", "global_flags", "env_vars", "exit_codes", "reference", "commands"] {
        assert!(data.get(key).is_some(), "schema is missing '{key}'");
    }
    let commands = data["commands"].as_array().unwrap();
    for expected in ["init", "run", "read", "get", "sync", "doctor"] {
        assert!(
            commands.iter().any(|c| c["name"] == expected),
            "schema omits command '{expected}'"
        );
    }
}

// --------------------------------------------------------------- non-interactive

#[test]
fn commands_never_block_waiting_for_input() {
    // Every command must complete with no TTY and stdin closed.
    let device = with_entry();
    for args in [
        vec!["list"],
        vec!["get", "openai"],
        vec!["sync"],
        vec!["doctor"],
        vec!["whoami"],
    ] {
        let out = device.run(&args);
        assert!(
            out.status.code().is_some(),
            "`akey {}` did not terminate — it is probably waiting on a prompt",
            args.join(" ")
        );
    }
}

#[test]
fn sync_without_a_remote_is_not_an_error() {
    let device = with_entry();
    let data = device.json_ok(&["sync"]);
    assert_eq!(data["outcome"], "no_remote");
}

// --------------------------------------------------------------- remote present but unreachable

#[test]
fn sync_reports_a_broken_remote_as_sync_failed() {
    let device = Device::blank();
    let remote = TempDir::new().unwrap();
    let url = bare_remote(&remote);
    device.init("testbox", &["--remote", &url]);

    // Pull the remote away so fetch fails.
    std::fs::remove_dir_all(remote.path().join("remote.git")).unwrap();

    let (code, kind, _) = device.expect_failure(&["sync"]);
    assert_eq!(code, 6, "unreachable remote must map to sync_failed");
    assert_eq!(kind, "sync_failed");
}

// --------------------------------------------------------------- the rest of the command surface
//
// This group covers the paths that only the real CLI exposes — clashing argument ids,
// un-wired subcommands, misaligned error-code mappings, and the like, none of which unit
// tests can see. A `--format` clash slipped through exactly this way.

#[test]
fn every_category_has_a_usable_template() {
    let device = Device::initialized("testbox");
    for category in [
        "apikey",
        "login",
        "token",
        "database",
        "ssh-key",
        "secure-note",
        "env-bundle",
    ] {
        let data = device.json_ok(&["template", "get", category]);
        assert_eq!(data["category"], category);
    }
    let listed = device.json_ok(&["template", "list"]);
    assert_eq!(listed["categories"].as_array().unwrap().len(), 7);
    // Every category must report its default secret field — `set --stdin` relies on it when no field name is given.
    for entry in listed["categories"].as_array().unwrap() {
        assert!(
            entry["default_secret_field"].is_string(),
            "{} has no default secret field",
            entry["category"]
        );
    }
}

#[test]
fn copy_move_remove_and_restore_round_trip() {
    let device = with_entry();

    device.json_ok(&["cp", "openai", "openai-copy"]);
    assert_eq!(entry_names(&device), vec!["openai", "openai-copy"]);

    device.json_ok(&["mv", "openai-copy", "openai-moved"]);
    assert_eq!(entry_names(&device), vec!["openai", "openai-moved"]);

    // After a soft delete it is hidden by default, visible with --all, and restorable.
    device.json_ok(&["rm", "openai-moved"]);
    assert_eq!(entry_names(&device), vec!["openai"]);
    let all = device.json_ok(&["list", "--all"]);
    assert_eq!(all["entries"].as_array().unwrap().len(), 2);
    device.json_ok(&["restore", "openai-moved"]);
    assert_eq!(entry_names(&device), vec!["openai", "openai-moved"]);

    // After --purge it is gone for good.
    device.json_ok(&["rm", "openai-moved", "--purge"]);
    let all = device.json_ok(&["list", "--all"]);
    assert_eq!(all["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn edit_updates_metadata_without_touching_the_secret() {
    let device = with_entry();
    device.json_ok(&["edit", "openai", "--title", "OpenAI", "--tags", "llm,prod"]);

    let data = device.json_ok(&["get", "openai"]);
    assert_eq!(data["title"], "OpenAI");
    assert_eq!(data["tags"].as_array().unwrap().len(), 2);
    // The value was not touched and is still concealed.
    assert!(!serde_json::to_string(&data).unwrap().contains(CANARY));
    assert!(
        device
            .stdout(&["read", "akey://openai/credential"])
            .contains(CANARY)
    );
}

#[test]
fn documents_round_trip_binary_payloads() {
    let device = with_entry();
    let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let source = device.workspace.path().join("kubeconfig.bin");
    std::fs::write(&source, &payload).unwrap();

    device.json_ok(&["doc", "put", "openai", source.to_str().unwrap(), "--field", "kubeconfig"]);

    let restored = device.workspace.path().join("restored.bin");
    device.json_ok(&["doc", "get", "akey://openai/kubeconfig", "-o", restored.to_str().unwrap()]);
    assert_eq!(std::fs::read(&restored).unwrap(), payload, "byte-for-byte");
}

#[test]
fn export_needs_yes_and_import_round_trips() {
    let device = with_entry();

    let (code, kind, _) = device.expect_failure(&["export", "--as", "json"]);
    assert_eq!(code, 2, "exporting plaintext must be explicit");
    assert_eq!(kind, "usage");

    let dump = device.workspace.path().join("dump.json");
    device.json_ok(&["export", "--as", "json", "--yes", "-o", dump.to_str().unwrap()]);

    let other = Device::initialized("other");
    other.json_ok(&["import", "--as", "json", "-i", dump.to_str().unwrap()]);

    // A name clash must be blocked; only --merge lets it through.
    let (code, _, _) = other.expect_failure(&["import", "--as", "json", "-i", dump.to_str().unwrap()]);
    assert_eq!(code, 2);
    other.json_ok(&["import", "--as", "json", "-i", dump.to_str().unwrap(), "--merge"]);

    assert!(
        other
            .stdout(&["read", "akey://openai/credential"])
            .contains(CANARY),
        "imported entry must be usable on the other device"
    );
}

#[test]
fn mcp_speaks_json_rpc_and_never_returns_values() {
    let device = with_entry();
    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"akey_list","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"openai"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"no/such/method"}"#,
    ];
    let out = device.run_with_stdin(&["mcp"], &(requests.join("\n") + "\n"));
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    let replies: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("every reply must be one JSON document"))
        .collect();

    // One of the 6 requests is a notification, which per JSON-RPC must not be answered.
    assert_eq!(replies.len(), 5, "notifications must not be answered: {stdout}");

    let by_id = |id: i64| {
        replies
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no reply for id {id}"))
    };
    assert!(by_id(1)["result"]["serverInfo"].is_object());
    assert!(by_id(2)["result"]["tools"].is_array());
    assert_eq!(by_id(5)["error"]["code"], -32601, "unknown method");

    // The security floor: this channel never leaks field values.
    assert!(
        !stdout.contains(CANARY),
        "MCP leaked a secret: {stdout}"
    );
}

#[test]
fn completion_emits_a_shell_script() {
    let device = Device::initialized("testbox");
    for shell in ["bash", "zsh", "fish"] {
        let script = device.stdout(&["completion", shell]);
        assert!(!script.trim().is_empty(), "{shell} completion is empty");
        assert!(script.contains("akey"), "{shell} completion does not mention akey");
    }
}

#[test]
fn recovery_rotate_changes_the_passphrase_non_interactively() {
    let device = Device::initialized("testbox");
    device.enable_recovery("the-first-passphrase");

    // Old and new are supplied separately, otherwise non-interactively both reads get the same value.
    device.run_ok_with_env(
        &["recovery", "rotate"],
        &[
            ("AKEY_RECOVERY_PASSPHRASE", "the-first-passphrase"),
            ("AKEY_NEW_RECOVERY_PASSPHRASE", "the-second-passphrase"),
        ],
    );

    let old = device.run_with_env(
        &["recovery", "unlock"],
        &[("AKEY_RECOVERY_PASSPHRASE", "the-first-passphrase")],
    );
    assert_eq!(old.status.code(), Some(4), "the old passphrase must stop working");

    device.run_ok_with_env(
        &["recovery", "unlock"],
        &[("AKEY_RECOVERY_PASSPHRASE", "the-second-passphrase")],
    );
}

#[test]
fn recovery_rotate_refuses_to_be_a_no_op() {
    let device = Device::initialized("testbox");
    device.enable_recovery("the-only-passphrase");

    let out = device.run_with_env(
        &["recovery", "rotate"],
        &[("AKEY_RECOVERY_PASSPHRASE", "the-only-passphrase")],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("identical"),
        "a rotate that does not rotate must be rejected loudly"
    );
}

#[test]
fn a_weak_recovery_passphrase_is_refused_from_any_source() {
    let device = Device::initialized("testbox");

    // The environment-variable path used to bypass the length check, allowing a single-character passphrase.
    let out = device.run_with_env(&["recovery", "set"], &[("AKEY_RECOVERY_PASSPHRASE", "a")]);
    assert_eq!(out.status.code(), Some(2), "1-character passphrase must be refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least"));

    let out = device.run_with_env(
        &["recovery", "rotate"],
        &[
            ("AKEY_RECOVERY_PASSPHRASE", "a-long-enough-passphrase"),
            ("AKEY_NEW_RECOVERY_PASSPHRASE", "b"),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "rotate must refuse a weak replacement too");
}

#[test]
fn devices_rename_is_visible_in_the_recipient_list() {
    let device = Device::initialized("oldname");
    device.json_ok(&["devices", "rename", "oldname", "newname"]);

    let listed = device.json_ok(&["devices", "list"]);
    let names: Vec<&str> = listed["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["newname"]);
    assert_eq!(listed["devices"][0]["this_device"], true);
}

/// Agent-facing docs must not quietly fall behind the CLI.
///
/// An agent only acts on the docs and `akey schema` — a new command missing from the docs is a
/// command that does not exist for it. This is a real slip that happens (this round, 8 commands
/// were once left out).
#[test]
fn agent_documentation_covers_every_command() {
    let device = Device::initialized("testbox");
    let schema = device.json_ok(&["schema"]);

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = ["docs/AGENT-INTEGRATION.md", "SKILL.md"]
        .map(|rel| std::fs::read_to_string(root.join(rel)).unwrap())
        .concat();

    let mut undocumented = Vec::new();
    for command in schema["commands"].as_array().unwrap() {
        let name = command["name"].as_str().unwrap();
        if !docs.contains(&format!("akey {name}")) {
            undocumented.push(name.to_string());
        }
    }
    assert!(
        undocumented.is_empty(),
        "these commands are missing from the agent-facing docs: {undocumented:?}"
    );
}

/// FR-3: an agent retries — after a timeout, a crash, a half-read response. Re-running the same
/// `set` must therefore be a no-op, not a second entry, a duplicated field, or a new timestamp.
/// A non-idempotent write turns every retry into corruption.
#[test]
fn set_repeated_with_the_same_value_is_a_no_op() {
    let device = with_entry();
    let before = device.json_ok(&["get", "openai"]);

    for _ in 0..3 {
        device.set_secret("openai", "credential", CANARY);
    }

    let after = device.json_ok(&["get", "openai"]);
    assert_eq!(after["id"], before["id"], "the entry must not be recreated");
    assert_eq!(after["created_at"], before["created_at"]);
    assert_eq!(
        after["updated_at"], before["updated_at"],
        "writing an identical value is not a change"
    );
    assert_eq!(after["fields"], before["fields"], "fields must not accumulate");
    assert_eq!(device.json_ok(&["list"])["count"], 1);
}

/// FR-13: `doctor --json` is what an agent reads to decide whether it may proceed. Its shape is
/// the contract — one record per probe, a status from a closed set, and a human-readable detail.
/// An unparseable or open-ended status is something an agent cannot branch on.
#[test]
fn doctor_json_reports_every_probe_with_a_known_status() {
    let device = with_entry();
    let data = device.json_ok(&["doctor"]);

    let checks = data["checks"]
        .as_array()
        .expect("doctor must report a list of checks");
    assert!(!checks.is_empty(), "a doctor that checks nothing is not a doctor");

    let mut names = Vec::new();
    for check in checks {
        let name = check["name"].as_str().expect("every check needs a name");
        let status = check["status"].as_str().expect("every check needs a status");
        assert!(
            ["ok", "warning", "error"].contains(&status),
            "{name} reports an unknown status {status:?}"
        );
        assert!(check["detail"].is_string(), "{name} must explain itself");
        names.push(name);
    }

    // The probes an agent actually branches on: whether this device can read and write at all,
    // and whether the vault is in a state it must not ignore.
    for required in [
        "identity_permissions",
        "repository",
        "remote",
        "vault",
        "conflicts",
        "tokens",
    ] {
        assert!(
            names.contains(&required),
            "doctor does not report `{required}`; it reported {names:?}"
        );
    }
}

// --------------------------------------------------------------- localization

/// The language moves human text and nothing else.
///
/// `--json` is the machine contract, so it must come out byte-identical in every language: an
/// agent that learned to parse the envelope must not have to re-learn it per locale. Only the
/// prose changes.
#[test]
fn language_changes_human_text_and_leaves_the_json_contract_untouched() {
    let device = with_entry();

    let en = device.stdout(&["--lang", "en", "--help"]);
    let zh = device.stdout(&["--lang", "zh-CN", "--help"]);
    assert!(en.contains("Create an entry"), "english help:\n{en}");
    assert!(zh.contains("新建条目"), "chinese help:\n{zh}");
    assert_ne!(en, zh, "the flag must actually change something");

    let en_json = device.run(&["--lang", "en", "--json", "list"]);
    let zh_json = device.run(&["--lang", "zh-CN", "--json", "list"]);
    assert_eq!(
        en_json.stdout, zh_json.stdout,
        "the JSON envelope must not depend on the language"
    );

    // An explicit language that does not exist is refused rather than silently downgraded.
    let out = device.run(&["--lang", "fr", "list"]);
    assert_eq!(out.status.code(), Some(2), "usage error");
    assert!(!out.stderr.is_empty());
    assert!(out.stdout.is_empty(), "a failing command writes nothing to stdout");
}

/// Hints are localized; the error code they accompany is not.
///
/// Message bodies are still being converted (they are English-only today), so this asserts the
/// hint specifically — the part an agent acts on next.
#[test]
fn error_hints_follow_the_language_while_the_code_stays_stable() {
    let device = with_entry();

    let (code, kind, _) = device.expect_failure(&["get", "ghost"]);
    assert_eq!(code, 3);
    assert_eq!(kind, "not_found", "the machine-readable code is stable");

    let zh = String::from_utf8_lossy(&device.run(&["--lang", "zh-CN", "get", "ghost"]).stderr)
        .to_string();
    assert!(zh.contains("查看可选条目"), "hint not localized:\n{zh}");

    let en = String::from_utf8_lossy(&device.run(&["--lang", "en", "get", "ghost"]).stderr)
        .to_string();
    assert!(en.contains("see available entries"), "english hint:\n{en}");
}

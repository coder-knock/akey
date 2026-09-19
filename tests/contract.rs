//! CLI 契约测试：信封、退出码、stdout/stderr 分离、明文永不外泄。
//!
//! 这些断言来自 `REQUIREMENTS.md` FR-3 / FR-4 与 `DESIGN.md` §10、§12——
//! 它们是**对外契约**，不是实现细节。

mod common;

use common::{Device, bare_remote};

use tempfile::TempDir;

const CANARY: &str = "CANARY-3f9a7b2e";

fn with_entry() -> Device {
    let device = Device::initialized("testbox");
    device.set_secret("openai", "credential", CANARY);
    device
}

// --------------------------------------------------------------- 信封与流分离

#[test]
fn json_success_is_a_single_ok_envelope_on_stdout() {
    let device = with_entry();
    let data = device.json_ok(&["list"]);
    assert!(data["entries"].is_array());

    // stdout 必须是**一个** JSON 文档，且诊断不混进来。
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

// --------------------------------------------------------------- 退出码

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

    // 越权优先于"禁 reveal"：同时命中两者时，报更准确的那个。
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

    // 允许范围内的条目仍然可用。
    let out = device
        .command()
        .env("AKEY_TOKEN", token)
        .args(["--json", "read", "akey://anthropic/credential"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("sk-other"));
}

/// 令牌是只读凭据：作用域不能被写命令绕过。
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

    // 库没被动过。
    assert_eq!(entry_names(&device), vec!["openai".to_string()]);
}

/// 关键回归：作用域必须对注入同样生效，否则 `--allow` 形同虚设。
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

    // 作用域内的条目仍然可以注入。
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

// --------------------------------------------------------------- 明文暴露控制

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

// --------------------------------------------------------------- 注入

#[test]
fn run_injects_a_secret_into_the_child_and_masks_any_echo() {
    let device = with_entry();

    // 1. 子进程确实拿到了明文。
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

    // 2. 子进程回显时被遮蔽，明文不进调用者的 stdout。
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

// --------------------------------------------------------------- 审计与自举

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

// --------------------------------------------------------------- 非交互

#[test]
fn commands_never_block_waiting_for_input() {
    // 所有命令都必须能在没有 TTY、stdin 已关闭的环境下跑完。
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

// --------------------------------------------------------------- 远端存在但不可达

#[test]
fn sync_reports_a_broken_remote_as_sync_failed() {
    let device = Device::blank();
    let remote = TempDir::new().unwrap();
    let url = bare_remote(&remote);
    device.init("testbox", &["--remote", &url]);

    // 把远端抽走，让 fetch 失败。
    std::fs::remove_dir_all(remote.path().join("remote.git")).unwrap();

    let (code, kind, _) = device.expect_failure(&["sync"]);
    assert_eq!(code, 6, "unreachable remote must map to sync_failed");
    assert_eq!(kind, "sync_failed");
}

// --------------------------------------------------------------- 其余命令面
//
// 这一组覆盖的是"只有走真实 CLI 才会暴露"的路径——参数 id 撞车、子命令没接线、
// 错误码映射错位之类的问题，单元测试全都看不见。`--format` 撞车就是这么漏过去的。

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
    // 每个分类都要报出它的默认秘密字段——`set --stdin` 不带字段名时靠它。
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

    // 软删后默认看不见，--all 看得见，restore 能救回来。
    device.json_ok(&["rm", "openai-moved"]);
    assert_eq!(entry_names(&device), vec!["openai"]);
    let all = device.json_ok(&["list", "--all"]);
    assert_eq!(all["entries"].as_array().unwrap().len(), 2);
    device.json_ok(&["restore", "openai-moved"]);
    assert_eq!(entry_names(&device), vec!["openai", "openai-moved"]);

    // --purge 之后彻底消失。
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
    // 值没被动过，且依然隐藏。
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

    // 重名必须挡下来，--merge 才放行。
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

    // 6 条请求里有一条是通知，按 JSON-RPC 不该有回复。
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

    // 安全底线：这个通道永不外泄字段值。
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

    // 新旧分开提供，否则非交互下两次读的是同一个值。
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

/// 面向 agent 的文档不能悄悄落后于 CLI。
///
/// 一个 agent 只会照着文档与 `akey schema` 行动——新命令没写进文档，等于那条命令对它不存在。
/// 这是会真实发生的疏漏（本轮就有 8 条命令一度没被写上）。
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

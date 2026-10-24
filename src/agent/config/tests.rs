use super::*;
use crate::agent::registry;

fn harness(id: &str) -> &'static Harness {
    registry::resolve(id).unwrap()
}

fn plan_for(harness: &Harness, home: &Path, cwd: &Path, force: bool) -> Result<Plan> {
    plan(harness, Scope::User, home, cwd, force)
}

fn install(harness: &Harness, home: &Path, cwd: &Path) -> Plan {
    let plan = plan_for(harness, home, cwd, false).unwrap();
    apply(&plan).unwrap();
    plan
}

/// Write a fixture config, creating its parent directory first.
fn write_config(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, text).unwrap();
}

#[test]
fn first_install_is_idempotent_for_every_harness() {
    for harness in registry::harnesses() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let cwd = temp.path();

        let first = install(harness, home, cwd);
        assert_ne!(
            first.change,
            Change::Unchanged,
            "{} must plan a write",
            harness.id
        );
        assert!(first.creates, "{} must create a file", harness.id);

        let inspection = inspect(harness, Scope::User, home, cwd).unwrap();
        assert_eq!(
            inspection.status,
            EntryStatus::Installed,
            "{} must inspect as installed\n{}",
            harness.id,
            String::from_utf8_lossy(&std::fs::read(&inspection.path).unwrap())
        );

        let second = plan_for(harness, home, cwd, false).unwrap();
        assert_eq!(
            second.change,
            Change::Unchanged,
            "{} must be idempotent",
            harness.id
        );
        assert!(second.contents.is_empty());
    }
}

#[test]
fn install_preserves_unrelated_keys_and_comments() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();

    // Claude: unrelated server plus an unrelated root key.
    std::fs::write(
        home.join(".claude.json"),
        "{
  // keep this comment
  \"theme\": \"dark\",
  \"mcpServers\": {
    \"other\": { \"command\": \"other\" }
  }
}
",
    )
    .unwrap();
    install(harness("claude"), home, temp.path());
    let text = std::fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(text.contains("keep this comment"), "{text}");
    assert!(text.contains("\"theme\""), "{text}");
    assert!(text.contains("\"other\""), "{text}");
    assert!(text.contains("\"akey\""), "{text}");

    // Codex: another server table stays intact.
    write_config(
        &home.join(".codex/config.toml"),
        "[mcp_servers.other]\ncommand = \"other\"\n",
    );
    install(harness("codex"), home, temp.path());
    let text = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(text.contains("[mcp_servers.other]"), "{text}");
    assert!(text.contains("[mcp_servers.akey]"), "{text}");

    // Hermes: unrelated root keys and servers survive.
    write_config(
        &home.join(".hermes/config.yaml"),
        "model: hermes-3\nmcp_servers:\n  other:\n    command: other\n",
    );
    install(harness("hermes"), home, temp.path());
    let text = std::fs::read_to_string(home.join(".hermes/config.yaml")).unwrap();
    assert!(text.contains("model: hermes-3"), "{text}");
    assert!(text.contains("other:"), "{text}");
    assert!(text.contains("akey:"), "{text}");
}

#[test]
fn conflicting_entry_requires_force() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let claude = harness("claude");
    std::fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers":{"akey":{"type":"stdio","command":"other","args":["mcp"]}}}"#,
    )
    .unwrap();

    let err = plan_for(claude, home, temp.path(), false).unwrap_err();
    assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");
    assert!(
        err.to_string().contains("--force"),
        "conflict must point at the fix: {err}"
    );

    let forced = plan_for(claude, home, temp.path(), true).unwrap();
    assert_eq!(forced.change, Change::Replaced);
    assert!(forced.replaced_detail.is_some());
    apply(&forced).unwrap();
    assert_eq!(
        inspect(claude, Scope::User, home, temp.path())
            .unwrap()
            .status,
        EntryStatus::Installed
    );
}

#[test]
fn disabled_or_wrong_type_entries_are_conflicts() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();

    write_config(
        &home.join(".hermes/config.yaml"),
        "mcp_servers:\n  akey:\n    command: akey\n    args: [mcp]\n    enabled: false\n",
    );
    assert!(matches!(
        inspect(harness("hermes"), Scope::User, home, temp.path())
            .unwrap()
            .status,
        EntryStatus::Conflict { .. }
    ));

    write_config(
        &home.join(".config/opencode/opencode.json"),
        r#"{"mcp":{"akey":{"type":"remote","command":["akey","mcp"]}}}"#,
    );
    assert!(matches!(
        inspect(harness("opencode"), Scope::User, home, temp.path())
            .unwrap()
            .status,
        EntryStatus::Conflict { .. }
    ));

    std::fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers":{"akey":{"type":"sse","command":"akey","args":["mcp"]}}}"#,
    )
    .unwrap();
    assert!(matches!(
        inspect(harness("claude"), Scope::User, home, temp.path())
            .unwrap()
            .status,
        EntryStatus::Conflict { .. }
    ));
}

#[test]
fn opencode_accepts_string_command_but_writes_the_array_form() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let oc = harness("opencode");
    write_config(
        &home.join(".config/opencode/opencode.json"),
        r#"{"mcp":{"akey":{"type":"local","command":"akey","args":["mcp"],"enabled":true}}}"#,
    );
    assert_eq!(
        inspect(oc, Scope::User, home, temp.path()).unwrap().status,
        EntryStatus::Installed
    );

    let other = temp.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let plan = plan(oc, Scope::User, &other, temp.path(), false).unwrap();
    let text = String::from_utf8_lossy(&plan.contents);
    assert!(text.contains("\"command\": ["), "{text}");
    assert!(text.contains("$schema"), "{text}");
}

#[test]
fn plain_entries_have_no_type_and_reject_disabled() {
    let configs = [
        ("cursor", ".cursor/mcp.json"),
        ("kiro", ".kiro/settings/mcp.json"),
        ("devin", ".config/devin/mcp_config.json"),
    ];

    for (id, relative) in configs {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let harness = harness(id);

        let plan = install(harness, home, temp.path());
        let text = String::from_utf8_lossy(&plan.contents);
        assert!(text.contains("\"command\": \"akey\""), "{id}: {text}");
        assert!(text.contains("\"args\""), "{id}: {text}");
        assert!(!text.contains("\"type\""), "{id}: {text}");
        assert!(
            !text.contains("\"enabled\"") && !text.contains("\"disabled\""),
            "{id}: {text}"
        );

        // The canonical plain shape is accepted with an explicit `stdio` type as well.
        write_config(
            &home.join(relative),
            r#"{"mcpServers":{"akey":{"type":"stdio","command":"akey","args":["mcp"]}}}"#,
        );
        assert_eq!(
            inspect(harness, Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Installed,
            "{id}"
        );

        // A remote transport must not be mistaken for the stdio entry akey installs.
        write_config(
            &home.join(relative),
            r#"{"mcpServers":{"akey":{"type":"sse","command":"akey","args":["mcp"]}}}"#,
        );
        assert!(matches!(
            inspect(harness, Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Conflict { .. }
        ));

        // `disabled: true` means the entry exists but never runs.
        write_config(
            &home.join(relative),
            r#"{"mcpServers":{"akey":{"command":"akey","args":["mcp"],"disabled":true}}}"#,
        );
        let err = plan_for(harness, home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{id}: {err:?}");
        assert!(err.to_string().contains("disabled"), "{id}: {err}");

        let forced = plan_for(harness, home, temp.path(), true).unwrap();
        assert_eq!(forced.change, Change::Replaced, "{id}");
        apply(&forced).unwrap();
        let text = std::fs::read_to_string(home.join(relative)).unwrap();
        assert!(!text.contains("disabled"), "{id}: {text}");
        assert_eq!(
            inspect(harness, Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Installed,
            "{id}"
        );
    }
}

#[test]
fn malformed_config_is_reported_and_never_overwritten() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    std::fs::write(home.join(".claude.json"), "{ not json").unwrap();

    let status = inspect(harness("claude"), Scope::User, home, temp.path())
        .unwrap()
        .status;
    assert!(
        matches!(status, EntryStatus::Unreadable { .. }),
        "{status:?}"
    );

    let err = plan_for(harness("claude"), home, temp.path(), true).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(home.join(".claude.json")).unwrap(),
        "{ not json"
    );
}

#[test]
fn wrong_container_shape_is_not_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    std::fs::write(home.join(".claude.json"), r#"{"mcpServers":[]}"#).unwrap();
    let err = plan_for(harness("claude"), home, temp.path(), true).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(home.join(".claude.json")).unwrap(),
        r#"{"mcpServers":[]}"#
    );
}

#[test]
fn snippets_reinspect_as_installed() {
    // The fragment printed by `akey agent print` must be exactly the fragment a fresh
    // install writes; otherwise copy-paste and `install` would disagree.
    for harness in registry::harnesses() {
        let snippet = snippet(harness).unwrap();
        assert!(!snippet.trim().is_empty(), "{}", harness.id);

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let plan = plan_for(harness, home, temp.path(), false).unwrap();
        assert_eq!(
            snippet,
            String::from_utf8_lossy(&plan.contents),
            "{} snippet drifted from its install",
            harness.id
        );
    }
}

fn remove_for(harness: &Harness, home: &Path, cwd: &Path, force: bool) -> Result<RemovePlan> {
    plan_remove(harness, Scope::User, home, cwd, force)
}

#[test]
fn uninstall_removes_only_the_akey_entry_for_every_harness() {
    for harness in registry::harnesses() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        install(harness, home, temp.path());

        let plan = remove_for(harness, home, temp.path(), false).unwrap();
        assert_eq!(
            plan.change,
            RemoveChange::Removed,
            "{} must plan a removal",
            harness.id
        );
        apply_remove(&plan).unwrap();

        assert!(
            plan.path.is_file(),
            "{} uninstall must keep the config file",
            harness.id
        );
        assert_eq!(
            inspect(harness, Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Missing,
            "{} must inspect as missing\n{}",
            harness.id,
            std::fs::read_to_string(&plan.path).unwrap()
        );

        // Uninstall is idempotent: a second pass is a no-op and drops no bytes.
        let again = remove_for(harness, home, temp.path(), false).unwrap();
        assert_eq!(again.change, RemoveChange::Missing, "{}", harness.id);
        assert!(again.contents.is_empty(), "{}", harness.id);
    }
}

#[test]
fn uninstall_preserves_unrelated_settings() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();

    std::fs::write(
            home.join(".claude.json"),
            "{\n  // keep this comment\n  \"theme\": \"dark\",\n  \"mcpServers\": {\n    \"other\": { \"command\": \"other\" }\n  }\n}\n",
        )
        .unwrap();
    install(harness("claude"), home, temp.path());
    let plan = remove_for(harness("claude"), home, temp.path(), false).unwrap();
    apply_remove(&plan).unwrap();
    let text = std::fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(text.contains("keep this comment"), "{text}");
    assert!(text.contains("\"theme\""), "{text}");
    assert!(text.contains("\"other\""), "{text}");
    assert!(!text.contains("\"akey\""), "{text}");

    write_config(
        &home.join(".codex/config.toml"),
        "# keep this comment\n[mcp_servers.other]\ncommand = \"other\"\n",
    );
    install(harness("codex"), home, temp.path());
    let plan = remove_for(harness("codex"), home, temp.path(), false).unwrap();
    apply_remove(&plan).unwrap();
    let text = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(text.contains("keep this comment"), "{text}");
    assert!(text.contains("[mcp_servers.other]"), "{text}");
    assert!(!text.contains("[mcp_servers.akey]"), "{text}");

    write_config(
        &home.join(".hermes/config.yaml"),
        "model: hermes-3\nmcp_servers:\n  other:\n    command: other\n",
    );
    install(harness("hermes"), home, temp.path());
    let plan = remove_for(harness("hermes"), home, temp.path(), false).unwrap();
    apply_remove(&plan).unwrap();
    let text = std::fs::read_to_string(home.join(".hermes/config.yaml")).unwrap();
    assert!(text.contains("model: hermes-3"), "{text}");
    assert!(text.contains("other:"), "{text}");
    assert!(!text.contains("akey:"), "{text}");

    write_config(
        &home.join(".config/opencode/opencode.json"),
        r#"{"$schema":"https://opencode.ai/config.json","mcp":{"other":{"type":"local","command":["other"]}}}"#,
    );
    install(harness("opencode"), home, temp.path());
    let plan = remove_for(harness("opencode"), home, temp.path(), false).unwrap();
    apply_remove(&plan).unwrap();
    let text = std::fs::read_to_string(home.join(".config/opencode/opencode.json")).unwrap();
    assert!(text.contains("$schema"), "{text}");
    assert!(text.contains("\"other\""), "{text}");
    assert!(!text.contains("\"akey\""), "{text}");

    write_config(
        &home.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"other":{"command":"other","args":[]}}}"#,
    );
    install(harness("cursor"), home, temp.path());
    let plan = remove_for(harness("cursor"), home, temp.path(), false).unwrap();
    apply_remove(&plan).unwrap();
    let text = std::fs::read_to_string(home.join(".cursor/mcp.json")).unwrap();
    assert!(text.contains("\"other\""), "{text}");
    assert!(!text.contains("\"akey\""), "{text}");
}

#[test]
fn uninstall_tolerates_a_missing_file() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let plan = remove_for(harness("claude"), home, temp.path(), false).unwrap();
    assert_eq!(plan.change, RemoveChange::Missing);
    apply_remove(&plan).unwrap();
    assert!(!home.join(".claude.json").exists());
}

#[test]
fn uninstall_requires_force_for_a_different_entry_and_force_removes_it() {
    let fixtures = [
        (
            "claude",
            ".claude.json",
            r#"{"mcpServers":{"akey":{"type":"stdio","command":"other","args":["mcp"]}}}"#,
        ),
        (
            "codex",
            ".codex/config.toml",
            "[mcp_servers.akey]\ncommand = \"other\"\n",
        ),
        (
            "hermes",
            ".hermes/config.yaml",
            "mcp_servers:\n  akey:\n    command: other\n    args: [mcp]\n",
        ),
        (
            "opencode",
            ".config/opencode/opencode.json",
            r#"{"mcp":{"akey":{"type":"local","command":["other","mcp"]}}}"#,
        ),
        (
            "cursor",
            ".cursor/mcp.json",
            r#"{"mcpServers":{"akey":{"command":"other","args":["mcp"]}}}"#,
        ),
        (
            "kiro",
            ".kiro/settings/mcp.json",
            r#"{"mcpServers":{"akey":{"command":"other","args":["mcp"]}}}"#,
        ),
        (
            "devin",
            ".config/devin/mcp_config.json",
            r#"{"mcpServers":{"akey":{"command":"other","args":["mcp"]}}}"#,
        ),
    ];

    for (id, relative, text) in fixtures {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        write_config(&home.join(relative), text);
        let harness = harness(id);

        let err = remove_for(harness, home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{id}: {err:?}");
        assert!(err.to_string().contains("--force"), "{id}: {err}");
        assert_eq!(
            std::fs::read_to_string(home.join(relative)).unwrap(),
            text,
            "{id} must be untouched without --force"
        );

        let forced = remove_for(harness, home, temp.path(), true).unwrap();
        assert_eq!(forced.change, RemoveChange::Removed, "{id}");
        assert!(forced.removed_detail.is_some(), "{id}");
        apply_remove(&forced).unwrap();
        assert_eq!(
            inspect(harness, Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Missing,
            "{id}"
        );
    }
}

#[test]
fn uninstall_force_removes_a_non_server_value() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();

    std::fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers":{"akey":7},"theme":"dark"}"#,
    )
    .unwrap();
    let err = remove_for(harness("claude"), home, temp.path(), false).unwrap_err();
    assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");
    let forced = remove_for(harness("claude"), home, temp.path(), true).unwrap();
    apply_remove(&forced).unwrap();
    let text = std::fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(!text.contains("\"akey\""), "{text}");
    assert!(text.contains("theme"), "{text}");

    write_config(
        &home.join(".codex/config.toml"),
        "[mcp_servers]\nakey = 7\n",
    );
    assert!(matches!(
        remove_for(harness("codex"), home, temp.path(), false).unwrap_err(),
        Error::AgentConflict(_)
    ));
    let forced = remove_for(harness("codex"), home, temp.path(), true).unwrap();
    apply_remove(&forced).unwrap();
    let text = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(!text.contains("akey"), "{text}");

    write_config(
        &home.join(".hermes/config.yaml"),
        "mcp_servers:\n  akey: 7\n",
    );
    assert!(matches!(
        remove_for(harness("hermes"), home, temp.path(), false).unwrap_err(),
        Error::AgentConflict(_)
    ));
    let forced = remove_for(harness("hermes"), home, temp.path(), true).unwrap();
    apply_remove(&forced).unwrap();
    let text = std::fs::read_to_string(home.join(".hermes/config.yaml")).unwrap();
    assert!(!text.contains("akey"), "{text}");
}

#[test]
fn uninstall_never_rewrites_a_malformed_file() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    std::fs::write(home.join(".claude.json"), "{ not json").unwrap();

    let err = remove_for(harness("claude"), home, temp.path(), true).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(home.join(".claude.json")).unwrap(),
        "{ not json"
    );
}

#[test]
fn project_scope_uses_the_project_config() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let cwd = temp.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();

    let claude = harness("claude");
    let plan = plan(claude, Scope::Project, &home, &cwd, false).unwrap();
    assert_eq!(plan.path, cwd.join(".mcp.json"));
    assert_eq!(plan.mode, PROJECT_FILE_MODE);
    apply(&plan).unwrap();
    assert!(cwd.join(".mcp.json").is_file());
    assert!(!home.join(".claude.json").exists());
}

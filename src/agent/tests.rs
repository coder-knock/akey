//! Tests for harness selection and the install/uninstall/inspect lifecycle.

use std::path::{Path, PathBuf};

use super::selection::scoped;
use super::*;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_string()).collect()
}

fn request<'a>(
    selection: &'a Selection,
    scope: Scope,
    only: Only,
    home: &'a Path,
    cwd: &'a Path,
    native: NativeMode<'a>,
) -> InstallRequest<'a> {
    InstallRequest {
        selection,
        scope,
        only,
        force: false,
        dry_run: false,
        native,
        home,
        cwd,
    }
}

#[test]
fn an_empty_name_list_selects_every_harness_in_registry_order() {
    let selection = select(&[]).unwrap();
    assert!(!selection.explicit());
    assert_eq!(
        selection
            .harnesses()
            .iter()
            .map(|harness| harness.id)
            .collect::<Vec<_>>(),
        vec![
            "claude-code",
            "codex",
            "cursor",
            "hermes",
            "opencode",
            "kiro",
            "devin"
        ]
    );
}

#[test]
fn explicit_names_are_ordered_and_deduplicated() {
    let selection = select(&names(&["opencode", "claude", "OpenCode"])).unwrap();
    assert!(selection.explicit());
    assert_eq!(
        selection
            .harnesses()
            .iter()
            .map(|harness| harness.id)
            .collect::<Vec<_>>(),
        vec!["claude-code", "opencode"]
    );
    assert_eq!(
        select(&names(&["nope"]))
            .err()
            .expect("unknown agent must fail")
            .code(),
        "usage"
    );
}

#[test]
fn a_default_selection_skips_harnesses_without_the_scope() {
    let temp = tempfile::tempdir().unwrap();
    let selection = select(&[]).unwrap();
    let targets = scoped(
        &selection,
        Scope::Project,
        Only::All,
        temp.path(),
        temp.path(),
    )
    .unwrap();
    assert_eq!(
        targets.iter().map(|harness| harness.id).collect::<Vec<_>>(),
        vec!["claude-code", "cursor", "opencode", "kiro", "devin"]
    );
}

#[test]
fn an_explicit_selection_errors_on_a_missing_scope() {
    let temp = tempfile::tempdir().unwrap();
    let selection = select(&names(&["codex"])).unwrap();
    let error = scoped(
        &selection,
        Scope::Project,
        Only::All,
        temp.path(),
        temp.path(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "usage");
    assert!(error.to_string().contains("Codex"), "{error}");
}

#[test]
fn status_reports_every_harness_and_never_fails_on_missing_files() {
    let temp = tempfile::tempdir().unwrap();
    let selection = select(&[]).unwrap();
    let report = status(&StatusRequest {
        selection: &selection,
        scope: Scope::User,
        only: Only::All,
        native: NativeMode::Disabled,
        home: temp.path(),
        cwd: temp.path(),
    })
    .unwrap();

    assert!(!report.ready);
    assert_eq!(report.harnesses.len(), 7);
    for row in &report.harnesses {
        assert_eq!(row.mcp.as_ref().unwrap().status, "missing");
        assert_eq!(row.skill.as_ref().unwrap().status, "missing");
        assert!(!row.native.found);
    }
}

#[test]
fn list_reports_shared_skill_roots() {
    let report = list();
    let codex = report
        .harnesses
        .iter()
        .find(|harness| harness.id == "codex")
        .unwrap();
    assert_eq!(codex.user_skill_shared_with, vec!["opencode"]);
    let claude = report
        .harnesses
        .iter()
        .find(|harness| harness.id == "claude-code")
        .unwrap();
    assert!(claude.user_skill_shared_with.is_empty());
    assert_eq!(claude.scopes, vec!["user", "project"]);
}

#[test]
fn installing_twice_changes_nothing_the_second_time() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["claude", "hermes"])).unwrap();

    let first = install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();
    assert!(first.changed);
    assert_eq!(first.harnesses[0].mcp.as_ref().unwrap().change, "added");
    assert_eq!(
        first.harnesses[0].skill.as_ref().unwrap().change,
        "installed"
    );

    let second = install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();
    assert!(!second.changed);
    for row in &second.harnesses {
        assert_eq!(row.written, 0);
        assert_eq!(row.mcp.as_ref().unwrap().change, "unchanged");
        assert_eq!(row.skill.as_ref().unwrap().change, "unchanged");
    }
}

#[test]
fn a_shared_skill_is_counted_once_in_the_install_total() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["codex", "opencode"])).unwrap();

    let report = install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();

    // Codex config + shared SKILL.md + sidecar + OpenCode config. Both per-harness rows
    // claim the shared skill, but the total must report real files.
    assert_eq!(report.written, 4);
    assert_eq!(
        report
            .harnesses
            .iter()
            .map(|row| row.written)
            .sum::<usize>(),
        6
    );
    assert!(home.join(".agents/skills/akey/SKILL.md").is_file());
}

#[test]
fn a_conflict_on_any_harness_stops_the_whole_install() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.akey]\ncommand = \"other\"\n",
    )
    .unwrap();

    let selection = select(&names(&["claude", "codex"])).unwrap();
    let error = install(&request(
        &selection,
        Scope::User,
        Only::Mcp,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap_err();
    assert_eq!(error.code(), "conflict");
    assert!(error.to_string().contains("--force"), "{error}");
    // Claude was planned first but must not have been written.
    assert!(!home.join(".claude.json").exists());
}

#[test]
fn force_replaces_a_conflicting_entry_through_the_config() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.akey]\ncommand = \"other\"\n",
    )
    .unwrap();

    let selection = select(&names(&["codex"])).unwrap();
    let mut install_request = request(
        &selection,
        Scope::User,
        Only::Mcp,
        home,
        temp.path(),
        NativeMode::Disabled,
    );
    install_request.force = true;
    let report = install(&install_request).unwrap();
    assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().change, "replaced");
    assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().via, "config");
    let written = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(written.contains("command = \"akey\""), "{written}");
}

#[test]
fn a_dry_run_plans_without_writing() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["claude"])).unwrap();
    let mut install_request = request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    );
    install_request.dry_run = true;
    let report = install(&install_request).unwrap();
    assert!(report.changed);
    assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().change, "added");
    assert!(!home.join(".claude.json").exists());
    assert!(!home.join(".claude/skills/akey/SKILL.md").exists());
    assert!(report.render(home).contains("dry run"));
}

fn uninstall_request<'a>(
    selection: &'a Selection,
    scope: Scope,
    only: Only,
    home: &'a Path,
    cwd: &'a Path,
) -> UninstallRequest<'a> {
    UninstallRequest {
        selection,
        scope,
        only,
        force: false,
        dry_run: false,
        home,
        cwd,
    }
}

#[test]
fn uninstall_removes_everything_install_wrote_and_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["claude", "codex"])).unwrap();
    install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();

    let report = uninstall(&uninstall_request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
    ))
    .unwrap();
    assert!(report.changed);
    assert_eq!(report.removed, 6, "two configs + two skills + two sidecars");
    assert!(home.join(".claude.json").is_file());
    assert!(home.join(".codex/config.toml").is_file());
    assert!(!home.join(".claude/skills/akey").exists());
    assert!(!home.join(".agents/skills/akey").exists());
    for row in &report.harnesses {
        assert_eq!(row.removed, 3, "{}", row.id);
        assert_eq!(row.mcp.as_ref().unwrap().change, "removed");
        assert_eq!(row.skill.as_ref().unwrap().change, "removed");
    }

    let again = uninstall(&uninstall_request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
    ))
    .unwrap();
    assert!(!again.changed);
    assert_eq!(again.removed, 0);
    assert!(again.render(home).contains("nothing to do"));
}

#[test]
fn uninstall_deduplicates_a_shared_skill_and_warns_about_it() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["codex", "opencode"])).unwrap();
    install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();

    let report = uninstall(&uninstall_request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
    ))
    .unwrap();
    assert_eq!(report.removed, 4, "two configs + one shared skill pair");
    assert_eq!(
        report
            .harnesses
            .iter()
            .map(|row| row.removed)
            .sum::<usize>(),
        6
    );
    let codex = report
        .harnesses
        .iter()
        .find(|row| row.id == "codex")
        .unwrap();
    assert_eq!(codex.skill.as_ref().unwrap().shared_with, vec!["opencode"]);

    let rendered = report.render(home);
    assert!(rendered.contains("shared with OpenCode"), "{rendered}");
    assert!(
        rendered.contains("the skill is removed for them too"),
        "{rendered}"
    );

    // On a rerun nothing is removed, so the shared-skill warning must not fire: it
    // would claim an impact that already happened.
    let again = uninstall(&uninstall_request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
    ))
    .unwrap();
    assert!(!again.changed);
    for row in &again.harnesses {
        assert!(
            row.skill.as_ref().unwrap().shared_with.is_empty(),
            "{}",
            row.id
        );
    }
    assert!(
        !again.render(home).contains("shared with"),
        "{}",
        again.render(home)
    );
}

#[test]
fn a_conflict_on_any_harness_stops_the_whole_uninstall() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["claude", "codex"])).unwrap();
    install(&request(
        &selection,
        Scope::User,
        Only::Mcp,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();
    std::fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.akey]\ncommand = \"other\"\n",
    )
    .unwrap();

    let error = uninstall(&uninstall_request(
        &selection,
        Scope::User,
        Only::Mcp,
        home,
        temp.path(),
    ))
    .unwrap_err();
    assert_eq!(error.code(), "conflict");
    // Claude was planned first but must not have been touched.
    let claude = std::fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(claude.contains("\"akey\""), "{claude}");

    let mut forced = uninstall_request(&selection, Scope::User, Only::Mcp, home, temp.path());
    forced.force = true;
    let report = uninstall(&forced).unwrap();
    assert_eq!(report.removed, 2);
    let claude = std::fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(!claude.contains("\"akey\""), "{claude}");
}

#[test]
fn uninstall_dry_run_deletes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["claude"])).unwrap();
    install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();

    let mut uninstall_request =
        uninstall_request(&selection, Scope::User, Only::All, home, temp.path());
    uninstall_request.dry_run = true;
    let report = uninstall(&uninstall_request).unwrap();
    assert!(report.changed);
    assert_eq!(report.removed, 3);
    assert!(home.join(".claude.json").is_file());
    assert!(home.join(".claude/skills/akey/SKILL.md").is_file());
    let rendered = report.render(home);
    assert!(rendered.contains("dry run"), "{rendered}");
    assert!(rendered.contains("would remove 3 file(s)"), "{rendered}");
}

#[test]
fn uninstall_can_remove_one_layer() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["claude"])).unwrap();
    install(&request(
        &selection,
        Scope::User,
        Only::All,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();

    let report = uninstall(&uninstall_request(
        &selection,
        Scope::User,
        Only::Mcp,
        home,
        temp.path(),
    ))
    .unwrap();
    assert_eq!(report.removed, 1);
    assert!(report.harnesses[0].skill.is_none());
    assert!(home.join(".claude/skills/akey/SKILL.md").is_file());
    let config = std::fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(!config.contains("\"akey\""), "{config}");
}

#[test]
fn printed_snippets_are_byte_identical_to_a_fresh_install() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let selection = select(&names(&["opencode"])).unwrap();

    install(&request(
        &selection,
        Scope::User,
        Only::Mcp,
        home,
        temp.path(),
        NativeMode::Disabled,
    ))
    .unwrap();
    let installed = std::fs::read_to_string(home.join(".config/opencode/opencode.json")).unwrap();

    let printed = print(&PrintRequest {
        selection: &selection,
        scope: Scope::User,
        only: Only::Mcp,
        home,
        cwd: temp.path(),
    })
    .unwrap();
    assert_eq!(
        printed.harnesses[0].mcp.as_ref().unwrap().snippet,
        installed
    );
    assert!(
        installed.contains("\"$schema\""),
        "a fresh OpenCode config carries its schema: {installed}"
    );
}

#[test]
fn print_shares_one_skill_document_between_harnesses() {
    let temp = tempfile::tempdir().unwrap();
    let selection = select(&names(&["codex", "opencode"])).unwrap();
    let report = print(&PrintRequest {
        selection: &selection,
        scope: Scope::User,
        only: Only::Skill,
        home: temp.path(),
        cwd: temp.path(),
    })
    .unwrap();
    let rendered = report.render(temp.path());
    assert_eq!(
        rendered.matches("# akey").count(),
        1,
        "the shared skill body must be printed once:\n{rendered}"
    );
    assert!(rendered.contains("Codex, OpenCode"), "{rendered}");
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[test]
    fn a_harness_cli_is_preferred_when_it_can_write_the_entry() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let target = home.join(".claude.json");
        script(
            &bin,
            "claude",
            &format!(
                "#!/bin/sh\nprintf 'added to stderr\\n' >&2\ncat > '{}' <<'JSON'\n{{\"mcpServers\":{{\"akey\":{{\"command\":\"akey\",\"args\":[\"mcp\"]}}}}}}\nJSON\n",
                target.display()
            ),
        );

        let selection = select(&names(&["claude"])).unwrap();
        let report = install(&request(
            &selection,
            Scope::User,
            Only::Mcp,
            &home,
            temp.path(),
            NativeMode::Path(bin.as_os_str()),
        ))
        .unwrap();

        let mcp = report.harnesses[0].mcp.as_ref().unwrap();
        assert_eq!(mcp.via, "native");
        assert_eq!(mcp.change, "added");
        assert!(target.is_file());
    }

    #[test]
    fn a_failing_harness_cli_is_a_harness_error_and_writes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        script(&bin, "claude", "#!/bin/sh\necho 'nope' >&2\nexit 3\n");

        let selection = select(&names(&["claude"])).unwrap();
        let error = install(&request(
            &selection,
            Scope::User,
            Only::Mcp,
            &home,
            temp.path(),
            NativeMode::Path(bin.as_os_str()),
        ))
        .unwrap_err();

        assert_eq!(error.code(), "harness");
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains("nope"), "{error}");
        assert!(!home.join(".claude.json").exists());
    }

    #[test]
    fn a_harness_cli_that_writes_nothing_is_not_believed() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        script(&bin, "claude", "#!/bin/sh\nexit 0\n");

        let selection = select(&names(&["claude"])).unwrap();
        let error = install(&request(
            &selection,
            Scope::User,
            Only::Mcp,
            &home,
            temp.path(),
            NativeMode::Path(bin.as_os_str()),
        ))
        .unwrap_err();

        assert_eq!(error.code(), "harness");
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("--no-native")),
            "the hint must point at the recovery path: {error}"
        );
    }

    #[test]
    fn the_native_cli_is_not_used_to_replace_an_entry() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let marker = temp.path().join("called");
        script(
            &bin,
            "claude",
            &format!("#!/bin/sh\n touch '{}'\n", marker.display()),
        );
        std::fs::write(
            home.join(".claude.json"),
            "{\"mcpServers\":{\"akey\":{\"command\":\"other\"}}}\n",
        )
        .unwrap();

        let selection = select(&names(&["claude"])).unwrap();
        let mut install_request = request(
            &selection,
            Scope::User,
            Only::Mcp,
            &home,
            temp.path(),
            NativeMode::Path(bin.as_os_str()),
        );
        install_request.force = true;
        let report = install(&install_request).unwrap();

        assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().via, "config");
        assert!(!marker.exists(), "the harness CLI must not be invoked");
    }
}

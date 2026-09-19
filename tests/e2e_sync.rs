//! 端到端：两台"机器"（两个临时 HOME）通过一个本地裸仓库同步。
//!
//! 全部离线。覆盖 `REQUIREMENTS.md` 的 S4/S5/S6 与 FR-8/FR-9/FR-10。

mod common;

use common::{Device, bare_remote};
use tempfile::TempDir;

const PASS: &str = "shared-recovery-passphrase";

struct Pair {
    alpha: Device,
    beta: Device,
    _remote: TempDir,
}

/// 起一对已互相认识、共享一个远端的设备。
fn pair() -> Pair {
    let remote = TempDir::new().unwrap();
    let url = bare_remote(&remote);

    let alpha = Device::blank();
    alpha.init("alpha", &["--remote", &url]);
    alpha.enable_recovery(PASS);
    alpha.run_ok_with_env(&["sync"], &[]);

    let beta = Device::blank();
    beta.join(&url, "beta", PASS);

    // alpha 拉回 beta 的设备登记。
    alpha.run_ok_with_env(&["sync"], &[]);

    Pair {
        alpha,
        beta,
        _remote: remote,
    }
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

#[test]
fn a_second_device_reads_what_the_first_stored() {
    let pair = pair();
    pair.alpha.set_secret("openai", "credential", "sk-alpha-canary");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    pair.beta.run_ok_with_env(&["sync"], &[]);

    assert_eq!(entry_names(&pair.beta), vec!["openai".to_string()]);
    // 关键：beta 拿到的是可用明文，而不是一份打不开的密文。
    let value = pair.beta.stdout(&["read", "akey://openai/credential"]);
    assert!(value.contains("sk-alpha-canary"));
}

#[test]
fn a_second_sync_with_nothing_to_do_reports_up_to_date() {
    let pair = pair();
    let data = pair.beta.json_ok(&["sync"]);
    assert_eq!(data["outcome"], "up_to_date");
}

#[test]
fn edits_to_different_entries_merge_without_conflict() {
    let pair = pair();
    // 关键：beta **不要**先拉取。它停在 S0，alpha 推到 S1，beta 再在 S0 之上提交，
    // 这才形成真正的分叉（共同祖先 S0）。若 beta 先拉，它就只是"领先"，走的是纯 push 路径。
    pair.alpha.set_secret("alpha-key", "credential", "from-alpha");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    pair.beta.set_secret("beta-key", "credential", "from-beta");

    let data = pair.beta.json_ok(&["sync"]);
    assert_eq!(data["outcome"], "merged");
    assert_eq!(data["conflicts"].as_array().unwrap().len(), 0);

    assert_eq!(
        entry_names(&pair.beta),
        vec!["alpha-key".to_string(), "beta-key".to_string()]
    );

    // alpha 也要能看到 beta 的那条。
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    assert_eq!(
        entry_names(&pair.alpha),
        vec!["alpha-key".to_string(), "beta-key".to_string()]
    );
}

#[test]
fn conflicting_edits_keep_both_sides_and_are_resolvable() {
    let pair = pair();
    pair.alpha.set_secret("shared", "credential", "base-value");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    pair.beta.run_ok_with_env(&["sync"], &[]);

    // 两台设备离线各改同一个条目。
    pair.alpha.set_secret("shared", "credential", "alpha-wins");
    pair.beta.set_secret("shared", "credential", "beta-loses");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    // beta 同步 → 合并已提交并推送，但退出码 5 明确要求人来看一眼。
    let (code, kind, stdout) = pair.beta.expect_failure(&["sync"]);
    assert_eq!(code, 5, "conflicts must be surfaced with a distinct exit code");
    assert_eq!(kind, "conflict");
    assert!(stdout.trim().is_empty(), "a failing command must not write stdout");

    // 两边的值都还在：原条目 + 一个冲突副本。
    let names = entry_names(&pair.beta);
    assert_eq!(names.len(), 2, "both sides must survive: {names:?}");
    assert!(names.iter().any(|n| n == "shared"));
    assert!(
        names.iter().any(|n| n.starts_with("shared.conflict.")),
        "expected a conflict copy, got {names:?}"
    );

    // 冲突清单可读。
    let conflicts = pair.beta.json_ok(&["conflicts"]);
    assert_eq!(conflicts["conflicts"].as_array().unwrap().len(), 1);

    // 挑一边，然后收敛。
    pair.beta.run_ok_with_env(&["resolve", "shared", "--theirs"], &[]);
    assert_eq!(entry_names(&pair.beta), vec!["shared".to_string()]);
    assert!(
        pair.beta
            .stdout(&["read", "akey://shared/credential"])
            .contains("alpha-wins"),
        "resolve --theirs should adopt the remote side"
    );

    pair.beta.run_ok_with_env(&["sync"], &[]);
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    assert!(
        pair.alpha
            .stdout(&["read", "akey://shared/credential"])
            .contains("alpha-wins")
    );
    assert_eq!(entry_names(&pair.alpha), vec!["shared".to_string()]);
}

#[test]
fn repeated_syncs_do_not_multiply_conflict_copies() {
    // 冲突副本的 ID 必须可复现，否则每轮同步都会再生一个副本，永不收敛。
    let pair = pair();
    pair.alpha.set_secret("shared", "credential", "base-value");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    pair.beta.run_ok_with_env(&["sync"], &[]);

    pair.alpha.set_secret("shared", "credential", "alpha-wins");
    pair.beta.set_secret("shared", "credential", "beta-loses");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    let _ = pair.beta.expect_failure(&["sync"]);
    let after_first = entry_names(&pair.beta);
    assert_eq!(after_first.len(), 2);

    // 再来几轮双向同步，副本数量不许增长。
    for _ in 0..3 {
        pair.alpha.run_ok_with_env(&["sync"], &[]);
        let _ = pair.beta.run(&["sync"]);
    }
    assert_eq!(
        entry_names(&pair.beta),
        after_first,
        "conflict copies must be stable across repeated syncs"
    );
}

#[test]
fn a_revoked_device_can_no_longer_open_the_vault() {
    let pair = pair();
    pair.alpha.set_secret("openai", "credential", "sk-secret");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    pair.beta.run_ok_with_env(&["sync"], &[]);
    assert!(pair.beta.stdout(&["read", "akey://openai/credential"]).contains("sk-secret"));

    // alpha 把 beta 踢出去并重新加密。
    pair.alpha.run_ok_with_env(&["devices", "rm", "beta"], &[]);

    // beta 现在既同步不了也读不了。
    let out = pair.beta.run(&["sync"]);
    assert!(!out.status.success(), "revoked device must not sync cleanly");

    let (code, _, _) = pair.beta.expect_failure(&["list"]);
    assert_eq!(code, 4, "revoked device must be locked out");

    // alpha 自己不受影响。
    assert!(pair.alpha.stdout(&["read", "akey://openai/credential"]).contains("sk-secret"));
}

#[test]
fn devices_rm_refuses_to_lock_out_the_current_machine() {
    let pair = pair();
    let (code, kind, _) = pair.alpha.expect_failure(&["devices", "rm", "alpha"]);
    assert_eq!(code, 2);
    assert_eq!(kind, "usage");
}

/// 吊销必须扛得住**快进路径**，而不只是扛得住分叉合并。
///
/// `merge_recipients` 的"吊销优先"只在分叉时跑得到。曾经快进分支用 `reset --hard`
/// 把工作区（含 `recipients.json`）整体换成远端版本，于是：一个被 `devices rm` 掉、
/// 但仍有 git 写权限的设备，只要推一个把自己加回去的**普通提交**，下一台设备的
/// 快进同步就会把本地那份带吊销标记的清单覆盖掉——吊销当场被逆转，它随即又能读到
/// 后续写入的全部明文。实测可复现。
#[test]
fn revocation_survives_a_fast_forward() {
    let pair = pair();
    pair.alpha.set_secret("openai", "credential", "sk-before-revoke");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    pair.beta.run_ok_with_env(&["sync"], &[]);
    assert!(pair.beta.stdout(&["read", "akey://openai/credential"]).contains("sk-before-revoke"));

    pair.alpha.run_ok_with_env(&["devices", "rm", "beta"], &[]);

    // beta 落后于远端：先快进，再把自己从 revoked 改回活跃，然后普通推送。
    let repo = pair.beta.repo();
    for args in [
        vec!["fetch", "--quiet", "origin"],
        vec!["reset", "--hard", "origin/main"],
    ] {
        assert!(git(&repo, &args).status.success(), "test setup: git {args:?}");
    }
    let path = repo.join("recipients.json");
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for (_, record) in file["recipients"].as_object_mut().unwrap() {
        if record["name"] == "beta" {
            record.as_object_mut().unwrap().remove("revoked_at");
        }
    }
    std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
    assert!(git(&repo, &["add", "-A"]).status.success());
    assert!(
        git(&repo, &["-c", "user.name=beta", "-c", "user.email=b@x.y", "commit", "-q", "-m", "rejoin"])
            .status
            .success()
    );
    assert!(
        git(&repo, &["push", "--quiet", "origin", "HEAD"]).status.success(),
        "a device with git write access can always push"
    );

    // alpha 的快进同步不得采纳这份被篡改的收件人清单。
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    let recipients: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pair.alpha.repo().join("recipients.json")).unwrap())
            .unwrap();
    let beta_active = recipients["recipients"]
        .as_object()
        .unwrap()
        .values()
        .any(|r| r["name"] == "beta" && r.get("revoked_at").is_none());
    assert!(!beta_active, "the revocation must not be undone by a fast-forward");

    // 而且它真的读不到后续写入的内容。
    pair.alpha.set_secret("openai", "credential", "sk-after-revoke");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    let _ = git(&repo, &["fetch", "--quiet", "origin"]);
    let _ = git(&repo, &["reset", "--hard", "origin/main"]);
    let (code, _, _) = pair.beta.expect_failure(&["read", "akey://openai/credential"]);
    assert_eq!(code, 4, "a revoked device must stay locked out");
}

/// 在指定仓库里跑一条 git 命令（测试用；与产品代码无关）。
fn git(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .unwrap()
}

#[test]
fn a_wrong_recovery_passphrase_cannot_join() {
    let remote = TempDir::new().unwrap();
    let url = bare_remote(&remote);
    let alpha = Device::blank();
    alpha.init("alpha", &["--remote", &url]);
    alpha.enable_recovery(PASS);
    alpha.run_ok_with_env(&["sync"], &[]);

    let stranger = Device::blank();
    let out = stranger.run_with_env(
        &["init", "--from", &url, "--device", "intruder"],
        &[("AKEY_RECOVERY_PASSPHRASE", "not-the-passphrase")],
    );
    assert_eq!(
        out.status.code(),
        Some(4),
        "a wrong passphrase must be a locked error, not a partial join"
    );
    // 没有留下半成品身份。
    assert!(!stranger.home_path().join("identity.key").is_file());
}

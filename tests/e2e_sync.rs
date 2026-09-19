//! End to end: two "machines" (two temp HOMEs) syncing through a local bare repo.
//!
//! Fully offline. Covers S4/S5/S6 and FR-8/FR-9/FR-10 of `REQUIREMENTS.md`.

mod common;

use common::{Device, bare_remote};
use tempfile::TempDir;

const PASS: &str = "shared-recovery-passphrase";

struct Pair {
    alpha: Device,
    beta: Device,
    _remote: TempDir,
}

/// Spins up a pair of devices that already know each other and share one remote.
fn pair() -> Pair {
    let remote = TempDir::new().unwrap();
    let url = bare_remote(&remote);

    let alpha = Device::blank();
    alpha.init("alpha", &["--remote", &url]);
    alpha.enable_recovery(PASS);
    alpha.run_ok_with_env(&["sync"], &[]);

    let beta = Device::blank();
    beta.join(&url, "beta", PASS);

    // alpha pulls back beta's device registration.
    alpha.run_ok_with_env(&["sync"], &[]);
    // Explicitly approve beta. This is the unavoidable friction of the rule "the remote can stuff
    // a public key into the directory, but only the local humans decide whether to encrypt to it" —
    // adding one device requires running this on **every other device**.
    alpha.run_ok_with_env(&["devices", "trust", "beta"], &[]);

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
    pair.alpha
        .set_secret("openai", "credential", "sk-alpha-canary");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    pair.beta.run_ok_with_env(&["sync"], &[]);

    assert_eq!(entry_names(&pair.beta), vec!["openai".to_string()]);
    // The point: beta gets usable plaintext, not a ciphertext it cannot open.
    let value = pair.beta.stdout(&["read", "akey://openai/credential"]);
    assert!(value.contains("sk-alpha-canary"));
}

#[test]
fn a_second_sync_with_nothing_to_do_reports_up_to_date() {
    let pair = pair();
    // The fixture's `devices trust beta` pushed a commit, so beta is one behind on entry.
    pair.beta.run_ok_with_env(&["sync"], &[]);

    let data = pair.beta.json_ok(&["sync"]);
    assert_eq!(data["outcome"], "up_to_date");
}

#[test]
fn edits_to_different_entries_merge_without_conflict() {
    let pair = pair();
    // The point: beta must **not** pull first. It stays at S0, alpha pushes to S1, then beta
    // commits on top of S0 — only that forms a real fork (common ancestor S0). If beta pulls
    // first it is merely "ahead", taking the plain push path.
    pair.alpha
        .set_secret("alpha-key", "credential", "from-alpha");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    pair.beta.set_secret("beta-key", "credential", "from-beta");

    let data = pair.beta.json_ok(&["sync"]);
    assert_eq!(data["outcome"], "merged");
    assert_eq!(data["conflicts"].as_array().unwrap().len(), 0);

    assert_eq!(
        entry_names(&pair.beta),
        vec!["alpha-key".to_string(), "beta-key".to_string()]
    );

    // alpha must see beta's entry too.
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

    // Both devices edit the same entry offline.
    pair.alpha.set_secret("shared", "credential", "alpha-wins");
    pair.beta.set_secret("shared", "credential", "beta-loses");
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    // beta syncs → the merge is committed and pushed, but exit code 5 explicitly demands a human look.
    let (code, kind, stdout) = pair.beta.expect_failure(&["sync"]);
    assert_eq!(
        code, 5,
        "conflicts must be surfaced with a distinct exit code"
    );
    assert_eq!(kind, "conflict");
    assert!(
        stdout.trim().is_empty(),
        "a failing command must not write stdout"
    );

    // Both sides' values survive: the original entry + a conflict copy.
    let names = entry_names(&pair.beta);
    assert_eq!(names.len(), 2, "both sides must survive: {names:?}");
    assert!(names.iter().any(|n| n == "shared"));
    assert!(
        names.iter().any(|n| n.starts_with("shared.conflict.")),
        "expected a conflict copy, got {names:?}"
    );

    // The conflict list is readable.
    let conflicts = pair.beta.json_ok(&["conflicts"]);
    assert_eq!(conflicts["conflicts"].as_array().unwrap().len(), 1);

    // Pick one side, then converge.
    pair.beta
        .run_ok_with_env(&["resolve", "shared", "--theirs"], &[]);
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
    // Conflict-copy IDs must be reproducible, otherwise every sync round spawns another copy and it never converges.
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

    // A few more rounds of bidirectional sync; the copy count must not grow.
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
    assert!(
        pair.beta
            .stdout(&["read", "akey://openai/credential"])
            .contains("sk-secret")
    );

    // alpha removes beta and re-encrypts.
    pair.alpha.run_ok_with_env(&["devices", "rm", "beta"], &[]);

    // beta can now neither sync nor read.
    let out = pair.beta.run(&["sync"]);
    assert!(
        !out.status.success(),
        "revoked device must not sync cleanly"
    );

    let (code, _, _) = pair.beta.expect_failure(&["list"]);
    assert_eq!(code, 4, "revoked device must be locked out");

    // alpha itself is unaffected.
    assert!(
        pair.alpha
            .stdout(&["read", "akey://openai/credential"])
            .contains("sk-secret")
    );
}

#[test]
fn devices_rm_refuses_to_lock_out_the_current_machine() {
    let pair = pair();
    let (code, kind, _) = pair.alpha.expect_failure(&["devices", "rm", "alpha"]);
    assert_eq!(code, 2);
    assert_eq!(kind, "usage");
}

/// Revocation must survive the **fast-forward path**, not only fork merges.
///
/// `merge_recipients`' "revocation wins" rule only ever runs on a fork. The fast-forward branch
/// used to `reset --hard` the worktree (including `recipients.json`) to the remote version
/// wholesale, so: a device that had been `devices rm`'d but still had git write access only had
/// to push an **ordinary commit** adding itself back, and the next device's fast-forward sync
/// would overwrite the local copy carrying the revocation marks — the revocation was instantly
/// undone and it could immediately read all plaintext written afterwards. Reproduced in practice.
#[test]
fn revocation_survives_a_fast_forward() {
    let pair = pair();
    pair.alpha
        .set_secret("openai", "credential", "sk-before-revoke");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    pair.beta.run_ok_with_env(&["sync"], &[]);
    assert!(
        pair.beta
            .stdout(&["read", "akey://openai/credential"])
            .contains("sk-before-revoke")
    );

    pair.alpha.run_ok_with_env(&["devices", "rm", "beta"], &[]);

    // beta is behind the remote: fast-forward, flip itself from revoked back to active, then push normally.
    let repo = pair.beta.repo();
    for args in [
        vec!["fetch", "--quiet", "origin"],
        vec!["reset", "--hard", "origin/main"],
    ] {
        assert!(
            git(&repo, &args).status.success(),
            "test setup: git {args:?}"
        );
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
        git(
            &repo,
            &[
                "-c",
                "user.name=beta",
                "-c",
                "user.email=b@x.y",
                "commit",
                "-q",
                "-m",
                "rejoin"
            ]
        )
        .status
        .success()
    );
    assert!(
        git(&repo, &["push", "--quiet", "origin", "HEAD"])
            .status
            .success(),
        "a device with git write access can always push"
    );

    // alpha's fast-forward sync must not adopt this tampered recipient list.
    pair.alpha.run_ok_with_env(&["sync"], &[]);

    let recipients: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pair.alpha.repo().join("recipients.json")).unwrap(),
    )
    .unwrap();
    let beta_active = recipients["recipients"]
        .as_object()
        .unwrap()
        .values()
        .any(|r| r["name"] == "beta" && r.get("revoked_at").is_none());
    assert!(
        !beta_active,
        "the revocation must not be undone by a fast-forward"
    );

    // And it really cannot read what was written afterwards.
    pair.alpha
        .set_secret("openai", "credential", "sk-after-revoke");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    let _ = git(&repo, &["fetch", "--quiet", "origin"]);
    let _ = git(&repo, &["reset", "--hard", "origin/main"]);
    let (code, _, _) = pair
        .beta
        .expect_failure(&["read", "akey://openai/credential"]);
    assert_eq!(code, 4, "a revoked device must stay locked out");
}

/// Runs one git command in the given repo (test-only; unrelated to product code).
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

/// **A1 regression**: someone who can write the remote can stuff a public key into
/// `recipients.json` and still never receive ciphertext.
///
/// This attack used to be fully viable: the attacker needed no keys at all — one ordinary
/// `git push` adding their own public key to `recipients.json` was enough, and the victim's
/// next legitimate write would re-encrypt "to all active recipients", handing the entire vault
/// (including history written before the attack) to the attacker.
///
/// Today's rule: `recipients.json` is merely the directory of "who exists"; **encryption only
/// goes to recipients this machine has approved**. The remote can get into the directory, but
/// not into the local trust set.
#[test]
fn an_injected_recipient_never_receives_ciphertext() {
    let remote = TempDir::new().unwrap();
    let url = bare_remote(&remote);

    let victim = Device::blank();
    victim.init("victim", &["--remote", &url]);
    victim.set_secret("openai", "credential", "sk-before-attack");
    victim.run_ok_with_env(&["sync"], &[]);

    // The attacker: one command makes an identity; it keeps only the public key.
    let attacker = Device::blank();
    attacker.init("attacker", &[]);
    let attacker_recipients: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(attacker.repo().join("recipients.json")).unwrap(),
    )
    .unwrap();
    let attacker_pub = attacker_recipients["recipients"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();

    // The attacker has remote **write** access: clone, change one JSON field, commit, push. No keys needed.
    let scratch = TempDir::new().unwrap();
    let clone = scratch.path().join("clone");
    assert!(
        git(
            scratch.path(),
            &["clone", "--quiet", &url, clone.to_str().unwrap()]
        )
        .status
        .success()
    );
    let path = clone.join("recipients.json");
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    file["recipients"][&attacker_pub] = serde_json::json!({
        "name": "backup-node",
        "kind": "device",
        "added_at": "2026-01-01T00:00:00Z",
        "last_seen_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
    assert!(git(&clone, &["add", "-A"]).status.success());
    assert!(
        git(
            &clone,
            &[
                "-c",
                "user.name=x",
                "-c",
                "user.email=x@y.z",
                "commit",
                "-q",
                "-m",
                "add node"
            ]
        )
        .status
        .success()
    );
    assert!(
        git(&clone, &["push", "--quiet", "origin", "HEAD"])
            .status
            .success()
    );

    // The victim syncs: the public key enters the directory but is marked pending and is not encrypted to.
    let data = victim.json_ok(&["sync"]);
    let pending = data["pending_recipients"].as_array().unwrap();
    assert!(
        pending.iter().any(|p| p["pubkey"] == attacker_pub.as_str()),
        "the injected key must be surfaced as pending: {data}"
    );

    // The victim writes as usual.
    victim.set_secret("openai", "credential", "sk-after-attack");
    victim.run_ok_with_env(&["sync"], &[]);

    // The attacker points its identity at that repo and tries to decrypt after a fast-forward — it must not reach it.
    let config_path = attacker.home_path().join("config.toml");
    let rewritten: String = std::fs::read_to_string(&config_path)
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("repo = ") {
                format!("repo = \"{}\"", clone.display())
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&config_path, rewritten).unwrap();
    assert!(
        git(&clone, &["fetch", "--quiet", "origin"])
            .status
            .success()
    );
    assert!(
        git(&clone, &["reset", "--hard", "origin/main"])
            .status
            .success()
    );

    let (code, kind, stdout) = attacker.expect_failure(&["read", "akey://openai/credential"]);
    assert_eq!(code, 4, "an injected recipient must be locked out ({kind})");
    assert!(
        !stdout.contains("sk-after-attack") && !stdout.contains("sk-before-attack"),
        "the injected recipient recovered plaintext: {stdout}"
    );
}

/// After approval that device really can read (proving the lock above has a key).
#[test]
fn trusting_a_recipient_lets_it_decrypt() {
    let pair = pair();
    pair.alpha.set_secret("openai", "credential", "sk-for-beta");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    pair.beta.run_ok_with_env(&["sync"], &[]);
    assert!(
        pair.beta
            .stdout(&["read", "akey://openai/credential"])
            .contains("sk-for-beta")
    );

    // Revoke approval: still in the directory, but gets no new ciphertext.
    pair.alpha
        .run_ok_with_env(&["devices", "untrust", "beta"], &[]);
    pair.alpha
        .set_secret("openai", "credential", "sk-after-untrust");
    pair.alpha.run_ok_with_env(&["sync"], &[]);
    let out = pair.beta.run(&["sync"]);
    assert!(
        !out.status.success(),
        "beta can no longer open new revisions"
    );
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
    // No half-finished identity is left behind.
    assert!(!stranger.home_path().join("identity.key").is_file());
}

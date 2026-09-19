//! Shared fixtures for integration tests: one isolated "device" = one temp HOME + one temp repo.
//!
//! Fully offline: the remote is a local `file://` bare repo, and global git config is cleared so
//! the developer's machine settings cannot bleed in.

#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

pub struct Device {
    pub home: TempDir,
    pub workspace: TempDir,
}

impl Device {
    /// An uninitialized "blank machine".
    pub fn blank() -> Device {
        Device {
            home: TempDir::new().unwrap(),
            workspace: TempDir::new().unwrap(),
        }
    }

    /// A machine already `init --no-recovery`'d.
    pub fn initialized(name: &str) -> Device {
        let device = Device::blank();
        device.init(name, &[]);
        device
    }

    pub fn home_path(&self) -> PathBuf {
        self.home.path().to_path_buf()
    }

    /// The machine's vault repo path (`init` defaults to `$HOME/repo`).
    pub fn repo(&self) -> PathBuf {
        self.home.path().join("repo")
    }

    /// An `akey` command wired up with the isolated environment.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_akey"));
        cmd.arg("--home").arg(self.home.path());
        cmd.current_dir(self.workspace.path());
        cmd.env("HOME", self.home.path());
        // Isolate machine-local git config: otherwise the developer's own insteadOf / signing setup bleeds into the test.
        cmd.env("GIT_CONFIG_GLOBAL", self.workspace.path().join("gitconfig"));
        cmd.env("GIT_CONFIG_SYSTEM", self.workspace.path().join("gitconfig"));
        cmd.env("AKEY_RECOVERY_PASSPHRASE", "");
        cmd.env_remove("AKEY_TOKEN");
        cmd.env_remove("AKEY_NO_REVEAL");
        cmd.env_remove("AKEY_DEVICE_NAME");
        cmd.stdin(Stdio::null());
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    /// Runs with stdin.
    pub fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        self.run_with_stdin_env(args, stdin, &[])
    }

    /// Runs with stdin and environment variables.
    pub fn run_with_stdin_env(&self, args: &[&str], stdin: &str, envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    pub fn init(&self, name: &str, extra: &[&str]) {
        let mut args = vec!["init", "--no-recovery", "--device", name];
        args.extend_from_slice(extra);
        let out = self.run(&args);
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Writes an entry, with the secret value going through stdin (to keep it out of argv).
    pub fn set_secret(&self, name: &str, field: &str, value: &str) {
        let payload = format!("{field}={value}\n");
        let out = self.run_with_stdin(
            &["set", name, "--category", "apikey", "--stdin"],
            &payload,
        );
        assert!(
            out.status.success(),
            "set {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Expects success and parses the `data` from the `--json` envelope.
    pub fn json_ok(&self, args: &[&str]) -> serde_json::Value {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        let out = self.run(&full);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            out.status.success(),
            "`akey {}` failed ({}):\nstdout: {stdout}\nstderr: {stderr}",
            args.join(" "),
            out.status.code().unwrap_or(-1)
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not JSON: {e}\n{stdout}"));
        assert_eq!(parsed["ok"], true, "envelope not ok: {stdout}");
        parsed["data"].clone()
    }

    /// Expects failure; returns (exit code, error code parsed from stderr, raw stdout).
    pub fn expect_failure(&self, args: &[&str]) -> (i32, String, String) {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        let out = self.run(&full);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let code = out.status.code().expect("process should exit normally");
        let parsed: serde_json::Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|e| panic!("stderr is not a JSON error envelope: {e}\n{stderr}"));
        assert_eq!(parsed["ok"], false);
        (
            code,
            parsed["error"]["code"].as_str().unwrap_or("").to_string(),
            stdout,
        )
    }

    pub fn stdout(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    pub fn stderr(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.run(args).stderr).to_string()
    }

    /// Runs with extra environment variables (e.g. supplying the recovery passphrase).
    pub fn run_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.args(args).output().unwrap()
    }

    /// Runs with environment variables and asserts success.
    pub fn run_ok_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let out = self.run_with_env(args, envs);
        assert!(
            out.status.success(),
            "`akey {}` failed ({}): {}",
            args.join(" "),
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Runs with environment variables and parses the `--json` `data`.
    pub fn json_ok_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> serde_json::Value {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        let out = self.run_ok_with_env(&full, envs);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let parsed: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON: {e}\n{stdout}"));
        assert_eq!(parsed["ok"], true, "envelope not ok: {stdout}");
        parsed["data"].clone()
    }

    /// Enables the recovery passphrase (a prerequisite for bootstrapping another machine).
    pub fn enable_recovery(&self, passphrase: &str) {
        self.run_ok_with_env(&["recovery", "set"], &[("AKEY_RECOVERY_PASSPHRASE", passphrase)]);
    }

    /// Bootstraps a new device from the remote.
    pub fn join(&self, url: &str, name: &str, passphrase: &str) {
        self.run_ok_with_env(
            &["init", "--from", url, "--device", name],
            &[("AKEY_RECOVERY_PASSPHRASE", passphrase)],
        );
    }
}

/// Creates a local bare repo and returns a `file://` URL. No test touches the network.
pub fn bare_remote(dir: &TempDir) -> String {
    let path = dir.path().join("remote.git");
    let out = Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    format!("file://{}", path.display())
}

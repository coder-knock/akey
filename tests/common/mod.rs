//! 集成测试共用夹具：一台隔离的"设备" = 一个临时 HOME + 一个临时仓库。
//!
//! 全部离线：远端用本地 `file://` 裸仓库，git 全局配置被清空，杜绝开发者本机配置干扰。

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
    /// 未初始化的一台"空机器"。
    pub fn blank() -> Device {
        Device {
            home: TempDir::new().unwrap(),
            workspace: TempDir::new().unwrap(),
        }
    }

    /// 已 `init --no-recovery` 的一台机器。
    pub fn initialized(name: &str) -> Device {
        let device = Device::blank();
        device.init(name, &[]);
        device
    }

    pub fn home_path(&self) -> PathBuf {
        self.home.path().to_path_buf()
    }

    /// 该机器的金库仓库路径（`init` 默认落在 `$HOME/repo`）。
    pub fn repo(&self) -> PathBuf {
        self.home.path().join("repo")
    }

    /// 装好隔离环境的 `akey` 命令。
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_akey"));
        cmd.arg("--home").arg(self.home.path());
        cmd.current_dir(self.workspace.path());
        cmd.env("HOME", self.home.path());
        // 隔离本机 git 配置：否则开发者自己的 insteadOf / 签名设置会渗进测试。
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

    /// 带 stdin 运行。
    pub fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        self.run_with_stdin_env(args, stdin, &[])
    }

    /// 带 stdin 与环境变量运行。
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

    /// 写一个条目，秘密值走 stdin（避免进 argv）。
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

    /// 期望成功并解析 `--json` 信封的 `data`。
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

    /// 期望失败，返回 (退出码, stderr 解析出的错误 code, 原始 stdout)。
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

    /// 带额外环境变量运行（如提供恢复密码）。
    pub fn run_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.args(args).output().unwrap()
    }

    /// 带环境变量运行并断言成功。
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

    /// 带环境变量运行并解析 `--json` 的 `data`。
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

    /// 启用恢复密码（换机引导的前提）。
    pub fn enable_recovery(&self, passphrase: &str) {
        self.run_ok_with_env(&["recovery", "set"], &[("AKEY_RECOVERY_PASSPHRASE", passphrase)]);
    }

    /// 从远端引导一台新设备。
    pub fn join(&self, url: &str, name: &str, passphrase: &str) {
        self.run_ok_with_env(
            &["init", "--from", url, "--device", name],
            &[("AKEY_RECOVERY_PASSPHRASE", passphrase)],
        );
    }
}

/// 建一个本地裸仓库，返回 `file://` URL。全测试不触网。
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

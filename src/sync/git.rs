//! 系统 `git` 的薄封装。
//!
//! 为什么是子进程而不是 `gix`：同步要走用户已有的 SSH key、credential helper、
//! 代理与 `insteadOf` 配置——这些 `git` 全都能用，纯 Rust 实现要重造一遍且更脆。
//!
//! 两条纪律：
//! - **绝不交互**：`GIT_TERMINAL_PROMPT=0`，避免 AI 调用时挂死在密码提示上。
//! - **消息稳定**：`LC_ALL=C`，否则下面基于 stderr 文案的判断会因本地化而失效。

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Pushed,
    UpToDate,
    /// 远端有新提交，需要先合并再推。
    Rejected,
}

pub struct Git {
    repo: PathBuf,
    author_name: String,
    author_email: String,
}

impl Git {
    pub fn new(repo: &Path, author_name: impl Into<String>, author_email: impl Into<String>) -> Self {
        Git {
            repo: repo.to_path_buf(),
            author_name: author_name.into(),
            author_email: author_email.into(),
        }
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// 组装命令。所有 git 调用都必须经此，保证非交互与环境一致。
    fn command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(&self.repo);
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        cmd.env("GIT_ASKPASS", "");
        cmd.env("SSH_ASKPASS", "");
        cmd.env("LC_ALL", "C");
        cmd
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let out = self.output(args)?;
        if !out.status.success() {
            return Err(git_failure(args, &out));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
    }

    /// 返回 `None` 表示命令非 0 退出（用于"允许失败"的探查）。
    fn run_optional(&self, args: &[&str]) -> Result<Option<String>> {
        let out = self.output(args)?;
        if out.status.success() {
            Ok(Some(String::from_utf8_lossy(&out.stdout).trim_end().to_string()))
        } else {
            Ok(None)
        }
    }

    fn output(&self, args: &[&str]) -> Result<Output> {
        self.command()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                Error::Git(format!(
                    "cannot run `git`: {e}; akey needs git on PATH for sync"
                ))
            })
    }

    pub fn is_repo(&self) -> bool {
        self.repo.join(".git").exists()
    }

    pub fn init(&self) -> Result<()> {
        std::fs::create_dir_all(&self.repo)?;
        self.run(&["init", "--quiet", "--initial-branch=main"])?;
        Ok(())
    }

    /// 克隆远端到 `dest`。目标目录必须为空或不存在（`git clone` 的要求）。
    pub fn clone(url: &str, dest: &Path) -> Result<Git> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let out = Command::new("git")
            .args(["clone", "--quiet", url])
            .arg(dest)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Git(format!("cannot run `git clone`: {e}")))?;
        if !out.status.success() {
            return Err(Error::SyncFailed(format!(
                "git clone {url} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(Git::new(dest, "akey", "akey@akey.invalid"))
    }

    /// 远端 URL，未配置则为 `None`。
    pub fn remote_url(&self) -> Result<Option<String>> {
        Ok(self
            .run_optional(&["remote", "get-url", "origin"])?
            .filter(|s| !s.is_empty()))
    }

    /// 设定或替换 `origin`。
    pub fn set_remote(&self, url: &str) -> Result<()> {
        if self.remote_url()?.is_some() {
            self.run(&["remote", "set-url", "origin", url])?;
        } else {
            self.run(&["remote", "add", "origin", url])?;
        }
        Ok(())
    }

    pub fn add_all(&self) -> Result<()> {
        self.run(&["add", "-A"])?;
        Ok(())
    }

    /// 提交暂存区。无内容可提交时返回 `false`（不是错误）。
    ///
    /// 先自己问 git"有没有暂存内容"，而不是解析 `nothing to commit` 那句文案：
    /// `--quiet` 会把它一起压掉，而且文案随版本与语言变化。
    pub fn commit(&self, message: &str) -> Result<bool> {
        // 退出码 0 = 无暂存差异；1 = 有。这里不把它当错误，所以走 `output` 而非 `run`。
        let staged = self.output(&["diff", "--cached", "--quiet"])?;
        if staged.status.success() {
            return Ok(false);
        }

        let out = self
            .command()
            .args([
                "-c",
                &format!("user.name={}", self.author_name),
                "-c",
                &format!("user.email={}", self.author_email),
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                message,
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Git(format!("cannot run `git commit`: {e}")))?;

        if out.status.success() {
            return Ok(true);
        }
        // 竞态兜底：预检之后、提交之前被别的进程清空了暂存区。
        if combined(&out).contains("nothing to commit") {
            return Ok(false);
        }
        Err(Error::Git(format!(
            "git commit failed: {}",
            combined(&out).trim()
        )))
    }

    pub fn fetch(&self) -> Result<()> {
        let out = self
            .command()
            .args(["fetch", "--quiet", "origin"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Git(format!("cannot run `git fetch`: {e}")))?;
        if !out.status.success() {
            return Err(Error::SyncFailed(format!(
                "git fetch failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    pub fn try_rev_parse(&self, rev: &str) -> Result<Option<String>> {
        Ok(self
            .run_optional(&["rev-parse", "--verify", "--quiet", rev])?
            .filter(|s| !s.is_empty()))
    }

    pub fn merge_base(&self, a: &str, b: &str) -> Result<Option<String>> {
        Ok(self
            .run_optional(&["merge-base", a, b])?
            .filter(|s| !s.is_empty()))
    }

    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool> {
        let out = self.output(&["merge-base", "--is-ancestor", ancestor, descendant])?;
        Ok(out.status.success())
    }

    pub fn commit_count(&self, range: &str) -> Result<usize> {
        let raw = self.run(&["rev-list", "--count", range])?;
        Ok(raw.trim().parse().unwrap_or(0))
    }

    pub fn rev_subject(&self, rev: &str) -> Result<String> {
        self.run(&["log", "-1", "--format=%s", rev])
    }

    /// 读取历史版本里的文件原始字节。路径不存在 → `None`。
    ///
    /// 用 `cat-file` 而非 `show`：前者是 plumbing，输出不经文本化处理，二进制安全。
    pub fn show_bytes(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let out = self.output(&["cat-file", "blob", &format!("{rev}:{path}")])?;
        if out.status.success() {
            Ok(Some(out.stdout))
        } else {
            Ok(None)
        }
    }

    /// 把工作区文件强制同步到某个版本。
    pub fn checkout_from(&self, rev: &str, path: &str) -> Result<()> {
        let out = self.output(&["checkout", rev, "--", path])?;
        if !out.status.success() {
            return Err(Error::SyncFailed(format!(
                "git checkout {rev} -- {path} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    pub fn reset_hard(&self, rev: &str) -> Result<()> {
        self.run(&["reset", "--hard", rev])?;
        Ok(())
    }

    /// 只移动分支指针，保留索引与工作区。
    ///
    /// 合并时用它把 HEAD 落到远端之上，再提交合并结果——这样提交以远端为祖先，
    /// push 能快进；否则每轮同步都会再撞一次非快进。
    pub fn reset_soft(&self, rev: &str) -> Result<()> {
        self.run(&["reset", "--soft", rev])?;
        Ok(())
    }

    pub fn restore_path(&self, path: &str) -> Result<()> {
        self.run(&["checkout", "HEAD", "--", path])?;
        Ok(())
    }

    /// 推送当前 HEAD。
    ///
    /// 用 `--porcelain`：它承诺给脚本用的稳定格式（每行以状态标记开头），
    /// 而不是靠 `Everything up-to-date` 这类会随版本/语言变化的人话。
    pub fn push(&self) -> Result<PushOutcome> {
        let out = self
            .command()
            .args(["push", "--porcelain", "origin", "HEAD"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Git(format!("cannot run `git push`: {e}")))?;

        let stdout = String::from_utf8_lossy(&out.stdout);
        let text = combined(&out);

        if out.status.success() {
            for line in stdout.lines() {
                match line.chars().next() {
                    // porcelain 的标记位：`=` 表示已是最新，其余（空格/+/@/-/*/!）表示发生了变更。
                    Some('=') => return Ok(PushOutcome::UpToDate),
                    Some(' ' | '+' | '-' | '*' | '@') => return Ok(PushOutcome::Pushed),
                    _ => {}
                }
            }
            // 没给出可解析的行（例如远端无分支）时按"推成功了"处理。
            return Ok(PushOutcome::Pushed);
        }

        if is_non_fast_forward(&text) {
            return Ok(PushOutcome::Rejected);
        }
        Err(Error::SyncFailed(format!(
            "git push failed: {}",
            text.trim()
        )))
    }
}

/// 识别"远端领先"这一类拒绝。`LC_ALL=C` 保证文案稳定。
pub fn is_non_fast_forward(stderr: &str) -> bool {
    stderr.contains("non-fast-forward")
        || stderr.contains("failed to push some refs")
        || stderr.contains("fetch first")
        || stderr.contains("Updates were rejected")
        || stderr.contains("behind its remote")
}

fn git_failure(args: &[&str], out: &Output) -> Error {
    Error::Git(format!(
        "git {} failed: {}",
        args.join(" "),
        combined(out).trim()
    ))
}

/// git 把提示与错误分散在 stdout / stderr，判定时两边都要看。
fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git_in(dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .output()
            .unwrap()
    }

    fn temp_repo() -> (tempfile::TempDir, Git) {
        let dir = tempfile::tempdir().unwrap();
        let git = Git::new(dir.path(), "akey-test", "akey@example.invalid");
        git.init().unwrap();
        (dir, git)
    }

    #[test]
    fn init_creates_a_repository() {
        let (_guard, git) = temp_repo();
        assert!(git.is_repo());
    }

    #[test]
    fn commit_reports_whether_anything_changed() {
        let (_guard, git) = temp_repo();
        std::fs::write(git.repo().join("a.txt"), b"one").unwrap();
        git.add_all().unwrap();
        assert!(git.commit("first").unwrap(), "should have committed");

        git.add_all().unwrap();
        assert!(!git.commit("again").unwrap(), "nothing to commit should be false");
    }

    #[test]
    fn rev_parse_and_merge_base_behave() {
        let (_guard, git) = temp_repo();
        std::fs::write(git.repo().join("a.txt"), b"one").unwrap();
        git.add_all().unwrap();
        git.commit("first").unwrap();
        let first = git.try_rev_parse("HEAD").unwrap().unwrap();

        std::fs::write(git.repo().join("a.txt"), b"two").unwrap();
        git.add_all().unwrap();
        git.commit("second").unwrap();
        let second = git.try_rev_parse("HEAD").unwrap().unwrap();

        assert_ne!(first, second);
        assert!(git.is_ancestor(&first, &second).unwrap());
        assert!(!git.is_ancestor(&second, &first).unwrap());
        assert_eq!(git.merge_base(&first, &second).unwrap().unwrap(), first);
        assert_eq!(git.commit_count(&format!("{first}..{second}")).unwrap(), 1);
        assert_eq!(git.rev_subject(&second).unwrap(), "second");
    }

    #[test]
    fn missing_revision_yields_none_rather_than_error() {
        let (_guard, git) = temp_repo();
        assert!(git.try_rev_parse("HEAD").unwrap().is_none());
        assert!(git.merge_base("HEAD", "HEAD").unwrap().is_none());
    }

    #[test]
    fn show_bytes_is_binary_safe_and_absent_paths_are_none() {
        let (_guard, git) = temp_repo();
        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        std::fs::write(git.repo().join("blob.bin"), &payload).unwrap();
        git.add_all().unwrap();
        git.commit("binary").unwrap();
        let rev = git.try_rev_parse("HEAD").unwrap().unwrap();

        assert_eq!(git.show_bytes(&rev, "blob.bin").unwrap().unwrap(), payload);
        assert!(git.show_bytes(&rev, "nope.bin").unwrap().is_none());
    }

    #[test]
    fn remote_url_absent_then_set_then_replaced() {
        let (_guard, git) = temp_repo();
        assert!(git.remote_url().unwrap().is_none());

        git.set_remote("file:///tmp/one.git").unwrap();
        assert_eq!(git.remote_url().unwrap().unwrap(), "file:///tmp/one.git");

        git.set_remote("file:///tmp/two.git").unwrap();
        assert_eq!(git.remote_url().unwrap().unwrap(), "file:///tmp/two.git");
    }

    #[test]
    fn push_to_a_local_bare_repo_succeeds_then_detects_up_to_date() {
        let bare = tempfile::tempdir().unwrap();
        git_in(bare.path(), &["init", "--bare", "--quiet"]);
        let (_guard, git) = temp_repo();
        git.set_remote(&format!("file://{}", bare.path().display())).unwrap();

        std::fs::write(git.repo().join("a.txt"), b"one").unwrap();
        git.add_all().unwrap();
        git.commit("first").unwrap();

        assert_eq!(git.push().unwrap(), PushOutcome::Pushed);
        assert_eq!(git.push().unwrap(), PushOutcome::UpToDate);
    }

    #[test]
    fn push_reports_rejected_when_the_remote_moved_ahead() {
        let bare = tempfile::tempdir().unwrap();
        git_in(bare.path(), &["init", "--bare", "--quiet"]);
        let url = format!("file://{}", bare.path().display());

        // 设备 A 推送第一条。
        let (dir_a, git_a) = temp_repo();
        git_a.set_remote(&url).unwrap();
        std::fs::write(git_a.repo().join("a.txt"), b"one").unwrap();
        git_a.add_all().unwrap();
        git_a.commit("from a").unwrap();
        assert_eq!(git_a.push().unwrap(), PushOutcome::Pushed);

        // 设备 B 克隆后推第二条。
        let dir_b = tempfile::tempdir().unwrap();
        git_in(dir_b.path(), &["clone", "--quiet", &url, "."]);
        let git_b = Git::new(dir_b.path(), "b", "b@example.invalid");
        std::fs::write(dir_b.path().join("b.txt"), b"two").unwrap();
        git_b.add_all().unwrap();
        git_b.commit("from b").unwrap();
        assert_eq!(git_b.push().unwrap(), PushOutcome::Pushed);

        // A 在不知道 B 的情况下再提交 → push 被拒。
        std::fs::write(git_a.repo().join("a.txt"), b"three").unwrap();
        git_a.add_all().unwrap();
        git_a.commit("from a again").unwrap();
        assert_eq!(git_a.push().unwrap(), PushOutcome::Rejected);

        // fetch 后能定位分叉点。
        git_a.fetch().unwrap();
        let local = git_a.try_rev_parse("HEAD").unwrap().unwrap();
        let remote = git_a.try_rev_parse("FETCH_HEAD").unwrap().unwrap();
        assert_ne!(local, remote);
        assert!(git_a.merge_base(&local, &remote).unwrap().is_some());

        drop(dir_a);
        drop(dir_b);
    }

    #[test]
    fn non_fast_forward_detection_matches_real_git_wording() {
        for text in [
            "! [rejected]        main -> main (non-fast-forward)",
            "error: failed to push some refs to 'origin'",
            "hint: Updates were rejected because the tip of your current branch is behind",
            "! [rejected] main -> main (fetch first)",
        ] {
            assert!(is_non_fast_forward(text), "should match: {text}");
        }
        assert!(!is_non_fast_forward("fatal: could not read Username"));
    }

    #[test]
    fn git_failure_is_actionable_when_repo_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let git = Git::new(&dir.path().join("nope"), "x", "x@y.z");
        let err = git.run(&["status"]).unwrap_err();
        assert!(matches!(err, Error::Git(_)));
        assert_eq!(err.exit_code(), 1);
    }
}

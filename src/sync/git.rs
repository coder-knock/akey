//! A thin wrapper around the system `git`.
//!
//! Why a subprocess and not `gix`: sync rides on the SSH key, credential helper, proxy and
//! `insteadOf` configuration the user already has — `git` handles all of them, while a pure
//! Rust implementation would have to rebuild them and would be more fragile.
//!
//! Two disciplines:
//! - **Never interactive**: `GIT_TERMINAL_PROMPT=0`, so an AI invocation cannot hang on a
//!   password prompt.
//! - **Stable messages**: `LC_ALL=C`, otherwise the stderr-text checks below break under
//!   localisation.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Pushed,
    UpToDate,
    /// The remote has new commits; merge before pushing.
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

    /// Build a command. Every git invocation must go through this, keeping it
    /// non-interactive and consistent.
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

    /// `None` means the command exited non-zero (for "failure is allowed" probes).
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

    /// Clone the remote into `dest`. The destination must be empty or absent (a
    /// `git clone` requirement).
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

    /// The remote URL, or `None` when unset.
    pub fn remote_url(&self) -> Result<Option<String>> {
        Ok(self
            .run_optional(&["remote", "get-url", "origin"])?
            .filter(|s| !s.is_empty()))
    }

    /// Set or replace `origin`.
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

    /// Stage only the given paths. It keeps files that stray into the repository directory
    /// out of the commit.
    ///
    /// Paths that are neither on disk nor in the index must be filtered out: `git add -A --
    /// <pathspec>` fails outright on such a path (`recovery.age` does not exist yet during
    /// `init`).
    pub fn add_paths(&self, paths: &[&str]) -> Result<()> {
        let tracked = self.run(&["ls-files"])?;
        let tracked: std::collections::HashSet<&str> = tracked.lines().collect();

        let wanted: Vec<&str> = paths
            .iter()
            .copied()
            .filter(|path| self.repo.join(path).exists() || tracked.contains(path))
            .collect();

        if wanted.is_empty() {
            return Ok(());
        }
        let mut args = vec!["add", "-A", "--"];
        args.extend_from_slice(&wanted);
        self.run(&args)?;
        Ok(())
    }

    /// Commit the index. Returns `false` when there is nothing to commit (not an error).
    ///
    /// Ask git whether anything is staged instead of parsing the `nothing to commit`
    /// wording: `--quiet` suppresses it, and the wording drifts across versions and
    /// locales.
    pub fn commit(&self, message: &str) -> Result<bool> {
        // Exit code 0 = nothing staged; 1 = something staged. Neither counts as an error
        // here, so this goes through `output` rather than `run`.
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
        // Race fallback: between the pre-check and the commit, another process emptied the
        // index.
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

    /// Read the raw bytes of a file at a historical revision. Absent path → `None`.
    ///
    /// Uses `cat-file` rather than `show`: the former is plumbing, its output is not
    /// text-processed, and it is binary-safe.
    pub fn show_bytes(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let out = self.output(&["cat-file", "blob", &format!("{rev}:{path}")])?;
        if out.status.success() {
            Ok(Some(out.stdout))
        } else {
            Ok(None)
        }
    }

    /// Force a working-tree file to match a revision.
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

    /// Move only the branch pointer, keeping the index and working tree.
    ///
    /// A merge uses this to drop HEAD onto the remote before committing the merge result —
    /// that way the commit has the remote as an ancestor and the push can fast-forward;
    /// otherwise every round of sync hits another non-fast-forward.
    pub fn reset_soft(&self, rev: &str) -> Result<()> {
        self.run(&["reset", "--soft", rev])?;
        Ok(())
    }

    pub fn restore_path(&self, path: &str) -> Result<()> {
        self.run(&["checkout", "HEAD", "--", path])?;
        Ok(())
    }

    /// Push the current HEAD.
    ///
    /// Uses `--porcelain`: it promises a stable, script-oriented format (each line starts
    /// with a status flag) rather than relying on human prose like `Everything up-to-date`
    /// that drifts across versions and locales.
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
                    // porcelain flags: `=` means already up to date, anything else
                    // (space / + / @ / - / * / !) means something changed.
                    Some('=') => return Ok(PushOutcome::UpToDate),
                    Some(' ' | '+' | '-' | '*' | '@') => return Ok(PushOutcome::Pushed),
                    _ => {}
                }
            }
            // No parseable line (e.g. the remote has no branch) counts as "pushed".
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

/// Recognise "the remote is ahead"-style rejections. `LC_ALL=C` keeps the wording stable.
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

/// git spreads hints and errors across stdout / stderr, so both must be inspected.
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

        // Device A pushes the first commit.
        let (dir_a, git_a) = temp_repo();
        git_a.set_remote(&url).unwrap();
        std::fs::write(git_a.repo().join("a.txt"), b"one").unwrap();
        git_a.add_all().unwrap();
        git_a.commit("from a").unwrap();
        assert_eq!(git_a.push().unwrap(), PushOutcome::Pushed);

        // Device B clones and pushes a second commit.
        let dir_b = tempfile::tempdir().unwrap();
        git_in(dir_b.path(), &["clone", "--quiet", &url, "."]);
        let git_b = Git::new(dir_b.path(), "b", "b@example.invalid");
        std::fs::write(dir_b.path().join("b.txt"), b"two").unwrap();
        git_b.add_all().unwrap();
        git_b.commit("from b").unwrap();
        assert_eq!(git_b.push().unwrap(), PushOutcome::Pushed);

        // A commits again, unaware of B → the push is rejected.
        std::fs::write(git_a.repo().join("a.txt"), b"three").unwrap();
        git_a.add_all().unwrap();
        git_a.commit("from a again").unwrap();
        assert_eq!(git_a.push().unwrap(), PushOutcome::Rejected);

        // After a fetch, the fork point can be located.
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

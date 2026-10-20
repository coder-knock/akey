//! Test-only helpers. A stub `akey` that records how it was invoked, so tests can assert
//! on the exact argv and stdin the GUI would have produced.
//!
//! Compiled only under `cfg(test)` on Unix — the stub is a POSIX shell script, and the
//! CLI's own end-to-end suite is gated the same way.
#![cfg(all(test, unix))]

use std::path::{Path, PathBuf};

/// Write an executable stub that behaves like `akey` for one canned scenario.
pub fn stub(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("akey-stub");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// A stub that records its argv and stdin, then replies with a fixed envelope.
pub struct RecordingStub {
    pub bin: PathBuf,
    pub argv_log: PathBuf,
    pub stdin_log: PathBuf,
}

impl RecordingStub {
    /// Record argv + stdin, then print `json` on stdout and exit 0.
    pub fn new(dir: &Path, json: &str) -> Self {
        Self::with_exit(dir, json, 0)
    }

    /// Record argv + stdin, then print `json` (to stderr when non-zero) and exit `code`.
    pub fn with_exit(dir: &Path, json: &str, code: i32) -> Self {
        let argv_log = dir.join("argv.log");
        let stdin_log = dir.join("stdin.log");
        let redirect = if code == 0 { "" } else { " >&2" };
        let bin = stub(
            dir,
            &format!(
                "printf '%s\\n' \"$@\" > {argv}\n\
                 cat > {stdin}\n\
                 printf '%s\\n' '{json}'{redirect}\n\
                 exit {code}\n",
                argv = argv_log.display(),
                stdin = stdin_log.display(),
                json = json,
                redirect = redirect,
                code = code
            ),
        );
        RecordingStub {
            bin,
            argv_log,
            stdin_log,
        }
    }

    /// Each recorded argv element, in order.
    pub fn argv(&self) -> Vec<String> {
        std::fs::read_to_string(&self.argv_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    pub fn stdin(&self) -> String {
        std::fs::read_to_string(&self.stdin_log).unwrap_or_default()
    }

    pub fn argv_joined(&self) -> String {
        self.argv().join(" ")
    }
}

/// A stub that emits a fixed envelope and exits with `code`, without recording anything.
pub fn canned(dir: &Path, json: &str, code: i32) -> PathBuf {
    let redirect = if code == 0 { "" } else { " >&2" };
    stub(
        dir,
        &format!("printf '%s\\n' '{json}'{redirect}\nexit {code}"),
    )
}

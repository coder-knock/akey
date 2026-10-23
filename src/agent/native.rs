//! Native harness CLI delegation.
//!
//! A harness CLI is used only to **add** an entry: it knows its own file format, but it
//! usually has no replace semantics and does not preserve comments. Replacement always
//! goes through [`super::config`], where the edit is structural and atomic.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::registry::{self, Harness, Scope};

/// How `install` reaches a harness config.
#[derive(Debug, Clone, Copy, Default)]
pub enum NativeMode<'a> {
    /// Always edit the config file. This is what `--no-native` and `$AKEY_AGENT_NATIVE=off`
    /// select, and what tests use so a real harness CLI is never invoked.
    #[default]
    Disabled,
    /// Use the harness CLI when it is on `PATH`, else edit the config file.
    Auto,
    /// Use a specific `PATH` value instead of the process environment (test hook).
    Path(&'a OsStr),
}

impl NativeMode<'_> {
    /// The harness executable this mode would run, if any.
    pub(super) fn program(&self, harness: &Harness) -> Option<PathBuf> {
        let name = harness.native_cli?;
        match self {
            NativeMode::Disabled => None,
            NativeMode::Path(path) => registry::find_in_path_in(name, path),
            NativeMode::Auto if registry::native_disabled() => None,
            NativeMode::Auto => registry::find_in_path(name),
        }
    }
}

pub(super) fn run_native(
    harness: &Harness,
    scope: Scope,
    cwd: &Path,
    program: &Path,
    config: &Path,
) -> crate::error::Result<()> {
    let args = harness
        .native_args(scope)
        .expect("native plans only exist for scopes with a native writer");
    // stdout is captured, never inherited: it belongs to the harness, and akey's own stdout
    // is a machine-readable contract that nothing else may pollute.
    let output = Command::new(program)
        .args(&args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| {
            crate::error::Error::harness(crate::msg!(
                "cannot run `{}`: {}",
                "无法运行 `{}`：{}",
                program.display(),
                err
            ))
        })?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = summarize(&stderr);
    Err(crate::error::Error::harness(crate::msg!(
        "`{} {}` failed ({}): {}; inspect {} before retrying, or rerun with `--no-native` to edit it directly",
        "`{} {}` 执行失败（{}）：{}；重试前请先检查 {} 的状态，或加 `--no-native` 直接编辑它",
        program.display(),
        args.join(" "),
        output.status,
        detail,
        config.display()
    )))
}

/// First few lines of harness diagnostics, bounded so an error message stays readable.
fn summarize(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return crate::msg!("no diagnostics", "没有诊断信息").to_string();
    }
    let mut lines = trimmed.lines().take(3).collect::<Vec<_>>().join("; ");
    if trimmed.lines().count() > 3 {
        lines.push_str("; …");
    }
    const MAX: usize = 400;
    if lines.chars().count() > MAX {
        lines = lines.chars().take(MAX).collect::<String>() + "…";
    }
    lines
}

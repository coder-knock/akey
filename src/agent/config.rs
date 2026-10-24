//! Config-file adapters: inspect and apply the `akey` MCP entry for one harness.
//!
//! Each adapter edits the harness's real serialization format instead of re-emitting the
//! whole file, so comments, key order, and unrelated settings survive an install. The
//! [`McpStyle`] decides how an entry is *shaped*; the [`ConfigFormat`] decides which parser
//! edits it. That split is why adding a harness is usually a registry row rather than a new
//! module.
//!
//! This module owns the format-agnostic pipeline; the serialization formats live in the
//! `json`, `toml`, and `yaml` submodules. Inspection and planning are deliberately separate:
//!
//! * [`inspect`] is tolerant — a broken file becomes [`EntryStatus::Unreadable`] so
//!   `akey agent status` can report on every harness and still exit 0.
//! * [`plan`] is strict — a broken file aborts the install *before* anything is written, so
//!   a multi-harness install can never be half-applied.

mod json;
mod toml;
mod yaml;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use super::registry::{ConfigFormat, Harness, McpStyle, Scope};
use crate::error::{Error, Result};
use crate::paths::{FILE_MODE, atomic_write};

/// Project files are checked into a repository, so they stay group/world readable.
const PROJECT_FILE_MODE: u32 = 0o644;

/// The MCP server name akey registers.
const SERVER_NAME: &str = "akey";
/// The command line every harness must end up running.
const ARGV: [&str; 2] = [SERVER_NAME, "mcp"];

/// What an existing MCP entry says, normalized across formats.
///
/// Only the fields akey owns are read. `env`, headers, and anything else a user added are
/// ignored when deciding whether the entry is already ours; `--force` replaces the entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EntryView {
    kind: Option<String>,
    argv: Vec<String>,
    enabled: Option<bool>,
    disabled: Option<bool>,
}

impl EntryView {
    fn is_akey(&self) -> bool {
        self.argv.len() == ARGV.len() && self.argv.iter().zip(ARGV).all(|(a, b)| a == b)
    }

    /// Why this entry is not the one akey would install; empty means it matches.
    fn problems(&self, style: McpStyle) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.is_akey() {
            problems.push(if self.argv.is_empty() {
                "has no command".to_string()
            } else {
                format!("runs `{}` instead of `akey mcp`", self.argv.join(" "))
            });
        }

        let expected_kind = match style {
            McpStyle::Claude | McpStyle::Plain => Some("stdio"),
            McpStyle::OpenCode => Some("local"),
            McpStyle::Codex | McpStyle::Hermes => None,
        };
        if let Some(expected) = expected_kind
            && let Some(actual) = self.kind.as_deref()
            && actual != expected
        {
            problems.push(format!("has `type` `{actual}` instead of `{expected}`"));
        }

        if matches!(style, McpStyle::Hermes | McpStyle::OpenCode) && self.enabled == Some(false) {
            problems.push("is disabled (`enabled: false`)".to_string());
        }
        if style == McpStyle::Plain && self.disabled == Some(true) {
            problems.push("is disabled (`disabled: true`)".to_string());
        }

        problems
    }
}

/// The state of the `akey` entry in one harness config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    /// No entry yet (or the file does not exist).
    Missing,
    /// An entry exists and points at `akey mcp`.
    Installed,
    /// An entry exists but is not the one akey owns.
    Conflict { detail: String },
    /// The file exists but cannot be read, parsed, or navigated safely.
    Unreadable { detail: String },
}

/// A read-only look at one harness config.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// The config file that would be read or written.
    pub path: PathBuf,
    /// Whether that file existed when inspected.
    pub exists: bool,
    pub status: EntryStatus,
}

/// What an install would do to one config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Added,
    Replaced,
    Unchanged,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Added => "added",
            Change::Replaced => "replaced",
            Change::Unchanged => "unchanged",
        }
    }
}

/// A planned config edit. Nothing is written until [`apply`] is called.
#[derive(Debug, Clone)]
pub struct Plan {
    pub path: PathBuf,
    pub change: Change,
    /// Bytes to write. Empty when `change` is [`Change::Unchanged`].
    pub contents: Vec<u8>,
    pub mode: u32,
    /// Whether the target file does not exist yet.
    pub creates: bool,
    /// What the conflicting entry said, when this plan replaces one.
    pub replaced_detail: Option<String>,
}

/// A rendered edit, before it is attributed to a path.
type Draft = (Change, Vec<u8>, Option<String>);

/// Inspect one harness config without failing on malformed user data.
pub fn inspect(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<Inspection> {
    let path = config_path(harness, scope, home, cwd)?;
    let exists = path.is_file();
    let status = match std::fs::read_to_string(&path) {
        Ok(text) => inspect_text(harness, &text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => EntryStatus::Missing,
        Err(err) => EntryStatus::Unreadable {
            detail: err.to_string(),
        },
    };
    Ok(Inspection {
        path,
        exists,
        status,
    })
}

/// Plan the edit that installs `akey mcp` into one harness config.
///
/// Returns [`Error::AgentConflict`] when a different entry already owns the `akey` name
/// and `force` is false, and [`Error::Corrupt`] when the existing file cannot be edited
/// safely. Nothing is written until the returned plan is applied.
pub fn plan(harness: &Harness, scope: Scope, home: &Path, cwd: &Path, force: bool) -> Result<Plan> {
    let path = config_path(harness, scope, home, cwd)?;
    let text = read_for_edit(&path)?;

    let draft = match harness.format {
        ConfigFormat::Json => json::draft(harness, &path, text.as_deref(), force)?,
        ConfigFormat::Toml => toml::draft(harness, &path, text.as_deref(), force)?,
        ConfigFormat::Yaml => yaml::draft(harness, &path, text.as_deref(), force)?,
    };

    Ok(Plan {
        path,
        change: draft.0,
        contents: draft.1,
        mode: file_mode(scope),
        creates: text.is_none(),
        replaced_detail: draft.2,
    })
}

/// Write a planned edit atomically. An unchanged plan is a no-op.
pub fn apply(plan: &Plan) -> Result<()> {
    if plan.change == Change::Unchanged {
        return Ok(());
    }
    atomic_write(&plan.path, &plan.contents, plan.mode)
}

// ---------------------------------------------------------------------------
// Removal
// ---------------------------------------------------------------------------

/// What an uninstall would do to one config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveChange {
    /// The `akey` entry is present and would be deleted.
    Removed,
    /// There is nothing to delete (missing file, or no `akey` entry).
    Missing,
}

impl RemoveChange {
    pub fn as_str(self) -> &'static str {
        match self {
            RemoveChange::Removed => "removed",
            RemoveChange::Missing => "missing",
        }
    }
}

/// A planned config removal. Nothing is written until [`apply_remove`] is called.
///
/// A config file is never deleted, even when the removal leaves it empty: it may hold
/// comments, a schema declaration, or settings this adapter does not understand.
#[derive(Debug, Clone)]
pub struct RemovePlan {
    pub path: PathBuf,
    pub change: RemoveChange,
    /// Bytes to write. Empty when `change` is [`RemoveChange::Missing`].
    pub contents: Vec<u8>,
    pub mode: u32,
    /// What the removed entry said, when it was not the one akey installs.
    pub removed_detail: Option<String>,
}

/// A rendered removal, before it is attributed to a path.
type RemoveDraft = (RemoveChange, Vec<u8>, Option<String>);

/// Plan the deletion of the `akey` entry from one harness config.
///
/// Absence is a no-op, not an error: uninstall is idempotent, and a harness may never have
/// been configured. A *different* entry named `akey` requires `force`, exactly like install,
/// so an unrelated server that happens to use the name is not deleted by accident. An
/// unreadable file aborts: deleting from a document akey cannot parse would be guesswork.
pub fn plan_remove(
    harness: &Harness,
    scope: Scope,
    home: &Path,
    cwd: &Path,
    force: bool,
) -> Result<RemovePlan> {
    let path = config_path(harness, scope, home, cwd)?;
    let mode = file_mode(scope);
    let Some(text) = read_for_edit(&path)? else {
        return Ok(RemovePlan::missing(path, mode));
    };
    if text.trim().is_empty() {
        return Ok(RemovePlan::missing(path, mode));
    }

    let draft = match harness.format {
        ConfigFormat::Json => json::remove(harness, &path, &text, force)?,
        ConfigFormat::Toml => toml::remove(harness, &path, &text, force)?,
        ConfigFormat::Yaml => yaml::remove(harness, &path, &text, force)?,
    };

    Ok(RemovePlan {
        path,
        change: draft.0,
        contents: draft.1,
        mode,
        removed_detail: draft.2,
    })
}

/// Write a planned removal atomically. A missing entry is a no-op.
pub fn apply_remove(plan: &RemovePlan) -> Result<()> {
    if plan.change == RemoveChange::Missing {
        return Ok(());
    }
    atomic_write(&plan.path, &plan.contents, plan.mode)
}

/// File mode for a planned write. User configs are private; project configs are committed.
fn file_mode(scope: Scope) -> u32 {
    match scope {
        Scope::User => FILE_MODE,
        Scope::Project => PROJECT_FILE_MODE,
    }
}

/// Read a file for a deliberate edit. A missing file is a new document, not an error.
fn read_for_edit(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::corrupt(format!(
            "cannot read {}: {err}",
            path.display()
        ))),
    }
}

impl RemovePlan {
    fn missing(path: PathBuf, mode: u32) -> Self {
        Self {
            path,
            change: RemoveChange::Missing,
            contents: Vec::new(),
            mode,
            removed_detail: None,
        }
    }
}

/// Allow a removal, or refuse one that would delete an entry akey does not own.
fn removal_guard(
    harness: &Harness,
    path: &Path,
    status: EntryStatus,
    force: bool,
) -> Result<Option<String>> {
    match status {
        EntryStatus::Installed => Ok(None),
        EntryStatus::Conflict { detail } => {
            if !force {
                return Err(Error::AgentConflict(format!(
                    "{} has a different `akey` MCP entry in {}: {}; \
                     rerun with `--force` to remove it",
                    harness.display,
                    path.display(),
                    detail
                )));
            }
            Ok(Some(detail))
        }
        // `classify` never returns these; a missing entry is handled by the caller and an
        // unreadable one by the parser before this point.
        EntryStatus::Missing => Ok(None),
        EntryStatus::Unreadable { detail } => Err(corrupt(path, detail)),
    }
}

/// A paste-ready fragment showing exactly what a fresh config would receive.
///
/// This is rendered through the same planner used for real installs, so the snippet cannot
/// drift from the bytes akey actually writes.
pub fn snippet(harness: &Harness) -> Result<String> {
    let path = Path::new("<config>");
    let draft = match harness.format {
        ConfigFormat::Json => json::draft(harness, path, None, false)?,
        ConfigFormat::Toml => toml::draft(harness, path, None, false)?,
        ConfigFormat::Yaml => yaml::draft(harness, path, None, false)?,
    };
    Ok(String::from_utf8_lossy(&draft.1).into_owned())
}

fn config_path(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<PathBuf> {
    harness.config_path(scope, home, cwd).ok_or_else(|| {
        Error::usage(format!(
            "{} does not support the {} scope",
            harness.display,
            scope.as_str()
        ))
    })
}

fn inspect_text(harness: &Harness, text: &str) -> EntryStatus {
    if text.trim().is_empty() {
        return EntryStatus::Missing;
    }
    match harness.format {
        ConfigFormat::Json => json::inspect(harness, text),
        ConfigFormat::Toml => toml::inspect(harness, text),
        ConfigFormat::Yaml => yaml::inspect(harness, text),
    }
}

// ---------------------------------------------------------------------------
// Shared decisions and helpers
// ---------------------------------------------------------------------------

fn classify(harness: &Harness, view: EntryView) -> EntryStatus {
    let problems = view.problems(harness.style);
    if problems.is_empty() {
        EntryStatus::Installed
    } else {
        EntryStatus::Conflict {
            detail: format!("`{}` {}", entry_pointer(harness), problems.join("; ")),
        }
    }
}

/// Same classification, but a file whose entry cannot be read safely aborts the plan.
fn classify_strict(harness: &Harness, path: &Path, view: EntryView) -> Result<EntryStatus> {
    if view.argv.is_empty() && view.kind.is_none() {
        return Err(corrupt(
            path,
            format!(
                "the `{}` entry is not a readable server object",
                entry_pointer(harness)
            ),
        ));
    }
    Ok(classify(harness, view))
}

fn entry_pointer(harness: &Harness) -> String {
    format!("{}.{SERVER_NAME}", harness.key)
}

fn decide(
    harness: &Harness,
    path: &Path,
    status: EntryStatus,
    force: bool,
) -> Result<(Change, Option<String>)> {
    match status {
        EntryStatus::Missing => Ok((Change::Added, None)),
        EntryStatus::Installed => Ok((Change::Unchanged, None)),
        EntryStatus::Conflict { detail } => {
            if !force {
                return Err(Error::AgentConflict(format!(
                    "{} already has a different `akey` MCP entry in {}: {}; \
                     rerun with `--force` to replace it",
                    harness.display,
                    path.display(),
                    detail
                )));
            }
            Ok((Change::Replaced, Some(detail)))
        }
        EntryStatus::Unreadable { detail } => Err(corrupt(path, detail)),
    }
}

fn unreadable(detail: impl Into<String>) -> EntryStatus {
    EntryStatus::Unreadable {
        detail: detail.into(),
    }
}

fn corrupt(path: &Path, detail: impl Into<String>) -> Error {
    Error::corrupt(format!("{}: {}", path.display(), detail.into()))
}

fn adapter_mismatch(harness: &Harness, style: McpStyle) -> Error {
    Error::corrupt(format!(
        "internal adapter mismatch: {} uses {:?} entries with a {:?} config",
        harness.id, style, harness.format
    ))
}

/// Normalize a rendered document to exactly one trailing newline.
fn finish(mut rendered: String) -> Vec<u8> {
    while rendered.ends_with('\n') {
        rendered.pop();
    }
    rendered.push('\n');
    rendered.into_bytes()
}

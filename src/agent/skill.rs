//! Skill installation: the agent-facing `SKILL.md` plus a managed-file sidecar.
//!
//! Every harness that supports skills gets the same document, but at its own root. The
//! sidecar (`.akey-managed`) records the hash akey wrote, which is what lets an update
//! tell "this is our older version" apart from "the user edited this". Without that
//! distinction, upgrading would either silently discard edits or refuse to ever update.
//!
//! The document is embedded at compile time, so an installed skill always describes the
//! binary that installed it rather than whatever happened to be checked out at build time.

use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::registry::{Harness, Scope};
use crate::error::{Error, Result};
use crate::paths::atomic_write;

/// Skills are documentation, not secrets; they stay world-readable like any other skill.
const SKILL_MODE: u32 = 0o644;

/// The skill body installed for every harness. Bumping the binary changes this string.
pub const BODY: &str = include_str!("../../SKILL.md");

const FILE_NAME: &str = "SKILL.md";
const SIDECAR_NAME: &str = ".akey-managed";

/// What is currently on disk for one harness skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillState {
    /// No `SKILL.md` at this root.
    Missing,
    /// The installed document is byte-identical to this binary's version.
    Current,
    /// akey installed it, but it belongs to an older version.
    Outdated { version: Option<String> },
    /// akey installed it and the user has edited it since.
    Modified { version: Option<String> },
    /// A `SKILL.md` exists that akey has no record of writing.
    Unmanaged,
    /// The file exists but cannot be read.
    Unreadable { detail: String },
}

/// What an install would do to one skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillChange {
    Installed,
    Updated,
    Replaced,
    Unchanged,
}

impl SkillChange {
    pub fn as_str(self) -> &'static str {
        match self {
            SkillChange::Installed => "installed",
            SkillChange::Updated => "updated",
            SkillChange::Replaced => "replaced",
            SkillChange::Unchanged => "unchanged",
        }
    }
}

/// A read-only look at one harness skill.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// Directory that holds the skill (`.../skills/akey`).
    pub dir: PathBuf,
    /// The `SKILL.md` inside it.
    pub path: PathBuf,
    pub state: SkillState,
}

/// A planned skill write. Each half is optional so repairing only the sidecar is possible.
#[derive(Debug, Clone)]
pub struct Plan {
    pub dir: PathBuf,
    pub path: PathBuf,
    pub record_path: PathBuf,
    pub change: SkillChange,
    /// New `SKILL.md` bytes, when the document itself changes.
    pub skill: Option<Vec<u8>>,
    /// New sidecar bytes, when tracking metadata changes.
    pub record: Option<Vec<u8>>,
    /// Why a modified or unmanaged file is being replaced.
    pub replaced_detail: Option<String>,
}

/// The sidecar format. `tool` is a guard: a sidecar written by something else is ignored.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    tool: String,
    version: String,
    sha256: String,
    installed_at: String,
}

/// Where the installed `SKILL.md` lives, whether or not it exists yet.
pub fn skill_path(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<PathBuf> {
    Ok(skill_dir(harness, scope, home, cwd)?.join(FILE_NAME))
}

/// Inspect one harness skill. Missing or unreadable files are reported, never raised.
pub fn inspect(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<Inspection> {
    let dir = skill_dir(harness, scope, home, cwd)?;
    let path = dir.join(FILE_NAME);
    let state = match std::fs::read(&path) {
        Ok(bytes) => classify(&dir, &bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => SkillState::Missing,
        Err(err) => SkillState::Unreadable {
            detail: err.to_string(),
        },
    };
    Ok(Inspection { dir, path, state })
}

/// Plan the skill write for one harness.
///
/// A modified or unmanaged document is an [`Error::AgentConflict`] unless `force` is set;
/// replacing it silently would destroy work akey did not create.
pub fn plan(harness: &Harness, scope: Scope, home: &Path, cwd: &Path, force: bool) -> Result<Plan> {
    let dir = skill_dir(harness, scope, home, cwd)?;
    let path = dir.join(FILE_NAME);
    let record_path = dir.join(SIDECAR_NAME);

    let existing = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(Error::corrupt(format!(
                "cannot read {}: {err}",
                path.display()
            )));
        }
    };

    let state = match &existing {
        Some(bytes) => classify(&dir, bytes),
        None => SkillState::Missing,
    };

    let (change, replaced_detail) = match state {
        SkillState::Missing => (SkillChange::Installed, None),
        SkillState::Current => (SkillChange::Unchanged, None),
        SkillState::Outdated { .. } => (SkillChange::Updated, None),
        SkillState::Modified { version } => {
            let detail = match version {
                Some(version) => format!(
                    "{} was edited after akey {version} installed it",
                    path.display()
                ),
                None => format!("{} was edited after akey installed it", path.display()),
            };
            guard(harness, detail, force)?
        }
        SkillState::Unmanaged => {
            let detail = format!(
                "{} already exists and was not installed by akey",
                path.display()
            );
            guard(harness, detail, force)?
        }
        SkillState::Unreadable { detail } => {
            return Err(Error::corrupt(format!("{}: {detail}", path.display())));
        }
    };

    if change == SkillChange::Unchanged {
        // Content is right; the sidecar may still be missing or stale (for example after a
        // hand-copied skill). Rewriting it costs one small file and makes future updates work.
        let record = match current_record(&record_path) {
            Some(record) => record_is_current(&record),
            None => false,
        };
        let record = if record {
            None
        } else {
            Some(render_record(&hash(BODY.as_bytes())))
        };
        return Ok(Plan {
            dir,
            path,
            record_path,
            change,
            skill: None,
            record,
            replaced_detail,
        });
    }

    let bytes = BODY.as_bytes().to_vec();
    Ok(Plan {
        dir,
        path,
        record_path,
        change,
        skill: Some(bytes.clone()),
        record: Some(render_record(&hash(&bytes))),
        replaced_detail,
    })
}

/// Apply a planned skill write. The document is written before its sidecar, so an
/// interrupted install leaves a recognizable file that the next run will simply rewrite.
pub fn apply(plan: &Plan) -> Result<()> {
    if let Some(bytes) = &plan.skill {
        atomic_write(&plan.path, bytes, SKILL_MODE)?;
    }
    if let Some(bytes) = &plan.record {
        atomic_write(&plan.record_path, bytes, SKILL_MODE)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Removal
// ---------------------------------------------------------------------------

/// What an uninstall would do to one harness skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveChange {
    /// `SKILL.md` (and any sidecar) would be deleted.
    Removed,
    /// Only a stale management sidecar would be deleted; the document was already gone.
    Cleaned,
    /// Nothing to delete.
    Missing,
}

impl RemoveChange {
    pub fn as_str(self) -> &'static str {
        match self {
            RemoveChange::Removed => "removed",
            RemoveChange::Cleaned => "cleaned",
            RemoveChange::Missing => "missing",
        }
    }
}

/// A planned skill removal. Nothing is deleted until [`apply_remove`] is called.
#[derive(Debug, Clone)]
pub struct RemovePlan {
    /// Directory that holds the skill (`.../skills/akey`).
    pub dir: PathBuf,
    pub path: PathBuf,
    pub record_path: PathBuf,
    pub change: RemoveChange,
    pub remove_skill: bool,
    pub remove_record: bool,
    /// Whether the directory is expected to be empty afterwards and can be deleted.
    pub remove_dir: bool,
    /// Why a modified or unmanaged file is being deleted.
    pub detail: Option<String>,
}

/// Plan the removal of one harness skill.
///
/// Absence is a no-op. A modified or unmanaged `SKILL.md` requires `force`, mirroring
/// install: akey must not delete a document it cannot prove it wrote. A sidecar is only
/// removed when it belongs to akey, so another tool's bookkeeping survives.
pub fn plan_remove(
    harness: &Harness,
    scope: Scope,
    home: &Path,
    cwd: &Path,
    force: bool,
) -> Result<RemovePlan> {
    let dir = skill_dir(harness, scope, home, cwd)?;
    let path = dir.join(FILE_NAME);
    let record_path = dir.join(SIDECAR_NAME);

    let existing = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(Error::corrupt(format!(
                "cannot read {}: {err}",
                path.display()
            )));
        }
    };
    let record = current_record(&record_path);

    let (change, remove_skill, detail) = match existing {
        None => match record {
            Some(_) => (RemoveChange::Cleaned, false, None),
            None => (RemoveChange::Missing, false, None),
        },
        Some(bytes) => {
            let detail = match classify(&dir, &bytes) {
                SkillState::Current | SkillState::Outdated { .. } => None,
                SkillState::Modified { version } => {
                    let detail = match version {
                        Some(version) => format!(
                            "{} was edited after akey {version} installed it",
                            path.display()
                        ),
                        None => format!("{} was edited after akey installed it", path.display()),
                    };
                    guard_remove(harness, detail, force)?
                }
                SkillState::Unmanaged => guard_remove(
                    harness,
                    format!(
                        "{} already exists and was not installed by akey",
                        path.display()
                    ),
                    force,
                )?,
                SkillState::Unreadable { detail } => {
                    return Err(Error::corrupt(format!("{}: {detail}", path.display())));
                }
                // `classify` only returns the states above once bytes were read.
                SkillState::Missing => None,
            };
            (RemoveChange::Removed, true, detail)
        }
    };

    let remove_record = record.is_some();
    let mut removed = Vec::new();
    if remove_skill {
        removed.push(path.clone());
    }
    if remove_record {
        removed.push(record_path.clone());
    }
    let remove_dir = !removed.is_empty() && will_be_empty(&dir, &removed);

    Ok(RemovePlan {
        dir,
        path,
        record_path,
        change,
        remove_skill,
        remove_record,
        remove_dir,
        detail,
    })
}

/// Apply a planned skill removal. Missing files are tolerated so a rerun after a partial
/// removal still finishes the job.
pub fn apply_remove(plan: &RemovePlan) -> Result<()> {
    for (enabled, path) in [
        (plan.remove_skill, &plan.path),
        (plan.remove_record, &plan.record_path),
    ] {
        if !enabled {
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(Error::corrupt(format!(
                    "cannot remove {}: {err}",
                    path.display()
                )));
            }
        }
    }

    if plan.remove_dir {
        // If another file appeared between planning and applying, the directory is not
        // empty; keeping it is harmless, so a failed rmdir is not an error.
        let _ = std::fs::remove_dir(&plan.dir);
    }
    Ok(())
}

/// Whether `dir` would contain nothing but the paths about to be deleted.
fn will_be_empty(dir: &Path, removed: &[PathBuf]) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .filter_map(|entry| entry.ok())
        .all(|entry| removed.iter().any(|path| path == &entry.path()))
}

fn guard_remove(harness: &Harness, detail: String, force: bool) -> Result<Option<String>> {
    if !force {
        return Err(Error::AgentConflict(format!(
            "{} skill conflict: {detail}; rerun with `--force` to remove it",
            harness.display
        )));
    }
    Ok(Some(detail))
}

fn skill_dir(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<PathBuf> {
    harness.skill_dir(scope, home, cwd).ok_or_else(|| {
        Error::usage(format!(
            "{} has no skill directory for the {} scope",
            harness.display,
            scope.as_str()
        ))
    })
}

fn classify(dir: &Path, bytes: &[u8]) -> SkillState {
    if bytes == BODY.as_bytes() {
        return SkillState::Current;
    }

    match current_record(&dir.join(SIDECAR_NAME)) {
        // akey wrote this exact content; it is an older version, not a user edit.
        Some(record) if record.sha256 == hash(bytes) => SkillState::Outdated {
            version: Some(record.version),
        },
        Some(record) => SkillState::Modified {
            version: Some(record.version),
        },
        None => SkillState::Unmanaged,
    }
}

fn current_record(path: &Path) -> Option<Record> {
    let text = std::fs::read_to_string(path).ok()?;
    let record: Record = serde_json::from_str(&text).ok()?;
    (record.tool == "akey").then_some(record)
}

fn record_is_current(record: &Record) -> bool {
    record.version == env!("CARGO_PKG_VERSION") && record.sha256 == hash(BODY.as_bytes())
}

fn render_record(sha256: &str) -> Vec<u8> {
    let record = Record {
        tool: "akey".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        sha256: sha256.to_string(),
        installed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let mut rendered =
        serde_json::to_string_pretty(&record).expect("the managed record is always serializable");
    rendered.push('\n');
    rendered.into_bytes()
}

fn hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn guard(harness: &Harness, detail: String, force: bool) -> Result<(SkillChange, Option<String>)> {
    if !force {
        return Err(Error::AgentConflict(format!(
            "{} skill conflict: {detail}; rerun with `--force` to replace it",
            harness.display
        )));
    }
    Ok((SkillChange::Replaced, Some(detail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::registry;

    fn harness(id: &str) -> &'static Harness {
        registry::resolve(id).unwrap()
    }

    fn install(harness: &Harness, home: &Path, cwd: &Path) -> Plan {
        let plan = plan(harness, Scope::User, home, cwd, false).unwrap();
        apply(&plan).unwrap();
        plan
    }

    #[test]
    fn install_then_inspect_is_current_and_idempotent() {
        for harness in registry::harnesses() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();

            let first = install(harness, home, temp.path());
            assert_eq!(first.change, SkillChange::Installed, "{}", harness.id);
            assert_eq!(
                std::fs::read(
                    home.join(harness.user_skills.unwrap())
                        .join("akey/SKILL.md")
                )
                .unwrap(),
                BODY.as_bytes(),
                "{}",
                harness.id
            );

            let inspected = inspect(harness, Scope::User, home, temp.path()).unwrap();
            assert_eq!(inspected.state, SkillState::Current, "{}", harness.id);

            let second = plan(harness, Scope::User, home, temp.path(), false).unwrap();
            assert_eq!(second.change, SkillChange::Unchanged, "{}", harness.id);
            assert!(second.skill.is_none() && second.record.is_none());
        }
    }

    #[test]
    fn edited_skill_requires_force_then_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let hermes = harness("hermes");
        install(hermes, home, temp.path());

        let path = home.join(".hermes/skills/akey/SKILL.md");
        std::fs::write(&path, "my local edits\n").unwrap();
        assert!(matches!(
            inspect(hermes, Scope::User, home, temp.path())
                .unwrap()
                .state,
            SkillState::Modified { .. }
        ));

        let err = plan(hermes, Scope::User, home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");

        let forced = plan(hermes, Scope::User, home, temp.path(), true).unwrap();
        assert_eq!(forced.change, SkillChange::Replaced);
        apply(&forced).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), BODY);
    }

    #[test]
    fn unmanaged_skill_is_not_overwritten_without_force() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let path = home.join(".claude/skills/akey/SKILL.md");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "---\nname: akey\n---\n# somebody else's\n").unwrap();

        assert_eq!(
            inspect(harness("claude"), Scope::User, home, temp.path())
                .unwrap()
                .state,
            SkillState::Unmanaged
        );
        assert!(matches!(
            plan(harness("claude"), Scope::User, home, temp.path(), false).unwrap_err(),
            Error::AgentConflict(_)
        ));

        let forced = plan(harness("claude"), Scope::User, home, temp.path(), true).unwrap();
        assert_eq!(forced.change, SkillChange::Replaced);
        apply(&forced).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), BODY);
    }

    #[test]
    fn older_managed_skill_is_updated_without_force() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let dir = home.join(".hermes/skills/akey");
        std::fs::create_dir_all(&dir).unwrap();
        let old = b"---\nname: akey\n---\n# older akey skill\n";
        std::fs::write(dir.join("SKILL.md"), old).unwrap();
        std::fs::write(
            dir.join(".akey-managed"),
            serde_json::json!({
                "tool": "akey",
                "version": "0.2.0",
                "sha256": hash(old),
                "installed_at": "2026-01-01T00:00:00Z"
            })
            .to_string(),
        )
        .unwrap();

        let state = inspect(harness("hermes"), Scope::User, home, temp.path())
            .unwrap()
            .state;
        assert_eq!(
            state,
            SkillState::Outdated {
                version: Some("0.2.0".into())
            }
        );

        let planned = plan(harness("hermes"), Scope::User, home, temp.path(), false).unwrap();
        assert_eq!(planned.change, SkillChange::Updated);
        apply(&planned).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("SKILL.md")).unwrap(), BODY);
    }

    #[test]
    fn copied_skill_gets_a_sidecar_without_rewriting_the_document() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let dir = home.join(".hermes/skills/akey");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), BODY).unwrap();

        let planned = plan(harness("hermes"), Scope::User, home, temp.path(), false).unwrap();
        assert_eq!(planned.change, SkillChange::Unchanged);
        assert!(planned.skill.is_none());
        assert!(planned.record.is_some());
        apply(&planned).unwrap();

        let record: Record =
            serde_json::from_str(&std::fs::read_to_string(dir.join(".akey-managed")).unwrap())
                .unwrap();
        assert_eq!(record.tool, "akey");
        assert_eq!(record.version, env!("CARGO_PKG_VERSION"));
    }

    fn remove_for(harness: &Harness, home: &Path, cwd: &Path, force: bool) -> Result<RemovePlan> {
        plan_remove(harness, Scope::User, home, cwd, force)
    }

    #[test]
    fn uninstall_removes_a_managed_skill_and_its_empty_directory() {
        for harness in registry::harnesses() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();
            install(harness, home, temp.path());

            let planned = remove_for(harness, home, temp.path(), false).unwrap();
            assert_eq!(planned.change, RemoveChange::Removed, "{}", harness.id);
            assert!(
                planned.remove_skill && planned.remove_record,
                "{}",
                harness.id
            );
            assert!(planned.remove_dir, "{}", harness.id);
            apply_remove(&planned).unwrap();

            assert!(!planned.path.exists(), "{}", harness.id);
            assert!(!planned.record_path.exists(), "{}", harness.id);
            assert!(!planned.dir.exists(), "{}", harness.id);
            assert_eq!(
                inspect(harness, Scope::User, home, temp.path())
                    .unwrap()
                    .state,
                SkillState::Missing,
                "{}",
                harness.id
            );

            let again = remove_for(harness, home, temp.path(), false).unwrap();
            assert_eq!(again.change, RemoveChange::Missing, "{}", harness.id);
            apply_remove(&again).unwrap();
        }
    }

    #[test]
    fn uninstall_requires_force_for_an_edited_skill() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let hermes = harness("hermes");
        install(hermes, home, temp.path());
        let path = home.join(".hermes/skills/akey/SKILL.md");
        std::fs::write(&path, "my edits\n").unwrap();

        let err = remove_for(hermes, home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");
        assert!(path.exists());

        let forced = remove_for(hermes, home, temp.path(), true).unwrap();
        assert_eq!(forced.change, RemoveChange::Removed);
        assert!(forced.detail.is_some());
        apply_remove(&forced).unwrap();
        assert!(!path.exists());
        assert!(!home.join(".hermes/skills/akey").exists());
    }

    #[test]
    fn uninstall_requires_force_for_an_unmanaged_skill_and_keeps_foreign_files() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let dir = home.join(".claude/skills/akey");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "# somebody else's\n").unwrap();
        std::fs::write(
            dir.join(".akey-managed"),
            r#"{"tool":"other","version":"1","sha256":"x","installed_at":"now"}"#,
        )
        .unwrap();

        let err = remove_for(harness("claude"), home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");

        let forced = remove_for(harness("claude"), home, temp.path(), true).unwrap();
        assert_eq!(forced.change, RemoveChange::Removed);
        assert!(forced.remove_skill);
        assert!(!forced.remove_record, "a foreign sidecar must survive");
        assert!(
            !forced.remove_dir,
            "the foreign sidecar keeps the dir alive"
        );
        apply_remove(&forced).unwrap();

        assert!(!dir.join("SKILL.md").exists());
        assert!(dir.join(".akey-managed").exists());
        assert!(dir.exists());
    }

    #[test]
    fn uninstall_cleans_an_orphan_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let dir = home.join(".agents/skills/akey");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".akey-managed"),
            serde_json::json!({
                "tool": "akey",
                "version": env!("CARGO_PKG_VERSION"),
                "sha256": hash(BODY.as_bytes()),
                "installed_at": "2026-01-01T00:00:00Z"
            })
            .to_string(),
        )
        .unwrap();

        let planned = remove_for(harness("codex"), home, temp.path(), false).unwrap();
        assert_eq!(planned.change, RemoveChange::Cleaned);
        assert!(!planned.remove_skill && planned.remove_record);
        assert!(planned.remove_dir);
        apply_remove(&planned).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn uninstall_keeps_a_directory_with_other_files() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let hermes = harness("hermes");
        install(hermes, home, temp.path());
        let dir = home.join(".hermes/skills/akey");
        std::fs::write(dir.join("notes.md"), "keep me\n").unwrap();

        let planned = remove_for(hermes, home, temp.path(), false).unwrap();
        assert!(!planned.remove_dir);
        apply_remove(&planned).unwrap();
        assert!(!dir.join("SKILL.md").exists());
        assert!(!dir.join(".akey-managed").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("notes.md")).unwrap(),
            "keep me\n"
        );
    }

    #[test]
    fn sidecar_from_another_tool_is_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let dir = home.join(".agents/skills/akey");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "# handwritten\n").unwrap();
        std::fs::write(
            dir.join(".akey-managed"),
            r#"{"tool":"other","version":"1","sha256":"x","installed_at":"now"}"#,
        )
        .unwrap();

        assert_eq!(
            inspect(harness("codex"), Scope::User, home, temp.path())
                .unwrap()
                .state,
            SkillState::Unmanaged
        );
    }
}

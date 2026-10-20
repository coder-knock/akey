//! Harness integration: one pipeline that installs akey into AI agent harnesses.
//!
//! The pipeline has four moving parts and this module owns the assembly:
//!
//! * [`registry`] answers **what harnesses exist and where their files live**.
//! * [`config`] answers **how one harness config is inspected, planned, and edited**.
//! * [`skill`] answers **how the agent-facing skill document is installed and versioned**.
//! * this module answers **which harnesses a command applies to, and how the write reaches
//!   the harness** — its own CLI when that is available, a structured config edit otherwise.
//!
//! Everything is planned before anything is applied. A malformed config or a hand-edited
//! skill therefore stops the whole install instead of leaving a half-configured machine;
//! because every writer is idempotent, rerunning after a failure is always safe.

pub mod config;
pub mod registry;
pub mod skill;

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;

use config::{Change, EntryStatus};
use registry::{Harness, harnesses, resolve};

pub use registry::{Only, Scope};
use skill::{SkillChange, SkillState};

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// The harnesses one command applies to.
///
/// `explicit` records whether the user named them. A default selection quietly skips
/// harnesses that cannot serve the requested scope; an explicit one turns that into an
/// error, because a user who typed `akey agent install codex --scope project` needs to
/// learn that Codex has no project scope, not silently get nothing.
pub struct Selection {
    harnesses: Vec<&'static Harness>,
    explicit: bool,
}

impl Selection {
    pub fn harnesses(&self) -> &[&'static Harness] {
        &self.harnesses
    }

    pub fn explicit(&self) -> bool {
        self.explicit
    }
}

/// Resolve agent names (empty = every harness, in registry order).
pub fn select(names: &[String]) -> crate::error::Result<Selection> {
    if names.is_empty() {
        return Ok(Selection {
            harnesses: harnesses().iter().collect(),
            explicit: false,
        });
    }

    let mut wanted = Vec::with_capacity(names.len());
    for name in names {
        let harness =
            resolve(name).ok_or_else(|| crate::error::Error::usage(unknown_agent(name)))?;
        if !wanted.iter().any(|h: &&'static Harness| h.id == harness.id) {
            wanted.push(harness);
        }
    }
    // Report in registry order so a multi-harness install reads the same way every time.
    let ordered = harnesses()
        .iter()
        .filter(|harness| wanted.iter().any(|w| w.id == harness.id))
        .collect();
    Ok(Selection {
        harnesses: ordered,
        explicit: true,
    })
}

fn unknown_agent(name: &str) -> String {
    crate::msg!(
        "unknown agent `{}`; supported agents: {}",
        "未知 agent `{}`；支持的 agent：{}",
        name,
        supported_ids()
    )
}

/// Comma-separated list of registered harness ids, for error messages.
pub fn supported_ids() -> String {
    harnesses()
        .iter()
        .map(|harness| harness.id)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Narrow a selection to the harnesses that can serve a scope, applying the explicit/default
/// rule described on [`Selection`].
fn scoped(
    selection: &Selection,
    scope: Scope,
    only: Only,
    home: &Path,
    cwd: &Path,
) -> crate::error::Result<Vec<&'static Harness>> {
    let mut targets = Vec::new();
    for &harness in &selection.harnesses {
        let has_scope = harness.supports(scope);
        let has_skill = !only.includes_skill() || harness.skill_dir(scope, home, cwd).is_some();
        if has_scope && has_skill {
            targets.push(harness);
            continue;
        }
        if selection.explicit {
            let reason = if !has_scope {
                crate::msg!(
                    "{} supports only the {} scope",
                    "{} 只支持 {} 范围",
                    harness.display,
                    harness.scopes_label()
                )
            } else {
                crate::msg!(
                    "{} has no skill directory for the {} scope",
                    "{} 在 {} 范围没有技能目录",
                    harness.display,
                    scope.as_str()
                )
            };
            return Err(crate::error::Error::usage(reason));
        }
    }
    if targets.is_empty() {
        return Err(crate::error::Error::usage(crate::msg!(
            "no selected harness supports the {} scope",
            "所选的 harness 都不支持 {} 范围",
            scope.as_str()
        )));
    }
    Ok(targets)
}

// ---------------------------------------------------------------------------
// Native delegation
// ---------------------------------------------------------------------------

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
    fn program(&self, harness: &Harness) -> Option<PathBuf> {
        match self {
            NativeMode::Disabled => None,
            NativeMode::Path(path) => registry::find_in_path_in(harness.native_cli, path),
            NativeMode::Auto if registry::native_disabled() => None,
            NativeMode::Auto => registry::find_in_path(harness.native_cli),
        }
    }
}

/// Which writer actually reaches the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Native,
    Config,
    None,
}

impl Via {
    fn as_str(self) -> &'static str {
        match self {
            Via::Native => "native",
            Via::Config => "config",
            Via::None => "none",
        }
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

pub struct InstallRequest<'a> {
    pub selection: &'a Selection,
    pub scope: Scope,
    pub only: Only,
    /// Replace a conflicting entry, or a skill the user has since edited.
    pub force: bool,
    pub dry_run: bool,
    pub native: NativeMode<'a>,
    pub home: &'a Path,
    pub cwd: &'a Path,
}

pub struct StatusRequest<'a> {
    pub selection: &'a Selection,
    pub scope: Scope,
    pub only: Only,
    pub native: NativeMode<'a>,
    pub home: &'a Path,
    pub cwd: &'a Path,
}

pub struct PrintRequest<'a> {
    pub selection: &'a Selection,
    pub scope: Scope,
    pub only: Only,
    pub home: &'a Path,
    pub cwd: &'a Path,
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct InstallReport {
    pub scope: &'static str,
    pub only: &'static str,
    pub dry_run: bool,
    /// Whether anything would change / did change.
    pub changed: bool,
    /// Distinct files written / to be written. A skill shared by two harnesses counts once.
    pub written: usize,
    pub harnesses: Vec<HarnessInstall>,
}

#[derive(Debug, Serialize)]
pub struct HarnessInstall {
    pub id: &'static str,
    pub name: &'static str,
    /// Files this harness's plan contributes. A skill shared by two harnesses is counted
    /// by both; [`InstallReport::written`] is the deduplicated total.
    pub written: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpInstall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<SkillInstall>,
}

#[derive(Debug, Serialize)]
pub struct McpInstall {
    pub path: PathBuf,
    pub change: &'static str,
    /// `native`, `config`, or `none`.
    pub via: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SkillInstall {
    pub path: PathBuf,
    pub change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub struct UninstallRequest<'a> {
    pub selection: &'a Selection,
    pub scope: Scope,
    pub only: Only,
    /// Delete an entry or skill akey did not install.
    pub force: bool,
    pub dry_run: bool,
    pub home: &'a Path,
    pub cwd: &'a Path,
}

#[derive(Debug, Serialize)]
pub struct UninstallReport {
    pub scope: &'static str,
    pub only: &'static str,
    pub dry_run: bool,
    /// Whether anything would be removed / was removed.
    pub changed: bool,
    /// Distinct files removed / to be removed. A skill shared by two harnesses counts once.
    pub removed: usize,
    pub harnesses: Vec<HarnessUninstall>,
}

#[derive(Debug, Serialize)]
pub struct HarnessUninstall {
    pub id: &'static str,
    pub name: &'static str,
    /// Files this harness's plan contributes. A shared skill is counted by both;
    /// [`UninstallReport::removed`] is the deduplicated total.
    pub removed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpUninstall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<SkillUninstall>,
}

#[derive(Debug, Serialize)]
pub struct McpUninstall {
    pub path: PathBuf,
    /// `removed` or `missing`.
    pub change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SkillUninstall {
    pub path: PathBuf,
    /// `removed`, `cleaned` (only a stale sidecar), or `missing`.
    pub change: &'static str,
    /// Whether the `.../skills/akey` directory is (or would be) deleted.
    pub removed_dir: bool,
    /// Other registered harnesses that read this same skill root. Removing the skill
    /// affects them too, even when they were not selected.
    pub shared_with: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub scope: &'static str,
    pub only: &'static str,
    pub home: PathBuf,
    pub cwd: PathBuf,
    /// Every selected artifact is in place and current.
    pub ready: bool,
    pub harnesses: Vec<HarnessStatus>,
}

#[derive(Debug, Serialize)]
pub struct HarnessStatus {
    pub id: &'static str,
    pub name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<SkillStatus>,
    pub native: NativeStatus,
}

#[derive(Debug, Serialize)]
pub struct McpStatus {
    pub path: PathBuf,
    pub exists: bool,
    /// `installed`, `missing`, `conflict`, or `unreadable`.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SkillStatus {
    pub path: PathBuf,
    /// `current`, `missing`, `outdated`, `modified`, `unmanaged`, or `unreadable`.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NativeStatus {
    pub command: &'static str,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct PrintReport {
    pub scope: &'static str,
    pub only: &'static str,
    pub harnesses: Vec<HarnessPrint>,
}

#[derive(Debug, Serialize)]
pub struct HarnessPrint {
    pub id: &'static str,
    pub name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpPrint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<SkillPrint>,
}

#[derive(Debug, Serialize)]
pub struct McpPrint {
    pub path: PathBuf,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct SkillPrint {
    pub path: PathBuf,
    pub contents: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ListReport {
    pub harnesses: Vec<HarnessInfo>,
}

#[derive(Debug, Serialize)]
pub struct HarnessInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub scopes: Vec<&'static str>,
    pub config_format: &'static str,
    pub user_config: &'static [&'static str],
    pub project_config: &'static [&'static str],
    pub user_skill: Option<&'static str>,
    pub project_skill: Option<&'static str>,
    /// Other harnesses that read the same user skill root.
    pub user_skill_shared_with: Vec<&'static str>,
    pub native_cli: &'static str,
    pub note: &'static str,
    pub docs: &'static str,
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// Describe every registered harness. Reads no files and never fails.
pub fn list() -> ListReport {
    let harnesses = harnesses()
        .iter()
        .map(|harness| HarnessInfo {
            id: harness.id,
            name: harness.display,
            aliases: harness.aliases,
            scopes: harness.scopes.iter().map(|scope| scope.as_str()).collect(),
            config_format: harness.format.as_str(),
            user_config: harness.user_config,
            project_config: harness.project_config,
            user_skill: harness.user_skills,
            project_skill: harness.project_skills,
            user_skill_shared_with: harnesses()
                .iter()
                .filter(|other| {
                    other.id != harness.id
                        && harness.user_skills.is_some()
                        && other.user_skills == harness.user_skills
                })
                .map(|other| other.id)
                .collect(),
            native_cli: harness.native_cli,
            note: harness.note,
            docs: harness.docs,
        })
        .collect();
    ListReport { harnesses }
}

impl ListReport {
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{}",
            crate::msg!(
                "{} supported harnesses",
                "支持 {} 个 harness",
                self.harnesses.len()
            )
        );
        for harness in &self.harnesses {
            let _ = writeln!(out);
            let _ = writeln!(out, "{} — {}", harness.id, harness.name);
            if !harness.aliases.is_empty() {
                let _ = writeln!(out, "  aliases  {}", harness.aliases.join(", "));
            }
            let _ = writeln!(out, "  scopes   {}", harness.scopes.join(", "));
            let _ = writeln!(
                out,
                "  mcp      {} [{}]",
                config_label(harness.user_config, harness.project_config),
                harness.config_format
            );
            let _ = writeln!(out, "  skill    {}", skill_label(harness));
            let _ = writeln!(out, "  native   {}", harness.native_cli);
            let _ = writeln!(out, "  note     {}", harness.note);
            if !harness.user_skill_shared_with.is_empty() {
                let _ = writeln!(
                    out,
                    "  shared   user skill with {}",
                    harness.user_skill_shared_with.join(", ")
                );
            }
        }
        let _ = writeln!(
            out,
            "\n{}",
            crate::msg!(
                "install with `akey agent install <agent>…` (or `--all`)",
                "用 `akey agent install <agent>…`（或 `--all`）安装"
            )
        );
        out
    }
}

fn config_label(user: &[&str], project: &[&str]) -> String {
    let mut parts = Vec::new();
    if let Some(first) = user.first() {
        parts.push(format!("~/{first}"));
    }
    for project_path in project {
        parts.push((*project_path).to_string());
    }
    parts.join(", ")
}

fn skill_label(harness: &HarnessInfo) -> String {
    let mut parts = Vec::new();
    if let Some(skill) = harness.user_skill {
        parts.push(format!("~/{skill}/akey"));
    }
    if let Some(skill) = harness.project_skill {
        parts.push(format!("{skill}/akey (project)"));
    }
    if parts.is_empty() {
        crate::msg!("none", "无").to_string()
    } else {
        parts.join(", ")
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// Inspect every selected harness. Never fails on bad user data: an unreadable config or an
/// unmanaged skill is a status, so `akey agent status` always reports on the whole set.
pub fn status(request: &StatusRequest<'_>) -> crate::error::Result<StatusReport> {
    let targets = scoped(
        request.selection,
        request.scope,
        request.only,
        request.home,
        request.cwd,
    )?;

    let mut ready = true;
    let mut rows = Vec::with_capacity(targets.len());
    for harness in targets {
        let mut row_ready = true;

        let mcp = if request.only.includes_mcp() {
            let inspection = config::inspect(harness, request.scope, request.home, request.cwd)?;
            let (status, detail) = entry_status(&inspection.status);
            row_ready &= status == "installed";
            Some(McpStatus {
                path: inspection.path,
                exists: inspection.exists,
                status,
                detail,
            })
        } else {
            None
        };

        let skill = if request.only.includes_skill() {
            let inspection = skill::inspect(harness, request.scope, request.home, request.cwd)?;
            let (status, version, detail) = skill_status(&inspection.state);
            row_ready &= status == "current";
            Some(SkillStatus {
                path: inspection.path,
                status,
                version,
                detail,
            })
        } else {
            None
        };

        let program = request.native.program(harness);
        rows.push(HarnessStatus {
            id: harness.id,
            name: harness.display,
            mcp,
            skill,
            native: NativeStatus {
                command: harness.native_cli,
                found: program.is_some(),
                path: program,
            },
        });
        ready &= row_ready;
    }

    Ok(StatusReport {
        scope: request.scope.as_str(),
        only: request.only.as_str(),
        home: request.home.to_path_buf(),
        cwd: request.cwd.to_path_buf(),
        ready,
        harnesses: rows,
    })
}

fn entry_status(status: &EntryStatus) -> (&'static str, Option<String>) {
    match status {
        EntryStatus::Missing => ("missing", None),
        EntryStatus::Installed => ("installed", None),
        EntryStatus::Conflict { detail } => ("conflict", Some(detail.clone())),
        EntryStatus::Unreadable { detail } => ("unreadable", Some(detail.clone())),
    }
}

fn skill_status(state: &SkillState) -> (&'static str, Option<String>, Option<String>) {
    match state {
        SkillState::Missing => ("missing", None, None),
        SkillState::Current => ("current", None, None),
        SkillState::Outdated { version } => ("outdated", version.clone(), None),
        SkillState::Modified { version } => ("modified", version.clone(), None),
        SkillState::Unmanaged => ("unmanaged", None, None),
        SkillState::Unreadable { detail } => ("unreadable", None, Some(detail.clone())),
    }
}

impl StatusReport {
    pub fn render(&self, home: &Path) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} {}  ({}, {})",
            self.scope,
            crate::msg!("scope", "范围"),
            display_path(&self.home, home),
            display_path(&self.cwd, home)
        );
        for row in &self.harnesses {
            let _ = writeln!(out);
            let _ = writeln!(out, "{} ({})", row.name, row.id);
            if let Some(mcp) = &row.mcp {
                let _ = writeln!(
                    out,
                    "  {:<8}{:<12}{}",
                    "mcp",
                    mcp.status,
                    display_path(&mcp.path, home)
                );
                if let Some(detail) = &mcp.detail {
                    let _ = writeln!(out, "          {detail}");
                }
            }
            if let Some(skill) = &row.skill {
                let _ = writeln!(
                    out,
                    "  {:<8}{:<12}{}",
                    "skill",
                    skill.status,
                    display_path(&skill.path, home)
                );
                if let Some(version) = &skill.version {
                    let _ = writeln!(
                        out,
                        "          {}",
                        crate::msg!("installed by akey {}", "由 akey {} 安装", version)
                    );
                }
                if let Some(detail) = &skill.detail {
                    let _ = writeln!(out, "          {detail}");
                }
            }
            let _ = writeln!(
                out,
                "  {:<8}{:<12}{}",
                "native",
                if row.native.found {
                    crate::msg!("found", "已找到")
                } else {
                    crate::msg!("missing", "未找到")
                },
                row.native
                    .path
                    .as_deref()
                    .map(|path| display_path(path, home))
                    .unwrap_or_else(|| row.native.command.to_string())
            );
        }

        let ready = self
            .harnesses
            .iter()
            .filter(|row| row_is_ready(row, self.only))
            .count();
        let _ = writeln!(
            out,
            "\n{}",
            if self.ready {
                crate::msg!(
                    "{}/{} harnesses ready",
                    "{}/{} 个 harness 已就绪",
                    ready,
                    self.harnesses.len()
                )
            } else {
                crate::msg!(
                    "{}/{} harnesses ready; run `akey agent install <agent>` to fix the rest",
                    "{}/{} 个 harness 已就绪；运行 `akey agent install <agent>` 修复其余",
                    ready,
                    self.harnesses.len()
                )
            }
        );
        out
    }
}

fn row_is_ready(row: &HarnessStatus, only: &str) -> bool {
    let mcp_ok = only == "skill" || row.mcp.as_ref().is_none_or(|mcp| mcp.status == "installed");
    let skill_ok = only == "mcp"
        || row
            .skill
            .as_ref()
            .is_none_or(|skill| skill.status == "current");
    mcp_ok && skill_ok
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

/// One harness's planned work: a config edit and/or a skill write.
struct HarnessPlan {
    harness: &'static Harness,
    mcp: Option<McpAction>,
    skill: Option<skill::Plan>,
}

struct McpAction {
    plan: config::Plan,
    via: Via,
    program: Option<PathBuf>,
}

impl HarnessPlan {
    fn written(&self) -> usize {
        let mcp =
            self.mcp
                .as_ref()
                .is_some_and(|action| action.plan.change != Change::Unchanged) as usize;
        let skill = self.skill.as_ref().map_or(0, |plan| {
            (plan.skill.is_some() as usize) + (plan.record.is_some() as usize)
        });
        mcp + skill
    }

    /// Collect every path this harness would write. The caller deduplicates: codex and
    /// OpenCode share one skill root, so the same `SKILL.md` can appear in two plans.
    fn collect_written(&self, paths: &mut BTreeSet<PathBuf>) {
        if let Some(action) = &self.mcp
            && action.plan.change != Change::Unchanged
        {
            paths.insert(action.plan.path.clone());
        }
        if let Some(plan) = &self.skill {
            if plan.skill.is_some() {
                paths.insert(plan.path.clone());
            }
            if plan.record.is_some() {
                paths.insert(plan.record_path.clone());
            }
        }
    }
}

/// Plan every selected harness, then apply. Nothing is written when any plan fails.
///
/// A failure mid-apply (for example a native CLI that dies on its second run) can leave
/// earlier harnesses installed; each writer is idempotent, so rerunning the same command
/// finishes the job.
pub fn install(request: &InstallRequest<'_>) -> crate::error::Result<InstallReport> {
    let targets = scoped(
        request.selection,
        request.scope,
        request.only,
        request.home,
        request.cwd,
    )?;

    let mut planned = Vec::with_capacity(targets.len());
    for harness in targets {
        planned.push(plan_harness(harness, request)?);
    }

    let mut changed = false;
    let mut files = BTreeSet::new();
    let mut rows = Vec::with_capacity(planned.len());
    for harness_plan in &planned {
        if !request.dry_run {
            apply_harness(harness_plan, request)?;
        }
        changed |= harness_plan.written() > 0;
        harness_plan.collect_written(&mut files);
        rows.push(install_row(harness_plan));
    }

    Ok(InstallReport {
        scope: request.scope.as_str(),
        only: request.only.as_str(),
        dry_run: request.dry_run,
        changed,
        written: files.len(),
        harnesses: rows,
    })
}

fn plan_harness(
    harness: &'static Harness,
    request: &InstallRequest<'_>,
) -> crate::error::Result<HarnessPlan> {
    let mcp = if request.only.includes_mcp() {
        Some(plan_mcp(harness, request)?)
    } else {
        None
    };
    let skill = if request.only.includes_skill() {
        Some(skill::plan(
            harness,
            request.scope,
            request.home,
            request.cwd,
            request.force,
        )?)
    } else {
        None
    };
    Ok(HarnessPlan {
        harness,
        mcp,
        skill,
    })
}

fn plan_mcp(
    harness: &'static Harness,
    request: &InstallRequest<'_>,
) -> crate::error::Result<McpAction> {
    let plan = config::plan(
        harness,
        request.scope,
        request.home,
        request.cwd,
        request.force,
    )?;
    let program = request.native.program(harness);
    // The harness CLI can only *create* an entry. Replacing one is done through the config
    // so the removal and the write are a single atomic file edit.
    let via = if plan.change == Change::Unchanged {
        Via::None
    } else if plan.change == Change::Added
        && program.is_some()
        && harness.native_args(request.scope).is_some()
    {
        Via::Native
    } else {
        Via::Config
    };
    Ok(McpAction { plan, via, program })
}

fn apply_harness(
    harness_plan: &HarnessPlan,
    request: &InstallRequest<'_>,
) -> crate::error::Result<()> {
    if let Some(action) = &harness_plan.mcp {
        match action.via {
            Via::None => {}
            Via::Config => config::apply(&action.plan)?,
            Via::Native => {
                let program = action
                    .program
                    .as_deref()
                    .expect("a native plan always carries the program it found");
                run_native(
                    harness_plan.harness,
                    request.scope,
                    request.cwd,
                    program,
                    &action.plan.path,
                )?;
                // The harness CLI is trusted, but not believed: some harnesses accept the
                // command and write nothing (or write a disabled server). Verifying here
                // turns that into one clear error instead of a mystery at runtime.
                let inspection = config::inspect(
                    harness_plan.harness,
                    request.scope,
                    request.home,
                    request.cwd,
                )?;
                if let Some(detail) = verify_failure(&inspection.status) {
                    return Err(crate::error::Error::harness(crate::msg!(
                        "`{}` exited successfully but {} still has no usable `akey` MCP entry: {}",
                        "`{}` 已成功退出，但 {} 中仍没有可用的 `akey` MCP 条目：{}",
                        harness_plan.harness.native_cli,
                        inspection.path.display(),
                        detail
                    )));
                }
            }
        }
    }
    if let Some(plan) = &harness_plan.skill {
        skill::apply(plan)?;
    }
    Ok(())
}

fn verify_failure(status: &EntryStatus) -> Option<String> {
    match status {
        EntryStatus::Installed => None,
        EntryStatus::Missing => {
            Some(crate::msg!("no `akey` entry was written", "没有写入 `akey` 条目").to_string())
        }
        EntryStatus::Conflict { detail } | EntryStatus::Unreadable { detail } => {
            Some(detail.clone())
        }
    }
}

fn run_native(
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
    if let Some(rest) = trimmed.lines().nth(3) {
        let _ = rest;
        lines.push_str("; …");
    }
    const MAX: usize = 400;
    if lines.chars().count() > MAX {
        lines = lines.chars().take(MAX).collect::<String>() + "…";
    }
    lines
}

fn install_row(harness_plan: &HarnessPlan) -> HarnessInstall {
    HarnessInstall {
        id: harness_plan.harness.id,
        name: harness_plan.harness.display,
        written: harness_plan.written(),
        mcp: harness_plan.mcp.as_ref().map(|action| McpInstall {
            path: action.plan.path.clone(),
            change: action.plan.change.as_str(),
            via: action.via.as_str(),
            detail: action.plan.replaced_detail.clone(),
        }),
        skill: harness_plan.skill.as_ref().map(|plan| SkillInstall {
            path: plan.path.clone(),
            change: plan.change.as_str(),
            detail: match (&plan.replaced_detail, plan.change, plan.record.is_some()) {
                (Some(detail), _, _) => Some(detail.clone()),
                (None, SkillChange::Unchanged, true) => {
                    Some(crate::msg!("sidecar refreshed", "刷新了管理记录").to_string())
                }
                _ => None,
            },
        }),
    }
}

impl InstallReport {
    pub fn render(&self, home: &Path) -> String {
        let mut out = String::new();
        if self.dry_run {
            let _ = writeln!(
                out,
                "{}",
                crate::msg!("dry run: nothing was written", "试运行：未写入任何文件")
            );
        }
        let mut touched = 0;
        for row in &self.harnesses {
            let _ = writeln!(out, "\n{} ({})", row.name, row.id);
            if let Some(mcp) = &row.mcp {
                let _ = writeln!(
                    out,
                    "  {:<8}{:<12}{}{}",
                    "mcp",
                    mcp.change,
                    display_path(&mcp.path, home),
                    match mcp.via {
                        "native" => format!("  ({})", mcp.via),
                        _ => String::new(),
                    }
                );
                if let Some(detail) = &mcp.detail {
                    let _ = writeln!(out, "          {detail}");
                }
            }
            if let Some(skill) = &row.skill {
                let _ = writeln!(
                    out,
                    "  {:<8}{:<12}{}",
                    "skill",
                    skill.change,
                    display_path(&skill.path, home)
                );
                if let Some(detail) = &skill.detail {
                    let _ = writeln!(out, "          {detail}");
                }
            }
            touched += usize::from(row.written > 0);
        }

        let summary = if self.written == 0 {
            crate::msg!(
                "nothing to do: every selected harness already matches",
                "无需改动：所选的 harness 都已配置"
            )
            .to_string()
        } else if self.dry_run {
            crate::msg!(
                "would write {} file(s) across {} harness(es)",
                "将写入 {} 个文件，涉及 {} 个 harness",
                self.written,
                touched
            )
        } else {
            crate::msg!(
                "wrote {} file(s) across {} harness(es)",
                "已写入 {} 个文件，涉及 {} 个 harness",
                self.written,
                touched
            )
        };
        let _ = writeln!(out, "\n{summary}");

        if self.written > 0 && !self.dry_run {
            let _ = writeln!(
                out,
                "{}",
                crate::msg!(
                    "note: harnesses launch `akey mcp`, so `akey` must stay on PATH",
                    "注意：harness 启动的是 `akey mcp`，所以 `akey` 必须保持在 PATH 上"
                )
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

/// One harness's planned removal: a config edit and/or a skill deletion.
struct HarnessRemoval {
    harness: &'static Harness,
    mcp: Option<config::RemovePlan>,
    skill: Option<skill::RemovePlan>,
}

impl HarnessRemoval {
    fn removed(&self) -> usize {
        let mcp = self
            .mcp
            .as_ref()
            .is_some_and(|plan| plan.change == config::RemoveChange::Removed)
            as usize;
        let skill = self.skill.as_ref().map_or(0, |plan| {
            (plan.remove_skill as usize) + (plan.remove_record as usize)
        });
        mcp + skill
    }

    /// Collect every path this harness would delete. Codex and OpenCode share one skill
    /// root, so the same `SKILL.md` can appear in two plans.
    fn collect_removed(&self, paths: &mut BTreeSet<PathBuf>) {
        if let Some(plan) = &self.mcp
            && plan.change == config::RemoveChange::Removed
        {
            paths.insert(plan.path.clone());
        }
        if let Some(plan) = &self.skill {
            if plan.remove_skill {
                paths.insert(plan.path.clone());
            }
            if plan.remove_record {
                paths.insert(plan.record_path.clone());
            }
        }
    }
}

/// Plan every selected harness, then remove. Nothing is deleted when any plan fails.
///
/// This is intentionally the mirror image of [`install`]: absence is a no-op so a rerun
/// finishes a partial uninstall, and a conflicting entry or an edited skill requires
/// `--force`. Config files are never deleted — only akey's entries inside them.
pub fn uninstall(request: &UninstallRequest<'_>) -> crate::error::Result<UninstallReport> {
    let targets = scoped(
        request.selection,
        request.scope,
        request.only,
        request.home,
        request.cwd,
    )?;

    let mut planned = Vec::with_capacity(targets.len());
    for harness in targets {
        planned.push(plan_uninstall(harness, request)?);
    }

    let mut changed = false;
    let mut files = BTreeSet::new();
    let mut rows = Vec::with_capacity(planned.len());
    for removal in &planned {
        if !request.dry_run {
            apply_uninstall(removal)?;
        }
        changed |= removal.removed() > 0;
        removal.collect_removed(&mut files);
        rows.push(uninstall_row(removal, request));
    }

    Ok(UninstallReport {
        scope: request.scope.as_str(),
        only: request.only.as_str(),
        dry_run: request.dry_run,
        changed,
        removed: files.len(),
        harnesses: rows,
    })
}

fn plan_uninstall(
    harness: &'static Harness,
    request: &UninstallRequest<'_>,
) -> crate::error::Result<HarnessRemoval> {
    let mcp = if request.only.includes_mcp() {
        Some(config::plan_remove(
            harness,
            request.scope,
            request.home,
            request.cwd,
            request.force,
        )?)
    } else {
        None
    };
    let skill = if request.only.includes_skill() {
        Some(skill::plan_remove(
            harness,
            request.scope,
            request.home,
            request.cwd,
            request.force,
        )?)
    } else {
        None
    };
    Ok(HarnessRemoval {
        harness,
        mcp,
        skill,
    })
}

fn apply_uninstall(removal: &HarnessRemoval) -> crate::error::Result<()> {
    if let Some(plan) = &removal.mcp {
        config::apply_remove(plan)?;
    }
    if let Some(plan) = &removal.skill {
        skill::apply_remove(plan)?;
    }
    Ok(())
}

fn uninstall_row(removal: &HarnessRemoval, request: &UninstallRequest<'_>) -> HarnessUninstall {
    let skill = removal.skill.as_ref().map(|plan| SkillUninstall {
        path: plan.path.clone(),
        change: plan.change.as_str(),
        removed_dir: plan.remove_dir,
        shared_with: if plan.remove_skill {
            skill_sharers(removal.harness, plan, request)
        } else {
            Vec::new()
        },
        detail: plan.detail.clone(),
    });
    HarnessUninstall {
        id: removal.harness.id,
        name: removal.harness.display,
        removed: removal.removed(),
        mcp: removal.mcp.as_ref().map(|plan| McpUninstall {
            path: plan.path.clone(),
            change: plan.change.as_str(),
            detail: plan.removed_detail.clone(),
        }),
        skill,
    }
}

/// Other registered harnesses that read the same skill root, whether or not they were
/// selected: deleting the shared document changes what they see.
fn skill_sharers(
    harness: &Harness,
    plan: &skill::RemovePlan,
    request: &UninstallRequest<'_>,
) -> Vec<&'static str> {
    harnesses()
        .iter()
        .filter(|other| other.id != harness.id)
        .filter(|other| {
            other
                .skill_dir(request.scope, request.home, request.cwd)
                .as_deref()
                == Some(plan.dir.as_path())
        })
        .map(|other| other.id)
        .collect()
}

impl UninstallReport {
    pub fn render(&self, home: &Path) -> String {
        let mut out = String::new();
        if self.dry_run {
            let _ = writeln!(
                out,
                "{}",
                crate::msg!("dry run: nothing was removed", "试运行：未删除任何文件")
            );
        }
        let mut touched = 0;
        let mut shared = false;
        for row in &self.harnesses {
            let _ = writeln!(out, "\n{} ({})", row.name, row.id);
            if let Some(mcp) = &row.mcp {
                let _ = writeln!(
                    out,
                    "  {:<8}{:<12}{}",
                    "mcp",
                    mcp.change,
                    display_path(&mcp.path, home)
                );
                if let Some(detail) = &mcp.detail {
                    let _ = writeln!(out, "          {detail}");
                }
            }
            if let Some(skill) = &row.skill {
                let _ = writeln!(
                    out,
                    "  {:<8}{:<12}{}",
                    "skill",
                    skill.change,
                    display_path(&skill.path, home)
                );
                if !skill.shared_with.is_empty() && skill.change == "removed" {
                    shared = true;
                    let names = skill
                        .shared_with
                        .iter()
                        .map(|id| resolve(id).map_or(*id, |harness| harness.display))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = writeln!(
                        out,
                        "          {}",
                        crate::msg!(
                            "shared with {}; the skill is removed for them too",
                            "与 {} 共享；它们也会失去该技能",
                            names
                        )
                    );
                }
                if let Some(detail) = &skill.detail {
                    let _ = writeln!(out, "          {detail}");
                }
            }
            touched += usize::from(row.removed > 0);
        }

        let summary = if self.removed == 0 {
            crate::msg!(
                "nothing to do: akey is not installed in the selected harnesses",
                "无需改动：所选的 harness 中没有安装 akey"
            )
            .to_string()
        } else if self.dry_run {
            crate::msg!(
                "would remove {} file(s) across {} harness(es)",
                "将删除 {} 个文件，涉及 {} 个 harness",
                self.removed,
                touched
            )
        } else {
            crate::msg!(
                "removed {} file(s) across {} harness(es)",
                "已删除 {} 个文件，涉及 {} 个 harness",
                self.removed,
                touched
            )
        };
        let _ = writeln!(out, "\n{summary}");

        if self.removed > 0 && !self.dry_run {
            let _ = writeln!(
                out,
                "{}",
                crate::msg!(
                    "note: restart the harness to drop the `akey` MCP server",
                    "注意：重启 harness 后 `akey` MCP 服务才会消失"
                )
            );
        }
        if shared && !self.dry_run {
            let _ = writeln!(
                out,
                "{}",
                crate::msg!(
                    "note: reinstall the skill for a harness that still needs it with `akey agent install <harness> --only skill`",
                    "注意：如需为其他 harness 恢复技能，请运行 `akey agent install <harness> --only skill`"
                )
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// print
// ---------------------------------------------------------------------------

/// Render the exact bytes an install would write, without touching anything.
///
/// This exists for machines where akey cannot write the harness config (containers, a
/// managed laptop): the output is produced by the same planner as a real install, so it
/// cannot drift from what `install` writes.
pub fn print(request: &PrintRequest<'_>) -> crate::error::Result<PrintReport> {
    let targets = scoped(
        request.selection,
        request.scope,
        request.only,
        request.home,
        request.cwd,
    )?;

    let mut rows = Vec::with_capacity(targets.len());
    for harness in targets {
        let mcp = if request.only.includes_mcp() {
            let path = harness
                .config_path(request.scope, request.home, request.cwd)
                .ok_or_else(|| {
                    crate::error::Error::usage(crate::msg!(
                        "{} has no config for the {} scope",
                        "{} 在 {} 范围没有配置文件",
                        harness.display,
                        request.scope.as_str()
                    ))
                })?;
            Some(McpPrint {
                path,
                snippet: config::snippet(harness)?,
            })
        } else {
            None
        };
        let skill = if request.only.includes_skill() {
            Some(
                skill::skill_path(harness, request.scope, request.home, request.cwd).map(
                    |path| SkillPrint {
                        path,
                        contents: skill::BODY,
                    },
                )?,
            )
        } else {
            None
        };
        rows.push(HarnessPrint {
            id: harness.id,
            name: harness.display,
            mcp,
            skill,
        });
    }

    Ok(PrintReport {
        scope: request.scope.as_str(),
        only: request.only.as_str(),
        harnesses: rows,
    })
}

impl PrintReport {
    pub fn render(&self, home: &Path) -> String {
        let mut out = String::new();
        // Several harnesses share one skill root (Codex and OpenCode both read
        // `~/.agents/skills`), so the document is printed once per path, not once per harness.
        let mut skills: Vec<(PathBuf, Vec<&'static str>, &'static str)> = Vec::new();
        for row in &self.harnesses {
            if let Some(mcp) = &row.mcp {
                let _ = writeln!(
                    out,
                    "{} ({}) — {}",
                    row.name,
                    self.scope,
                    display_path(&mcp.path, home)
                );
                out.push_str(&mcp.snippet);
                if !mcp.snippet.ends_with('\n') {
                    out.push('\n');
                }
                out.push('\n');
            }
            if let Some(skill) = &row.skill {
                match skills.iter_mut().find(|(path, _, _)| path == &skill.path) {
                    Some((_, names, _)) => names.push(row.name),
                    None => skills.push((skill.path.clone(), vec![row.name], skill.contents)),
                }
            }
        }
        for (path, names, contents) in &skills {
            let _ = writeln!(out, "{} — {}", names.join(", "), display_path(path, home));
            out.push_str(contents);
            if !contents.ends_with('\n') {
                out.push('\n');
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Render a path relative to the user home, so `agent` output is readable and portable.
fn display_path(path: &Path, home: &Path) -> String {
    if let Ok(rest) = path.strip_prefix(home)
        && !rest.as_os_str().is_empty()
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_string()).collect()
    }

    fn request<'a>(
        selection: &'a Selection,
        scope: Scope,
        only: Only,
        home: &'a Path,
        cwd: &'a Path,
        native: NativeMode<'a>,
    ) -> InstallRequest<'a> {
        InstallRequest {
            selection,
            scope,
            only,
            force: false,
            dry_run: false,
            native,
            home,
            cwd,
        }
    }

    #[test]
    fn an_empty_name_list_selects_every_harness_in_registry_order() {
        let selection = select(&[]).unwrap();
        assert!(!selection.explicit());
        assert_eq!(
            selection
                .harnesses()
                .iter()
                .map(|harness| harness.id)
                .collect::<Vec<_>>(),
            vec!["claude-code", "codex", "hermes", "opencode"]
        );
    }

    #[test]
    fn explicit_names_are_ordered_and_deduplicated() {
        let selection = select(&names(&["opencode", "claude", "OpenCode"])).unwrap();
        assert!(selection.explicit());
        assert_eq!(
            selection
                .harnesses()
                .iter()
                .map(|harness| harness.id)
                .collect::<Vec<_>>(),
            vec!["claude-code", "opencode"]
        );
        assert_eq!(
            select(&names(&["nope"]))
                .err()
                .expect("unknown agent must fail")
                .code(),
            "usage"
        );
    }

    #[test]
    fn a_default_selection_skips_harnesses_without_the_scope() {
        let temp = tempfile::tempdir().unwrap();
        let selection = select(&[]).unwrap();
        let targets = scoped(
            &selection,
            Scope::Project,
            Only::All,
            temp.path(),
            temp.path(),
        )
        .unwrap();
        assert_eq!(
            targets.iter().map(|harness| harness.id).collect::<Vec<_>>(),
            vec!["claude-code", "opencode"]
        );
    }

    #[test]
    fn an_explicit_selection_errors_on_a_missing_scope() {
        let temp = tempfile::tempdir().unwrap();
        let selection = select(&names(&["codex"])).unwrap();
        let error = scoped(
            &selection,
            Scope::Project,
            Only::All,
            temp.path(),
            temp.path(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "usage");
        assert!(error.to_string().contains("Codex"), "{error}");
    }

    #[test]
    fn status_reports_every_harness_and_never_fails_on_missing_files() {
        let temp = tempfile::tempdir().unwrap();
        let selection = select(&[]).unwrap();
        let report = status(&StatusRequest {
            selection: &selection,
            scope: Scope::User,
            only: Only::All,
            native: NativeMode::Disabled,
            home: temp.path(),
            cwd: temp.path(),
        })
        .unwrap();

        assert!(!report.ready);
        assert_eq!(report.harnesses.len(), 4);
        for row in &report.harnesses {
            assert_eq!(row.mcp.as_ref().unwrap().status, "missing");
            assert_eq!(row.skill.as_ref().unwrap().status, "missing");
            assert!(!row.native.found);
        }
    }

    #[test]
    fn list_reports_shared_skill_roots() {
        let report = list();
        let codex = report
            .harnesses
            .iter()
            .find(|harness| harness.id == "codex")
            .unwrap();
        assert_eq!(codex.user_skill_shared_with, vec!["opencode"]);
        let claude = report
            .harnesses
            .iter()
            .find(|harness| harness.id == "claude-code")
            .unwrap();
        assert!(claude.user_skill_shared_with.is_empty());
        assert_eq!(claude.scopes, vec!["user", "project"]);
    }

    #[test]
    fn installing_twice_changes_nothing_the_second_time() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["claude", "hermes"])).unwrap();

        let first = install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();
        assert!(first.changed);
        assert_eq!(first.harnesses[0].mcp.as_ref().unwrap().change, "added");
        assert_eq!(
            first.harnesses[0].skill.as_ref().unwrap().change,
            "installed"
        );

        let second = install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();
        assert!(!second.changed);
        for row in &second.harnesses {
            assert_eq!(row.written, 0);
            assert_eq!(row.mcp.as_ref().unwrap().change, "unchanged");
            assert_eq!(row.skill.as_ref().unwrap().change, "unchanged");
        }
    }

    #[test]
    fn a_shared_skill_is_counted_once_in_the_install_total() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["codex", "opencode"])).unwrap();

        let report = install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();

        // Codex config + shared SKILL.md + sidecar + OpenCode config. Both per-harness rows
        // claim the shared skill, but the total must report real files.
        assert_eq!(report.written, 4);
        assert_eq!(
            report
                .harnesses
                .iter()
                .map(|row| row.written)
                .sum::<usize>(),
            6
        );
        assert!(home.join(".agents/skills/akey/SKILL.md").is_file());
    }

    #[test]
    fn a_conflict_on_any_harness_stops_the_whole_install() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::write(
            home.join(".codex/config.toml"),
            "[mcp_servers.akey]\ncommand = \"other\"\n",
        )
        .unwrap();

        let selection = select(&names(&["claude", "codex"])).unwrap();
        let error = install(&request(
            &selection,
            Scope::User,
            Only::Mcp,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap_err();
        assert_eq!(error.code(), "conflict");
        assert!(error.to_string().contains("--force"), "{error}");
        // Claude was planned first but must not have been written.
        assert!(!home.join(".claude.json").exists());
    }

    #[test]
    fn force_replaces_a_conflicting_entry_through_the_config() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::write(
            home.join(".codex/config.toml"),
            "[mcp_servers.akey]\ncommand = \"other\"\n",
        )
        .unwrap();

        let selection = select(&names(&["codex"])).unwrap();
        let mut install_request = request(
            &selection,
            Scope::User,
            Only::Mcp,
            home,
            temp.path(),
            NativeMode::Disabled,
        );
        install_request.force = true;
        let report = install(&install_request).unwrap();
        assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().change, "replaced");
        assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().via, "config");
        let written = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(written.contains("command = \"akey\""), "{written}");
    }

    #[test]
    fn a_dry_run_plans_without_writing() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["claude"])).unwrap();
        let mut install_request = request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        );
        install_request.dry_run = true;
        let report = install(&install_request).unwrap();
        assert!(report.changed);
        assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().change, "added");
        assert!(!home.join(".claude.json").exists());
        assert!(!home.join(".claude/skills/akey/SKILL.md").exists());
        assert!(report.render(home).contains("dry run"));
    }

    fn uninstall_request<'a>(
        selection: &'a Selection,
        scope: Scope,
        only: Only,
        home: &'a Path,
        cwd: &'a Path,
    ) -> UninstallRequest<'a> {
        UninstallRequest {
            selection,
            scope,
            only,
            force: false,
            dry_run: false,
            home,
            cwd,
        }
    }

    #[test]
    fn uninstall_removes_everything_install_wrote_and_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["claude", "codex"])).unwrap();
        install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();

        let report = uninstall(&uninstall_request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
        ))
        .unwrap();
        assert!(report.changed);
        assert_eq!(report.removed, 6, "two configs + two skills + two sidecars");
        assert!(home.join(".claude.json").is_file());
        assert!(home.join(".codex/config.toml").is_file());
        assert!(!home.join(".claude/skills/akey").exists());
        assert!(!home.join(".agents/skills/akey").exists());
        for row in &report.harnesses {
            assert_eq!(row.removed, 3, "{}", row.id);
            assert_eq!(row.mcp.as_ref().unwrap().change, "removed");
            assert_eq!(row.skill.as_ref().unwrap().change, "removed");
        }

        let again = uninstall(&uninstall_request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
        ))
        .unwrap();
        assert!(!again.changed);
        assert_eq!(again.removed, 0);
        assert!(again.render(home).contains("nothing to do"));
    }

    #[test]
    fn uninstall_deduplicates_a_shared_skill_and_warns_about_it() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["codex", "opencode"])).unwrap();
        install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();

        let report = uninstall(&uninstall_request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
        ))
        .unwrap();
        assert_eq!(report.removed, 4, "two configs + one shared skill pair");
        assert_eq!(
            report
                .harnesses
                .iter()
                .map(|row| row.removed)
                .sum::<usize>(),
            6
        );
        let codex = report
            .harnesses
            .iter()
            .find(|row| row.id == "codex")
            .unwrap();
        assert_eq!(codex.skill.as_ref().unwrap().shared_with, vec!["opencode"]);

        let rendered = report.render(home);
        assert!(rendered.contains("shared with OpenCode"), "{rendered}");
        assert!(
            rendered.contains("the skill is removed for them too"),
            "{rendered}"
        );

        // On a rerun nothing is removed, so the shared-skill warning must not fire: it
        // would claim an impact that already happened.
        let again = uninstall(&uninstall_request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
        ))
        .unwrap();
        assert!(!again.changed);
        for row in &again.harnesses {
            assert!(
                row.skill.as_ref().unwrap().shared_with.is_empty(),
                "{}",
                row.id
            );
        }
        assert!(
            !again.render(home).contains("shared with"),
            "{}",
            again.render(home)
        );
    }

    #[test]
    fn a_conflict_on_any_harness_stops_the_whole_uninstall() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["claude", "codex"])).unwrap();
        install(&request(
            &selection,
            Scope::User,
            Only::Mcp,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();
        std::fs::write(
            home.join(".codex/config.toml"),
            "[mcp_servers.akey]\ncommand = \"other\"\n",
        )
        .unwrap();

        let error = uninstall(&uninstall_request(
            &selection,
            Scope::User,
            Only::Mcp,
            home,
            temp.path(),
        ))
        .unwrap_err();
        assert_eq!(error.code(), "conflict");
        // Claude was planned first but must not have been touched.
        let claude = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(claude.contains("\"akey\""), "{claude}");

        let mut forced = uninstall_request(&selection, Scope::User, Only::Mcp, home, temp.path());
        forced.force = true;
        let report = uninstall(&forced).unwrap();
        assert_eq!(report.removed, 2);
        let claude = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(!claude.contains("\"akey\""), "{claude}");
    }

    #[test]
    fn uninstall_dry_run_deletes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["claude"])).unwrap();
        install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();

        let mut uninstall_request =
            uninstall_request(&selection, Scope::User, Only::All, home, temp.path());
        uninstall_request.dry_run = true;
        let report = uninstall(&uninstall_request).unwrap();
        assert!(report.changed);
        assert_eq!(report.removed, 3);
        assert!(home.join(".claude.json").is_file());
        assert!(home.join(".claude/skills/akey/SKILL.md").is_file());
        let rendered = report.render(home);
        assert!(rendered.contains("dry run"), "{rendered}");
        assert!(rendered.contains("would remove 3 file(s)"), "{rendered}");
    }

    #[test]
    fn uninstall_can_remove_one_layer() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["claude"])).unwrap();
        install(&request(
            &selection,
            Scope::User,
            Only::All,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();

        let report = uninstall(&uninstall_request(
            &selection,
            Scope::User,
            Only::Mcp,
            home,
            temp.path(),
        ))
        .unwrap();
        assert_eq!(report.removed, 1);
        assert!(report.harnesses[0].skill.is_none());
        assert!(home.join(".claude/skills/akey/SKILL.md").is_file());
        let config = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(!config.contains("\"akey\""), "{config}");
    }

    #[test]
    fn printed_snippets_are_byte_identical_to_a_fresh_install() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let selection = select(&names(&["opencode"])).unwrap();

        install(&request(
            &selection,
            Scope::User,
            Only::Mcp,
            home,
            temp.path(),
            NativeMode::Disabled,
        ))
        .unwrap();
        let installed =
            std::fs::read_to_string(home.join(".config/opencode/opencode.json")).unwrap();

        let printed = print(&PrintRequest {
            selection: &selection,
            scope: Scope::User,
            only: Only::Mcp,
            home,
            cwd: temp.path(),
        })
        .unwrap();
        assert_eq!(
            printed.harnesses[0].mcp.as_ref().unwrap().snippet,
            installed
        );
        assert!(
            installed.contains("\"$schema\""),
            "a fresh OpenCode config carries its schema: {installed}"
        );
    }

    #[test]
    fn print_shares_one_skill_document_between_harnesses() {
        let temp = tempfile::tempdir().unwrap();
        let selection = select(&names(&["codex", "opencode"])).unwrap();
        let report = print(&PrintRequest {
            selection: &selection,
            scope: Scope::User,
            only: Only::Skill,
            home: temp.path(),
            cwd: temp.path(),
        })
        .unwrap();
        let rendered = report.render(temp.path());
        assert_eq!(
            rendered.matches("# akey").count(),
            1,
            "the shared skill body must be printed once:\n{rendered}"
        );
        assert!(rendered.contains("Codex, OpenCode"), "{rendered}");
    }

    #[cfg(unix)]
    mod native {
        use super::*;
        use std::os::unix::fs::PermissionsExt as _;

        fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
            path
        }

        #[test]
        fn a_harness_cli_is_preferred_when_it_can_write_the_entry() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            let target = home.join(".claude.json");
            script(
                &bin,
                "claude",
                &format!(
                    "#!/bin/sh\nprintf 'added to stderr\\n' >&2\ncat > '{}' <<'JSON'\n{{\"mcpServers\":{{\"akey\":{{\"command\":\"akey\",\"args\":[\"mcp\"]}}}}}}\nJSON\n",
                    target.display()
                ),
            );

            let selection = select(&names(&["claude"])).unwrap();
            let report = install(&request(
                &selection,
                Scope::User,
                Only::Mcp,
                &home,
                temp.path(),
                NativeMode::Path(bin.as_os_str()),
            ))
            .unwrap();

            let mcp = report.harnesses[0].mcp.as_ref().unwrap();
            assert_eq!(mcp.via, "native");
            assert_eq!(mcp.change, "added");
            assert!(target.is_file());
        }

        #[test]
        fn a_failing_harness_cli_is_a_harness_error_and_writes_nothing() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            script(&bin, "claude", "#!/bin/sh\necho 'nope' >&2\nexit 3\n");

            let selection = select(&names(&["claude"])).unwrap();
            let error = install(&request(
                &selection,
                Scope::User,
                Only::Mcp,
                &home,
                temp.path(),
                NativeMode::Path(bin.as_os_str()),
            ))
            .unwrap_err();

            assert_eq!(error.code(), "harness");
            assert_eq!(error.exit_code(), 1);
            assert!(error.to_string().contains("nope"), "{error}");
            assert!(!home.join(".claude.json").exists());
        }

        #[test]
        fn a_harness_cli_that_writes_nothing_is_not_believed() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            script(&bin, "claude", "#!/bin/sh\nexit 0\n");

            let selection = select(&names(&["claude"])).unwrap();
            let error = install(&request(
                &selection,
                Scope::User,
                Only::Mcp,
                &home,
                temp.path(),
                NativeMode::Path(bin.as_os_str()),
            ))
            .unwrap_err();

            assert_eq!(error.code(), "harness");
            assert!(
                error
                    .hint()
                    .is_some_and(|hint| hint.contains("--no-native")),
                "the hint must point at the recovery path: {error}"
            );
        }

        #[test]
        fn the_native_cli_is_not_used_to_replace_an_entry() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            let marker = temp.path().join("called");
            script(
                &bin,
                "claude",
                &format!("#!/bin/sh\n touch '{}'\n", marker.display()),
            );
            std::fs::write(
                home.join(".claude.json"),
                "{\"mcpServers\":{\"akey\":{\"command\":\"other\"}}}\n",
            )
            .unwrap();

            let selection = select(&names(&["claude"])).unwrap();
            let mut install_request = request(
                &selection,
                Scope::User,
                Only::Mcp,
                &home,
                temp.path(),
                NativeMode::Path(bin.as_os_str()),
            );
            install_request.force = true;
            let report = install(&install_request).unwrap();

            assert_eq!(report.harnesses[0].mcp.as_ref().unwrap().via, "config");
            assert!(!marker.exists(), "the harness CLI must not be invoked");
        }
    }
}

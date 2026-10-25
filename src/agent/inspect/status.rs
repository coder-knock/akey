//! `akey agent status`: inspect every selected harness without modifying it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::agent::config::{self, EntryStatus};
use crate::agent::display_path;
use crate::agent::native::NativeMode;
use crate::agent::registry::{Only, Scope};
use crate::agent::selection::{Selection, scoped};
use crate::agent::skill::{self, SkillState};

pub struct StatusRequest<'a> {
    pub selection: &'a Selection,
    pub scope: Scope,
    pub only: Only,
    pub native: NativeMode<'a>,
    pub home: &'a Path,
    pub cwd: &'a Path,
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
    /// `None` for config-only harnesses, which have no CLI akey can delegate to.
    pub command: Option<&'static str>,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
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
            if let Some(command) = row.native.command {
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
                        .unwrap_or_else(|| command.to_string())
                );
            }
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

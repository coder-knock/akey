//! Read-only harness inspection: `list`, `status`, and `print`.
//!
//! These commands never modify a harness. `status` is deliberately tolerant of bad user
//! data: an unreadable config or an unmanaged skill becomes a row, not a failed command,
//! so one broken harness cannot hide the state of the rest.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::config::{self, EntryStatus};
use super::display_path;
use super::native::NativeMode;
use super::registry::{Only, Scope, harnesses};
use super::selection::{Selection, scoped};
use super::skill::{self, SkillState};

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
    /// `None` when the harness is supported through config editing only.
    pub native_cli: Option<&'static str>,
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
            let native = harness.native_cli.map(str::to_string).unwrap_or_else(|| {
                crate::msg!("none (edits the config directly)", "无（直接编辑配置）")
            });
            let _ = writeln!(out, "  native   {native}");
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

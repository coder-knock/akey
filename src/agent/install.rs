//! The install pipeline: plan every selected harness, then apply.
//!
//! Planning is side-effect free. A malformed config or a hand-edited skill therefore
//! stops the whole run before the first byte is written. Applying can still fail midway
//! (for example a native CLI dies on its second invocation), but every writer is
//! idempotent, so rerunning the same command converges.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::config::{self, Change, EntryStatus};
use super::display_path;
use super::native::{NativeMode, run_native};
use super::registry::{Harness, Only, Scope};
use super::selection::{Selection, scoped};
use super::skill::{self, SkillChange};

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
                        harness_plan.harness.native_cli.unwrap_or("harness CLI"),
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

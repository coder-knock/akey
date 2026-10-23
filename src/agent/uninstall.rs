//! The uninstall pipeline: the mirror image of the install pipeline.
//!
//! Removal is narrow on purpose. It deletes akey's MCP entry and the skill akey wrote,
//! never the surrounding config file. Absence is a no-op, so a rerun finishes a partial
//! uninstall; a differing entry or a user-edited skill requires `--force`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::config;
use super::display_path;
use super::registry::{Harness, Only, Scope, harnesses, resolve};
use super::selection::{Selection, scoped};
use super::skill;

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
/// This is intentionally the mirror image of the install pipeline: absence is a no-op so a rerun
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

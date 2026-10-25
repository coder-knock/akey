//! `akey agent print`: render what an install would write, without writing it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::agent::config;
use crate::agent::display_path;
use crate::agent::registry::{Only, Scope};
use crate::agent::selection::{Selection, scoped};
use crate::agent::skill;

pub struct PrintRequest<'a> {
    pub selection: &'a Selection,
    pub scope: Scope,
    pub only: Only,
    pub home: &'a Path,
    pub cwd: &'a Path,
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

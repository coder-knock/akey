//! `akey agent list`: describe the registry without touching the filesystem.

use std::fmt::Write as _;

use serde::Serialize;

use crate::agent::registry::harnesses;

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

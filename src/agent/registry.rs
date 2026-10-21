//! The data-driven harness registry.
//!
//! A harness is **data**, not a trait object. Each row describes where the MCP entry and
//! the skill live, how the entry is shaped, and which native CLI (if any) can write it.
//! Adding a harness is therefore a registry row plus — for an unseen config shape — one
//! adapter arm in [`super::config`], not a new implementation of the whole install pipeline.
//!
//! Keeping this table plain also makes `akey agent list` honest: it reports exactly what
//! the binary knows how to do, with no hidden capability behind a dynamic loader.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Installation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope {
    /// Machine-wide, under the user's home directory.
    User,
    /// The current working directory (checked into a project).
    Project,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which artifacts a command should touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Only {
    All,
    Mcp,
    Skill,
}

impl Only {
    pub fn includes_mcp(self) -> bool {
        matches!(self, Only::All | Only::Mcp)
    }

    pub fn includes_skill(self) -> bool {
        matches!(self, Only::All | Only::Skill)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Only::All => "all",
            Only::Mcp => "mcp",
            Only::Skill => "skill",
        }
    }
}

/// The serialization format of a harness config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,
}

impl ConfigFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigFormat::Json => "json",
            ConfigFormat::Toml => "toml",
            ConfigFormat::Yaml => "yaml",
        }
    }
}

/// How an MCP server entry is shaped inside a config.
///
/// The style names the adapter, not the agent: Claude, Codex, Hermes, OpenCode and the
/// plain `command`/`args` hosts each have a distinct entry grammar, and a future harness
/// will usually reuse one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpStyle {
    Claude,
    Codex,
    Hermes,
    OpenCode,
    /// `{"command": "akey", "args": ["mcp"]}` with no `type` discriminator.
    ///
    /// Cursor, Kiro, and Devin all use the bare stdio shape that the wider MCP ecosystem
    /// standardized on. Some of them also accept `disabled: true`, which is read as a
    /// conflict because the entry would exist without ever running.
    Plain,
}

/// One supported AI agent harness.
#[derive(Debug)]
pub struct Harness {
    /// Stable identifier used on the command line and in JSON.
    pub id: &'static str,
    /// Human-readable name.
    pub display: &'static str,
    /// Accepted aliases, in addition to `id`.
    pub aliases: &'static [&'static str],
    /// Scopes the MCP entry can be installed at.
    pub scopes: &'static [Scope],
    /// User-scope config candidates, relative to the home directory.
    pub user_config: &'static [&'static str],
    /// Project-scope config candidates, relative to the working directory.
    pub project_config: &'static [&'static str],
    pub format: ConfigFormat,
    pub style: McpStyle,
    /// Top-level key that holds the server map.
    pub key: &'static str,
    /// `$schema` written into a fresh config, when the harness supports one.
    pub schema_url: Option<&'static str>,
    /// Skill root relative to the home directory.
    pub user_skills: Option<&'static str>,
    /// Skill root relative to the working directory.
    pub project_skills: Option<&'static str>,
    /// Native CLI that can write the MCP entry, when the harness ships one akey can drive.
    ///
    /// `None` means the harness is supported through structured config editing only; the
    /// install pipeline then never looks for an executable.
    pub native_cli: Option<&'static str>,
    /// Human note for `agent list`.
    pub note: &'static str,
    /// Section of the integration guide that documents this harness.
    pub docs: &'static str,
}

impl Harness {
    pub fn supports(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Every candidate config path for a scope, in preference order.
    pub fn config_candidates(&self, scope: Scope, home: &Path, cwd: &Path) -> Vec<PathBuf> {
        if !self.supports(scope) {
            return Vec::new();
        }
        let (base, relatives) = match scope {
            Scope::User => (home, self.user_config),
            Scope::Project => (cwd, self.project_config),
        };
        relatives.iter().map(|rel| base.join(rel)).collect()
    }

    /// The config path to read or write: the first existing candidate, else the preferred one.
    pub fn config_path(&self, scope: Scope, home: &Path, cwd: &Path) -> Option<PathBuf> {
        let candidates = self.config_candidates(scope, home, cwd);
        candidates
            .iter()
            .find(|path| path.is_file())
            .cloned()
            .or_else(|| candidates.into_iter().next())
    }

    /// Directory of the installed skill for a scope (`None` when the harness has no skill root there).
    pub fn skill_dir(&self, scope: Scope, home: &Path, cwd: &Path) -> Option<PathBuf> {
        let (base, rel) = match scope {
            Scope::User => (home, self.user_skills),
            Scope::Project => (cwd, self.project_skills),
        };
        Some(base.join(rel?).join("akey"))
    }

    /// Native command arguments, or `None` when this harness has no native writer for the scope.
    ///
    /// The registered command is always `akey`, never the path of the running executable:
    /// the harness launches it later, from its own environment, so the stable name is the
    /// only thing that keeps working. `akey` must therefore be on `PATH`.
    pub fn native_args(&self, scope: Scope) -> Option<Vec<&'static str>> {
        if !self.supports(scope) {
            return None;
        }
        match self.id {
            "claude-code" => Some(vec![
                "mcp",
                "add",
                "--scope",
                scope.as_str(),
                "akey",
                "--",
                "akey",
                "mcp",
            ]),
            "codex" => Some(vec!["mcp", "add", "akey", "--", "akey", "mcp"]),
            "hermes" => Some(vec![
                "mcp",
                "add",
                "akey",
                "--command",
                "akey",
                "--args",
                "mcp",
            ]),
            "opencode" => {
                let mut args = vec!["mcp", "add"];
                if scope == Scope::User {
                    args.push("--global");
                }
                args.extend(["akey", "--", "akey", "mcp"]);
                Some(args)
            }
            _ => None,
        }
    }

    pub fn scopes_label(&self) -> String {
        self.scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The registry, ordered by how likely a user is to ask for it.
static HARNESSES: &[Harness] = &[
    Harness {
        id: "claude-code",
        display: "Claude Code",
        aliases: &["claude", "cc"],
        scopes: &[Scope::User, Scope::Project],
        user_config: &[".claude.json"],
        project_config: &[".mcp.json"],
        format: ConfigFormat::Json,
        style: McpStyle::Claude,
        key: "mcpServers",
        schema_url: None,
        user_skills: Some(".claude/skills"),
        project_skills: Some(".claude/skills"),
        native_cli: Some("claude"),
        note: "user and project MCP configs",
        docs: "docs/AGENT-INTEGRATION.md#claude-code",
    },
    Harness {
        id: "codex",
        display: "Codex",
        aliases: &["codex-cli"],
        scopes: &[Scope::User],
        user_config: &[".codex/config.toml"],
        project_config: &[],
        format: ConfigFormat::Toml,
        style: McpStyle::Codex,
        key: "mcp_servers",
        schema_url: None,
        user_skills: Some(".agents/skills"),
        project_skills: None,
        native_cli: Some("codex"),
        note: "global config only",
        docs: "docs/AGENT-INTEGRATION.md#codex",
    },
    Harness {
        id: "cursor",
        display: "Cursor",
        aliases: &[],
        scopes: &[Scope::User, Scope::Project],
        user_config: &[".cursor/mcp.json"],
        project_config: &[".cursor/mcp.json"],
        format: ConfigFormat::Json,
        style: McpStyle::Plain,
        key: "mcpServers",
        schema_url: None,
        user_skills: Some(".cursor/skills"),
        project_skills: Some(".cursor/skills"),
        native_cli: None,
        note: "user and project MCP configs",
        docs: "docs/AGENT-INTEGRATION.md#cursor",
    },
    Harness {
        id: "hermes",
        display: "Hermes Agent",
        aliases: &["hermes-agent"],
        scopes: &[Scope::User],
        user_config: &[".hermes/config.yaml"],
        project_config: &[],
        format: ConfigFormat::Yaml,
        style: McpStyle::Hermes,
        key: "mcp_servers",
        schema_url: None,
        user_skills: Some(".hermes/skills"),
        project_skills: None,
        native_cli: Some("hermes"),
        note: "global config only",
        docs: "docs/AGENT-INTEGRATION.md#hermes-agent",
    },
    Harness {
        id: "opencode",
        display: "OpenCode",
        aliases: &["oc"],
        scopes: &[Scope::User, Scope::Project],
        // `opencode.jsonc` is the modern default; the plain variant is kept for older installs.
        user_config: &[
            ".config/opencode/opencode.json",
            ".config/opencode/opencode.jsonc",
        ],
        project_config: &["opencode.json", "opencode.jsonc", ".opencode/opencode.json"],
        format: ConfigFormat::Json,
        style: McpStyle::OpenCode,
        key: "mcp",
        schema_url: Some("https://opencode.ai/config.json"),
        user_skills: Some(".agents/skills"),
        project_skills: Some(".agents/skills"),
        native_cli: Some("opencode"),
        note: "user and project MCP configs",
        docs: "docs/AGENT-INTEGRATION.md#opencode",
    },
    Harness {
        id: "kiro",
        display: "Kiro",
        aliases: &[],
        scopes: &[Scope::User, Scope::Project],
        // Workspace config shadows the user file; both use the same nested settings path.
        user_config: &[".kiro/settings/mcp.json"],
        project_config: &[".kiro/settings/mcp.json"],
        format: ConfigFormat::Json,
        style: McpStyle::Plain,
        key: "mcpServers",
        schema_url: None,
        user_skills: Some(".kiro/skills"),
        project_skills: Some(".kiro/skills"),
        native_cli: None,
        note: "user and project MCP configs",
        docs: "docs/AGENT-INTEGRATION.md#kiro",
    },
    Harness {
        id: "devin",
        display: "Devin",
        aliases: &["devin-cli"],
        scopes: &[Scope::User, Scope::Project],
        // Devin CLI reads its user config from the XDG-style config directory. Windows
        // uses `%APPDATA%\devin` instead and is not covered by the current path model.
        user_config: &[".config/devin/mcp_config.json"],
        project_config: &[".devin/mcp_config.json"],
        format: ConfigFormat::Json,
        style: McpStyle::Plain,
        key: "mcpServers",
        schema_url: None,
        user_skills: Some(".config/devin/skills"),
        project_skills: Some(".devin/skills"),
        native_cli: None,
        note: "user and project MCP configs",
        docs: "docs/AGENT-INTEGRATION.md#devin",
    },
];

pub fn harnesses() -> &'static [Harness] {
    HARNESSES
}

/// Resolve an id, alias, display name, or underscore variant.
pub fn resolve(name: &str) -> Option<&'static Harness> {
    let normalized = name.trim().to_ascii_lowercase().replace('_', "-");
    HARNESSES.iter().find(|harness| {
        harness.id == normalized
            || harness.display.eq_ignore_ascii_case(name.trim())
            || harness.aliases.contains(&normalized.as_str())
    })
}

/// The real user home, which is where harness configs live.
///
/// This is deliberately **not** `ctx.paths.home`: that is akey's private directory
/// (`~/.config/akey`), while Claude Code keeps `~/.claude.json`, Codex keeps
/// `~/.codex/config.toml`, and so on. `AKEY_AGENT_HOME` overrides the root for tests and
/// unusual layouts.
pub fn user_home() -> Result<PathBuf> {
    if let Some(value) = non_empty_env("AKEY_AGENT_HOME") {
        return Ok(PathBuf::from(value));
    }

    #[cfg(windows)]
    {
        for key in ["USERPROFILE", "HOME"] {
            if let Some(value) = non_empty_env(key) {
                return Ok(PathBuf::from(value));
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(value) = non_empty_env("HOME") {
            return Ok(PathBuf::from(value));
        }
    }

    Err(Error::usage(crate::msg!(
        "cannot determine the user home directory; set $AKEY_AGENT_HOME or $HOME",
        "无法确定用户主目录；请设置 $AKEY_AGENT_HOME 或 $HOME"
    )))
}

fn non_empty_env(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

/// Whether native CLI delegation is disabled by the environment.
///
/// `AKEY_AGENT_NATIVE=off` is the test hook (and an escape hatch for locked-down
/// machines). The explicit flag wins only in the direction of disabling.
pub fn native_disabled() -> bool {
    non_empty_env("AKEY_AGENT_NATIVE").is_some_and(|value| {
        matches!(
            value.to_string_lossy().trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no"
        )
    })
}

/// Find an executable on `PATH`, honoring Windows executable extensions.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    find_in_path_in(name, &path)
}

/// Find an executable in an explicit `PATH` value.
///
/// Tests use this to point at a fake harness CLI without mutating the process environment,
/// which would race with the rest of the test suite.
pub fn find_in_path_in(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    let extensions: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ".com", ""]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(path) {
        for extension in extensions {
            let candidate = dir.join(format!("{name}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_harness_has_a_unique_id_and_alias() {
        let mut seen = std::collections::BTreeSet::new();
        for harness in harnesses() {
            assert!(seen.insert(harness.id), "duplicate id {}", harness.id);
            for alias in harness.aliases {
                assert!(seen.insert(*alias), "duplicate alias {alias}");
            }
        }
    }

    #[test]
    fn resolves_ids_aliases_and_underscore_variants() {
        assert_eq!(resolve("claude").unwrap().id, "claude-code");
        assert_eq!(resolve("Claude_Code").unwrap().id, "claude-code");
        assert_eq!(resolve("Hermes Agent").unwrap().id, "hermes");
        assert_eq!(resolve("hermes_agent").unwrap().id, "hermes");
        assert_eq!(resolve("codex").unwrap().id, "codex");
        assert_eq!(resolve("opencode").unwrap().id, "opencode");
        assert_eq!(resolve("cursor").unwrap().id, "cursor");
        assert_eq!(resolve("kiro").unwrap().id, "kiro");
        assert_eq!(resolve("devin-cli").unwrap().id, "devin");
        assert!(resolve("nope").is_none());
    }

    #[test]
    fn config_only_harnesses_have_no_native_writer() {
        for harness in harnesses() {
            for scope in harness.scopes {
                assert_eq!(
                    harness.native_cli.is_some(),
                    harness.native_args(*scope).is_some(),
                    "{} advertises a native CLI and a native writer inconsistently",
                    harness.id
                );
            }
        }
        for id in ["cursor", "kiro", "devin"] {
            let harness = resolve(id).unwrap();
            assert!(harness.native_cli.is_none(), "{id}");
        }
    }

    #[test]
    fn config_candidates_are_scope_relative() {
        let home = Path::new("/home/agent");
        let cwd = Path::new("/work/project");
        let claude = resolve("claude").unwrap();
        assert_eq!(
            claude.config_path(Scope::User, home, cwd).unwrap(),
            PathBuf::from("/home/agent/.claude.json")
        );
        assert_eq!(
            claude.config_path(Scope::Project, home, cwd).unwrap(),
            PathBuf::from("/work/project/.mcp.json")
        );

        let codex = resolve("codex").unwrap();
        assert!(codex.config_path(Scope::Project, home, cwd).is_none());
        assert!(codex.skill_dir(Scope::Project, home, cwd).is_none());

        let cursor = resolve("cursor").unwrap();
        assert_eq!(
            cursor.config_path(Scope::User, home, cwd).unwrap(),
            PathBuf::from("/home/agent/.cursor/mcp.json")
        );
        assert_eq!(
            cursor.config_path(Scope::Project, home, cwd).unwrap(),
            PathBuf::from("/work/project/.cursor/mcp.json")
        );

        let kiro = resolve("kiro").unwrap();
        assert_eq!(
            kiro.config_path(Scope::User, home, cwd).unwrap(),
            PathBuf::from("/home/agent/.kiro/settings/mcp.json")
        );
        assert_eq!(
            kiro.config_path(Scope::Project, home, cwd).unwrap(),
            PathBuf::from("/work/project/.kiro/settings/mcp.json")
        );

        let devin = resolve("devin").unwrap();
        assert_eq!(
            devin.config_path(Scope::User, home, cwd).unwrap(),
            PathBuf::from("/home/agent/.config/devin/mcp_config.json")
        );
        assert_eq!(
            devin.config_path(Scope::Project, home, cwd).unwrap(),
            PathBuf::from("/work/project/.devin/mcp_config.json")
        );
    }

    #[test]
    fn native_args_are_scope_aware() {
        let claude = resolve("claude").unwrap();
        assert_eq!(
            claude.native_args(Scope::User).unwrap(),
            vec!["mcp", "add", "--scope", "user", "akey", "--", "akey", "mcp"]
        );
        assert_eq!(
            claude.native_args(Scope::Project).unwrap(),
            vec![
                "mcp", "add", "--scope", "project", "akey", "--", "akey", "mcp"
            ]
        );

        let opencode = resolve("opencode").unwrap();
        assert_eq!(
            opencode.native_args(Scope::User).unwrap(),
            vec!["mcp", "add", "--global", "akey", "--", "akey", "mcp"]
        );
        assert_eq!(
            opencode.native_args(Scope::Project).unwrap(),
            vec!["mcp", "add", "akey", "--", "akey", "mcp"]
        );
    }

    #[test]
    fn codex_and_hermes_are_user_only() {
        for id in ["codex", "hermes"] {
            let harness = resolve(id).unwrap();
            assert_eq!(harness.scopes, &[Scope::User]);
            assert!(
                harness
                    .config_path(Scope::Project, Path::new("/h"), Path::new("/w"))
                    .is_none()
            );
            assert!(harness.native_args(Scope::Project).is_none());
        }
    }

    #[test]
    fn skill_roots_are_where_the_harnesses_look() {
        let home = Path::new("/home/agent");
        let cwd = Path::new("/work/project");
        assert_eq!(
            resolve("claude")
                .unwrap()
                .skill_dir(Scope::User, home, cwd)
                .unwrap(),
            PathBuf::from("/home/agent/.claude/skills/akey")
        );
        assert_eq!(
            resolve("hermes")
                .unwrap()
                .skill_dir(Scope::User, home, cwd)
                .unwrap(),
            PathBuf::from("/home/agent/.hermes/skills/akey")
        );
        assert_eq!(
            resolve("codex")
                .unwrap()
                .skill_dir(Scope::User, home, cwd)
                .unwrap(),
            PathBuf::from("/home/agent/.agents/skills/akey")
        );
        assert_eq!(
            resolve("opencode")
                .unwrap()
                .skill_dir(Scope::Project, home, cwd)
                .unwrap(),
            PathBuf::from("/work/project/.agents/skills/akey")
        );
        assert_eq!(
            resolve("cursor")
                .unwrap()
                .skill_dir(Scope::User, home, cwd)
                .unwrap(),
            PathBuf::from("/home/agent/.cursor/skills/akey")
        );
        assert_eq!(
            resolve("kiro")
                .unwrap()
                .skill_dir(Scope::Project, home, cwd)
                .unwrap(),
            PathBuf::from("/work/project/.kiro/skills/akey")
        );
        assert_eq!(
            resolve("devin")
                .unwrap()
                .skill_dir(Scope::User, home, cwd)
                .unwrap(),
            PathBuf::from("/home/agent/.config/devin/skills/akey")
        );
        assert_eq!(
            resolve("devin")
                .unwrap()
                .skill_dir(Scope::Project, home, cwd)
                .unwrap(),
            PathBuf::from("/work/project/.devin/skills/akey")
        );
    }
}

//! `$AKEY_HOME/config.toml` —— 本机私有配置，绝不同步。

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths::{self, Paths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// 同步仓库的工作区路径（绝对路径），密文与 `recipients.json` 都在这里。
    pub repo: PathBuf,
    /// git 远端 URL；`None` = 纯本地库。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// 本机设备名，出现在 `recipients.json` 与审计日志中。
    pub device_name: String,
    /// 本机是否允许 `--reveal`。为 false 时即便条目允许也拒绝（退出码 7）。
    #[serde(default = "default_true")]
    pub reveal_allowed: bool,
    pub created_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Config> {
        if !paths.has_config() {
            return Err(Error::locked(format!(
                "no config at {}; run `akey init`",
                paths.config.display()
            )));
        }
        paths::ensure_private(&paths.config)?;
        let raw = std::fs::read_to_string(&paths.config)?;
        let mut config: Config = toml::from_str(&raw)
            .map_err(|e| Error::Corrupt(format!("{}: {e}", paths.config.display())))?;
        config.repo = expand_home(&config.repo);
        Ok(config)
    }

    /// 未初始化时返回 `None`，用于区分"没配过"与"配坏了"。
    pub fn try_load(paths: &Paths) -> Result<Option<Config>> {
        if paths.has_config() {
            Config::load(paths).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        paths.ensure()?;
        let rendered = toml::to_string_pretty(self)
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        paths::atomic_write(&paths.config, rendered.as_bytes(), paths::FILE_MODE)
    }

    /// 把 `~` 展开到 `$HOME`，并相对当前目录补齐为绝对路径。
    pub fn normalise_repo(raw: &Path) -> Result<PathBuf> {
        let expanded = expand_home(raw);
        if expanded.is_absolute() {
            Ok(expanded)
        } else {
            let cwd = std::env::current_dir()?;
            Ok(cwd.join(expanded))
        }
    }
}

fn expand_home(path: &Path) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path.to_path_buf();
    };
    if (raw == "~" || raw.starts_with("~/"))
        && let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty())
    {
        let rest = raw.strip_prefix("~/").unwrap_or("");
        return PathBuf::from(home).join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        paths.ensure().unwrap();
        (dir, paths)
    }

    fn sample() -> Config {
        Config {
            repo: PathBuf::from("/tmp/vault-repo"),
            remote: Some("git@github.com:me/akey-vault.git".into()),
            device_name: "macbook".into(),
            reveal_allowed: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn round_trips_through_disk_with_private_permissions() {
        let (_guard, paths) = setup();
        let config = sample();
        config.save(&paths).unwrap();

        let back = Config::load(&paths).unwrap();
        assert_eq!(back, config);

        let mode = std::fs::metadata(&paths.config).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, paths::FILE_MODE);
    }

    #[test]
    fn missing_config_is_locked_with_init_hint() {
        let (_guard, paths) = setup();
        let err = Config::load(&paths).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("akey init"));
        assert!(Config::try_load(&paths).unwrap().is_none());
    }

    #[test]
    fn remote_defaults_to_absent_and_reveal_defaults_to_allowed() {
        let (_guard, paths) = setup();
        let rendered = "repo = \"/tmp/r\"\ndevice_name = \"d\"\ncreated_at = \"2026-09-19T00:00:00Z\"\n";
        std::fs::write(&paths.config, rendered).unwrap();
        std::fs::set_permissions(
            &paths.config,
            std::fs::Permissions::from_mode(paths::FILE_MODE),
        )
        .unwrap();

        let config = Config::load(&paths).unwrap();
        assert!(config.remote.is_none());
        assert!(config.reveal_allowed);
    }

    #[test]
    fn relative_repo_paths_become_absolute() {
        let resolved = Config::normalise_repo(Path::new("vault-repo")).unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("vault-repo"));
    }

    #[test]
    fn corrupt_toml_is_reported_as_corrupt_not_locked() {
        let (_guard, paths) = setup();
        std::fs::write(&paths.config, b"this is not = = toml").unwrap();
        std::fs::set_permissions(
            &paths.config,
            std::fs::Permissions::from_mode(paths::FILE_MODE),
        )
        .unwrap();

        let err = Config::load(&paths).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)));
        assert_eq!(err.exit_code(), 1);
    }
}

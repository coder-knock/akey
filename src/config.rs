//! `$AKEY_HOME/config.toml` — machine-local private config, never synced.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths::{self, Paths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Workspace path of the sync repo (absolute); ciphertext and `recipients.json` live here.
    pub repo: PathBuf,
    /// git remote URL; `None` = purely local vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// This machine's device name, appearing in `recipients.json` and the audit log.
    pub device_name: String,
    /// This machine's **approved** recipient public keys → approval time.
    ///
    /// This is local policy, **never stored in the repo**. `recipients.json` says "who exists"
    /// (the remote can stuff people in); this set says "who is allowed to decrypt" (the remote
    /// cannot stuff anyone in). `encrypt_to` intersects the two.
    ///
    /// Why it exists: anyone who can write the remote can add their own public key to
    /// `recipients.json`, and the next legitimate write re-encrypts "to all active recipients" —
    /// which hands the entire vault (including history) to the attacker. With this set, the
    /// attacker's key only ever shows up in the directory and never receives ciphertext.
    #[serde(default)]
    pub trusted: BTreeMap<String, DateTime<Utc>>,

    /// Upgrade marker for old configs that lack the `trusted` field.
    ///
    /// Its only reason to exist is to avoid conflating "never initialized" with "explicitly
    /// approved zero recipients" — the latter is a valid state (trust nobody), and must not be
    /// used to seed.
    #[serde(default)]
    pub trust_seeded: bool,

    pub created_at: DateTime<Utc>,
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

    /// Returns `None` when uninitialized, distinguishing "never configured" from "configured but broken".
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

    /// Expands `~` to `$HOME` and resolves against the current directory to an absolute path.
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
    /// Write a config the way `Config::save` does. On unix the mode matters: `Config::load`
    /// refuses a config other users could read, and `fs::write` alone would create a `0644` one.
    fn write_config(paths: &Paths, data: &str) {
        std::fs::write(&paths.config, data).unwrap();
        #[cfg(unix)]
        {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &paths.config,
                std::fs::Permissions::from_mode(paths::FILE_MODE),
            )
            .unwrap();
        }
    }

    use super::*;
    use crate::paths::Paths;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        paths.ensure().unwrap();
        (dir, paths)
    }

    /// Only the unix-only permission test needs a fully-populated config to round-trip.
    #[cfg(unix)]
    fn sample() -> Config {
        Config {
            repo: PathBuf::from("/tmp/vault-repo"),
            remote: Some("git@github.com:me/akey-vault.git".into()),
            device_name: "macbook".into(),
            trusted: BTreeMap::new(),
            trust_seeded: true,
            created_at: Utc::now(),
        }
    }

    /// The assertion *is* the mode bits, and Windows has none. The profile-location guard
    /// that replaces it there is covered by `paths::profile_containment_*`.
    #[cfg(unix)]
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
        write_config(&paths, rendered);

        let config = Config::load(&paths).unwrap();
        assert!(config.remote.is_none());
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
        write_config(&paths, "this is not = = toml");

        let err = Config::load(&paths).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)));
        assert_eq!(err.exit_code(), 1);
    }
}

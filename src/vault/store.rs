//! Vault storage: encryption/decryption orchestration, atomic writes, file locks.
//!
//! The layer above (`cmd`) talks only to this module and must not touch `crypto` or the
//! repository files directly.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::config::Config;
use crate::crypto::{DeviceIdentity, encrypt_to};
use crate::error::{Error, Result};
use crate::paths::{self, Paths};
use crate::vault::model::{FORMAT_VERSION, Vault};
use crate::vault::recipients::Recipients;

/// The fixed file names inside the sync repository.
pub const VAULT_FILE: &str = "vault.age";
pub const RECOVERY_FILE: &str = "recovery.age";
pub const RECIPIENTS_FILE: &str = "recipients.json";
pub const AGENTS_FILE: &str = "AGENTS.md";

/// The **whitelist** of files that get committed to the sync repository.
///
/// Why not `git add -A`: that would commit **anything** that lands in the repository
/// directory. One slip — a user or script writing plaintext there (`akey inject -o
/// repo/x.txt` is enough) — and a single `sync` writes it permanently into git history and
/// pushes it to the remote, and git history cannot be scrubbed clean. Adding only known
/// files keeps such a mistake local.
pub const SYNCED_FILES: &[&str] = &[
    VAULT_FILE,
    RECIPIENTS_FILE,
    RECOVERY_FILE,
    AGENTS_FILE,
    ".gitignore",
];

/// An unlocked local view: this device's identity + config + repository location.
pub struct Store {
    pub paths: Paths,
    pub config: Config,
    pub identity: DeviceIdentity,
}

impl Store {
    /// Open the local context. Missing config or identity → `Locked` (exit code 4).
    pub fn open(paths: Paths) -> Result<Store> {
        let config = Config::load(&paths)?;
        let identity = DeviceIdentity::load(&paths.identity, config.device_name.clone())?;
        let mut store = Store {
            paths,
            config,
            identity,
        };
        if !store.config.trust_seeded {
            // Upgrade path: an old config has no trust set. Seed it once from the
            // **current** recipients and say so out loud — if someone has already pushed a
            // public key to the remote, the user at least sees whom they just approved.
            let adopted = store.seed_trust(Utc::now())?;
            if adopted > 0 {
                eprintln!(
                    "warning: this config predates the local trust set; adopted {adopted} existing \
                     recipient(s). Run `akey doctor` to review them."
                );
            }
        }
        Ok(store)
    }

    /// The recipient public keys this device has approved.
    pub fn trusted(&self) -> &std::collections::BTreeMap<String, DateTime<Utc>> {
        &self.config.trusted
    }

    /// Active public keys in `recipients.json` that this device has not approved yet, as
    /// `(name, pubkey)`.
    ///
    /// They are **never encrypted to**. An agent / human should see them in the output of
    /// `sync` or `doctor`.
    pub fn pending_recipients(&self) -> Result<Vec<(String, String)>> {
        let all = self.load_recipients()?;
        Ok(all
            .recipients
            .iter()
            .filter(|(key, record)| record.is_active() && !self.config.trusted.contains_key(*key))
            .map(|(key, record)| (record.name.clone(), key.clone()))
            .collect())
    }

    /// Narrow a recipient list down to those **this device approved**.
    ///
    /// This is the plug for A1: whoever can write the remote can push a public key into
    /// `recipients.json`, but they cannot push it into this device's `config.toml`, so no
    /// encryption ever hands them ciphertext.
    pub fn filter_trusted(&self, recipients: &Recipients) -> Recipients {
        let mut allowed = Recipients::default();
        for (key, record) in &recipients.recipients {
            if record.is_active() && self.config.trusted.contains_key(key) {
                allowed.recipients.insert(key.clone(), record.clone());
            }
        }
        allowed
    }

    /// Approve several public keys and persist them. Returns how many were actually new.
    pub fn trust(&mut self, pubkeys: &[String], now: DateTime<Utc>) -> Result<usize> {
        let mut added = 0;
        for key in pubkeys {
            if self.config.trusted.insert(key.clone(), now).is_none() {
                added += 1;
            }
        }
        self.config.trust_seeded = true;
        self.config.save(&self.paths)?;
        Ok(added)
    }

    /// Withdraw approval for one public key (it does not touch the revocation marker in
    /// `recipients.json`).
    pub fn untrust(&mut self, pubkey: &str) -> Result<bool> {
        let removed = self.config.trusted.remove(pubkey).is_some();
        self.config.save(&self.paths)?;
        Ok(removed)
    }

    /// Seed the trust set from the currently active recipients (only for `init` and
    /// old-config upgrades).
    fn seed_trust(&mut self, now: DateTime<Utc>) -> Result<usize> {
        let all = self.load_recipients()?;
        let keys: Vec<String> = all
            .recipients
            .iter()
            .filter(|(_, record)| record.is_active())
            .map(|(key, _)| key.clone())
            .collect();
        let added = self.trust(&keys, now)?;
        self.config.trust_seeded = true;
        self.config.save(&self.paths)?;
        Ok(added)
    }

    pub fn repo(&self) -> &Path {
        &self.config.repo
    }

    pub fn vault_path(&self) -> PathBuf {
        self.repo().join(VAULT_FILE)
    }

    pub fn recipients_path(&self) -> PathBuf {
        self.repo().join(RECIPIENTS_FILE)
    }

    pub fn recovery_path(&self) -> PathBuf {
        self.repo().join(RECOVERY_FILE)
    }

    pub fn load_recipients(&self) -> Result<Recipients> {
        Recipients::load(&self.recipients_path())
    }

    /// Decrypt the vault. This is the entry point for every read command.
    pub fn load(&self) -> Result<Vault> {
        let ciphertext = paths::read_file(&self.vault_path()).map_err(|e| match e {
            Error::Locked(_) => Error::Locked(crate::msg!(
                "no vault at {}; run `akey init` or `akey init --from <url>`",
                "{} 处没有金库；请运行 `akey init` 或 `akey init --from <url>`",
                self.vault_path().display()
            )),
            other => other,
        })?;
        self.open_ciphertext(&ciphertext)
    }

    /// Decrypt from in-memory ciphertext (sync decrypts historical versions this way).
    pub fn open_ciphertext(&self, ciphertext: &[u8]) -> Result<Vault> {
        let plaintext = self.identity.decrypt(ciphertext).map_err(|e| {
            Error::Locked(crate::msg!(
                "{}; device '{}' may have been removed with `akey devices rm`",
                "{}；设备 '{}' 可能已被 `akey devices rm` 移除",
                e,
                self.identity.name()
            ))
        })?;
        let vault: Vault = serde_json::from_slice(&plaintext).map_err(|e| {
            Error::Corrupt(crate::msg!(
                "vault decrypted but is not valid JSON: {}",
                "金库已解密但不是合法的 JSON：{}",
                e
            ))
        })?;
        if vault.version > FORMAT_VERSION {
            return Err(Error::Unsupported(crate::msg!(
                "vault format v{} is newer than this build supports (v{}); upgrade akey",
                "金库格式 v{} 比本构建支持的版本（v{}）更新；请升级 akey",
                vault.version,
                FORMAT_VERSION
            )));
        }
        Ok(vault)
    }

    /// Encrypt and write atomically, using every currently **unrevoked** recipient.
    pub fn save(&self, vault: &Vault) -> Result<()> {
        let recipients = self.load_recipients()?;
        self.save_with(vault, &recipients)
    }

    pub fn save_with(&self, vault: &Vault, recipients: &Recipients) -> Result<()> {
        // The directory is always written in full — it is the ledger of "who exists", and
        // other devices rely on it to see new members.
        recipients.save(&self.recipients_path())?;

        // But **encryption goes only to those this device approved**. Whoever controls the
        // remote can push a public key into the directory, but not into the local trust set.
        let allowed = self.filter_trusted(recipients);
        if !allowed.recipients.contains_key(&self.identity.pubkey()) {
            // Letting it through here would write ciphertext this device itself cannot
            // reopen — or worse, that only someone else can open.
            let me = self.identity.pubkey();
            // Two ways to land here, with two different fixes, so say which one it is. The
            // trust case is the security-relevant one: it is a local config edit, whereas the
            // membership case means someone changed the repository.
            let reason = if recipients.recipients.contains_key(&me) {
                crate::msg!(
                    "this device ({}) is no longer in the local trust set",
                    "本设备（{}）已不在本地信任集合中",
                    me
                )
            } else {
                crate::msg!(
                    "this device ({}) is not a recipient in {}",
                    "本设备（{}）不是 {} 中的收件人",
                    me,
                    RECIPIENTS_FILE
                )
            };
            return Err(Error::locked(crate::msg!(
                "{}; refusing to write a vault this device could not reopen — \
                 run `akey devices trust {}`",
                "{}；拒绝写入本设备无法重新打开的金库——请运行 `akey devices trust {}`",
                reason,
                me
            )));
        }

        let plaintext =
            serde_json::to_vec(vault).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        let ciphertext = encrypt_to(&allowed.to_recipients()?, &plaintext)?;
        paths::atomic_write(&self.vault_path(), &ciphertext, paths::FILE_MODE)
    }

    /// Run logic that must stay consistent across several reads and writes, under an
    /// exclusive lock.
    pub fn with_lock<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        paths::with_write_lock(&self.paths.lock, || f(self))
    }

    /// Read-modify-write. Every write command should go through here so concurrent updates
    /// are not lost.
    pub fn update<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        self.with_lock(|store| {
            let mut vault = store.load()?;
            let out = f(&mut vault)?;
            store.save(&vault)?;
            Ok(out)
        })
    }

    /// A lightweight write for metadata-only changes that do not touch the ciphertext
    /// content (e.g. refreshing `last_used_at`).
    pub fn touch_usage(&self, entry_id: ulid::Ulid) -> Result<()> {
        self.update(|vault| {
            if let Some(entry) = vault.entries.get_mut(&entry_id) {
                entry.last_used_at = Some(Utc::now());
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DeviceIdentity;
    use crate::vault::model::{Category, Entry};
    use crate::vault::recipients::RecipientKind;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        paths.ensure().unwrap();

        let now = Utc::now();
        let identity = DeviceIdentity::generate("testbox");
        identity.save(&paths.identity).unwrap();

        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let mut recipients = Recipients::default();
        recipients.add(&identity.pubkey(), "testbox", RecipientKind::Device, now);
        recipients.save(&repo.join(RECIPIENTS_FILE)).unwrap();

        Config {
            repo,
            remote: None,
            device_name: "testbox".into(),
            // This fixture writes, so it must trust itself.
            trusted: std::collections::BTreeMap::from([(identity.pubkey(), now)]),
            trust_seeded: true,
            created_at: now,
        }
        .save(&paths)
        .unwrap();

        let store = Store::open(paths).unwrap();
        store.save(&Vault::default()).unwrap();
        (dir, store)
    }

    fn entry(name: &str, secret: &str) -> Entry {
        let id = ulid::Ulid::generate();
        let mut e = Entry::new(id, name.into(), Category::Apikey, Utc::now());
        e.fields.push(crate::vault::model::Field::new(
            "credential",
            crate::vault::model::FieldType::Concealed,
            secret.into(),
        ));
        e
    }

    #[test]
    fn round_trip_preserves_entries_and_hides_them_on_disk() {
        let (_guard, store) = temp_store();
        let mut vault = Vault::default();
        vault
            .entries
            .insert(ulid::Ulid::generate(), entry("openai", "sk-canary-value"));

        store.save(&vault).unwrap();
        let back = store.load().unwrap();
        assert_eq!(back, vault);

        let raw = std::fs::read(store.vault_path()).unwrap();
        assert!(
            !raw.windows(9).any(|w| w == b"sk-canary"),
            "the vault file must not contain plaintext"
        );
    }

    #[test]
    fn update_reads_modifies_and_persists_under_a_lock() {
        let (_guard, store) = temp_store();
        store
            .update(|vault| {
                vault
                    .entries
                    .insert(ulid::Ulid::generate(), entry("a", "1"));
                Ok(())
            })
            .unwrap();

        let id = store
            .update(|vault| {
                let id = ulid::Ulid::generate();
                vault.entries.insert(id, entry("b", "2"));
                Ok(id)
            })
            .unwrap();

        let back = store.load().unwrap();
        assert_eq!(back.entries.len(), 2);
        assert!(back.entries.contains_key(&id));
    }

    /// The security-relevant half: the device is a perfectly valid recipient, but this machine
    /// never approved it. Writing anyway would emit a vault nobody here can open.
    #[test]
    fn refuses_to_write_when_this_device_is_untrusted() {
        let (_guard, store) = temp_store();
        let paths = store.paths.clone();
        let mut config = Config::load(&paths).unwrap();
        config.trusted.remove(&store.identity.pubkey());
        config.save(&paths).unwrap();
        drop(store);
        let store = Store::open(paths).unwrap();

        let err = store.save(&Vault::default()).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(
            err.to_string().contains("no longer in the local trust set"),
            "the error must name trust, not membership: {err}"
        );
    }

    /// The other half: still trusted, but someone removed it from the repository's directory.
    #[test]
    fn refuses_to_write_when_this_device_is_no_longer_a_recipient() {
        let (_guard, store) = temp_store();
        store
            .with_lock(|store| {
                let recipients = Recipients::default();
                recipients.save(&store.recipients_path())
            })
            .unwrap();

        let err = store.save(&Vault::default()).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(
            err.to_string().contains("is not a recipient in"),
            "the error must name membership, not trust: {err}"
        );
    }

    #[test]
    fn opening_without_a_config_is_locked_with_an_init_hint() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        paths.ensure().unwrap();
        // `Store` deliberately does not implement Debug (it holds the identity), so no
        // unwrap_err here.
        let err = match Store::open(paths) {
            Err(err) => err,
            Ok(_) => panic!("opening without a config must fail"),
        };
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("akey init"));
    }

    /// NFR-2: every command except bootstrap and passphrase change stays under a 100ms p95.
    /// Decryption + parsing is the fixed cost of every read, so this is what gets stressed.
    #[test]
    #[ignore = "benchmark: run with `cargo test -- --ignored`"]
    fn hot_path_stays_under_100ms_with_a_thousand_entries() {
        use std::time::Instant;

        let (_guard, store) = temp_store();
        let mut vault = Vault::default();
        for i in 0..1000 {
            vault.entries.insert(
                ulid::Ulid::generate(),
                entry(&format!("key{i}"), "value-material"),
            );
        }
        store.save(&vault).unwrap();

        let mut worst = std::time::Duration::ZERO;
        for _ in 0..50 {
            let started = Instant::now();
            let loaded = store.load().unwrap();
            assert_eq!(loaded.entries.len(), 1000);
            worst = worst.max(started.elapsed());
        }

        let ciphertext = std::fs::metadata(store.vault_path()).unwrap().len();
        eprintln!(
            "vault 1000 entries: {ciphertext} bytes, worst load {:?}",
            worst
        );
        assert!(
            worst < std::time::Duration::from_millis(100),
            "cold read took {worst:?}, over the 100ms budget"
        );
    }
}

//! 金库存储：加解密编排、原子写、文件锁。
//!
//! 上层（`cmd`）只与本模块交互，不应直接碰 `crypto` 或仓库文件。

use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::config::Config;
use crate::crypto::{DeviceIdentity, encrypt_to};
use crate::error::{Error, Result};
use crate::paths::{self, Paths};
use crate::vault::model::{FORMAT_VERSION, Vault};
use crate::vault::recipients::Recipients;

/// 同步仓库内的固定文件名。
pub const VAULT_FILE: &str = "vault.age";
pub const RECOVERY_FILE: &str = "recovery.age";
pub const RECIPIENTS_FILE: &str = "recipients.json";
pub const AGENTS_FILE: &str = "AGENTS.md";

/// 会被提交进同步仓库的文件**白名单**。
///
/// 为什么不用 `git add -A`：那会把落进仓库目录的**任何**文件一起提交。用户或脚本一旦
/// 误把明文写到那里（`akey inject -o repo/x.txt` 就够了），一次 `sync` 就把它永久写进
/// git 历史并推到远端——而 git 历史是删不干净的。只 add 已知文件，让这种失误停在本地。
pub const SYNCED_FILES: &[&str] = &[VAULT_FILE, RECIPIENTS_FILE, RECOVERY_FILE, AGENTS_FILE, ".gitignore"];

/// 一个已解锁的本地视图：本机身份 + 配置 + 仓库位置。
pub struct Store {
    pub paths: Paths,
    pub config: Config,
    pub identity: DeviceIdentity,
}

impl Store {
    /// 打开本机上下文。缺配置或缺身份 → `Locked`（退出码 4）。
    pub fn open(paths: Paths) -> Result<Store> {
        let config = Config::load(&paths)?;
        let identity = DeviceIdentity::load(&paths.identity, config.device_name.clone())?;
        Ok(Store {
            paths,
            config,
            identity,
        })
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

    /// 解密金库。这是所有读命令的入口。
    pub fn load(&self) -> Result<Vault> {
        let ciphertext = paths::read_file(&self.vault_path()).map_err(|e| match e {
            Error::Locked(_) => Error::Locked(format!(
                "no vault at {}; run `akey init` or `akey init --from <url>`",
                self.vault_path().display()
            )),
            other => other,
        })?;
        self.open_ciphertext(&ciphertext)
    }

    /// 从内存中的密文解密（同步时会解出历史版本）。
    pub fn open_ciphertext(&self, ciphertext: &[u8]) -> Result<Vault> {
        let plaintext = self.identity.decrypt(ciphertext).map_err(|e| {
            Error::Locked(format!(
                "{e}; device '{}' may have been removed with `akey devices rm`",
                self.identity.name()
            ))
        })?;
        let vault: Vault = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Corrupt(format!("vault decrypted but is not valid JSON: {e}")))?;
        if vault.version > FORMAT_VERSION {
            return Err(Error::Unsupported(format!(
                "vault format v{} is newer than this build supports (v{FORMAT_VERSION}); upgrade akey",
                vault.version
            )));
        }
        Ok(vault)
    }

    /// 加密并原子落盘。会用当前全部**未吊销**收件人加密。
    pub fn save(&self, vault: &Vault) -> Result<()> {
        let recipients = self.load_recipients()?;
        self.save_with(vault, &recipients)
    }

    pub fn save_with(&self, vault: &Vault, recipients: &Recipients) -> Result<()> {
        let mine = self.identity.pubkey();
        if !recipients.active_pubkeys().iter().any(|k| k == &mine) {
            // 若在此放行，写下去的密文本机自己也解不开。
            return Err(Error::Locked(format!(
                "this device ({mine}) is not an active recipient; refusing to write a vault \
                 this device could not reopen — run `akey devices add` or restore from recovery"
            )));
        }
        let plaintext = serde_json::to_vec(vault)
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        let ciphertext = encrypt_to(&recipients.to_recipients()?, &plaintext)?;
        paths::atomic_write(&self.vault_path(), &ciphertext, paths::FILE_MODE)
    }

    /// 排他锁下执行一段需要跨多次读写保持一致的逻辑。
    pub fn with_lock<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        paths::with_write_lock(&self.paths.lock, || f(self))
    }

    /// 读-改-写。所有写命令都应走这里，避免丢失并发更新。
    pub fn update<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        self.with_lock(|store| {
            let mut vault = store.load()?;
            let out = f(&mut vault)?;
            store.save(&vault)?;
            Ok(out)
        })
    }

    /// 只改元数据、不触碰密文内容时的轻量写（如刷新 `last_used_at`）。
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
        e.fields
            .push(crate::vault::model::Field::new("credential", crate::vault::model::FieldType::Concealed, secret.into()));
        e
    }

    #[test]
    fn round_trip_preserves_entries_and_hides_them_on_disk() {
        let (_guard, store) = temp_store();
        let mut vault = Vault::default();
        vault.entries.insert(ulid::Ulid::generate(), entry("openai", "sk-canary-value"));

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
                vault.entries.insert(ulid::Ulid::generate(), entry("a", "1"));
                Ok(())
            })
            .unwrap();

        let id = store.update(|vault| {
            let id = ulid::Ulid::generate();
            vault.entries.insert(id, entry("b", "2"));
            Ok(id)
        })
        .unwrap();

        let back = store.load().unwrap();
        assert_eq!(back.entries.len(), 2);
        assert!(back.entries.contains_key(&id));
    }

    #[test]
    fn refuses_to_write_a_vault_this_device_could_not_reopen() {
        let (_guard, store) = temp_store();
        // 把自己从收件人里剔除，模拟误操作。
        store
            .with_lock(|store| {
                let recipients = Recipients::default();
                recipients.save(&store.recipients_path())
            })
            .unwrap();

        let err = store.save(&Vault::default()).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("not an active recipient"));
    }

    #[test]
    fn opening_without_a_config_is_locked_with_an_init_hint() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        paths.ensure().unwrap();
        // `Store` 故意不实现 Debug（它握着身份），所以不用 unwrap_err。
        let err = match Store::open(paths) {
            Err(err) => err,
            Ok(_) => panic!("opening without a config must fail"),
        };
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("akey init"));
    }

    /// NFR-2：除引导与改恢复密码外，任何命令 p95 < 100ms。
    /// 解密 + 解析是每次读取的固定成本，所以直接压这里。
    #[test]
    #[ignore = "benchmark: run with `cargo test -- --ignored`"]
    fn hot_path_stays_under_100ms_with_a_thousand_entries() {
        use std::time::Instant;

        let (_guard, store) = temp_store();
        let mut vault = Vault::default();
        for i in 0..1000 {
            vault
                .entries
                .insert(ulid::Ulid::generate(), entry(&format!("key{i}"), "value-material"));
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
        eprintln!("vault 1000 entries: {ciphertext} bytes, worst load {:?}", worst);
        assert!(
            worst < std::time::Duration::from_millis(100),
            "cold read took {worst:?}, over the 100ms budget"
        );
    }
}

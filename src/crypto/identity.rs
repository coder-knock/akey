//! 设备身份：每台机器一份 age X25519 密钥对，私钥仅存本机且永不进 git。

use std::path::Path;
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient};
use zeroize::Zeroizing;

use crate::crypto::boxcrypto;
use crate::error::{Error, Result};
use crate::paths;

/// 本机设备身份。
pub struct DeviceIdentity {
    identity: Identity,
    name: String,
}

impl DeviceIdentity {
    /// 生成全新身份。
    pub fn generate(name: impl Into<String>) -> Self {
        Self {
            identity: Identity::generate(),
            name: name.into(),
        }
    }

    /// 从 `AGE-SECRET-KEY-1…` 文本解析。
    ///
    /// 允许首尾空白：`save` 会在末尾写入换行，读回的文件内容不是纯净的单行。
    pub fn parse(secret: &str, name: impl Into<String>) -> Result<Self> {
        let identity = Identity::from_str(secret.trim())
            .map_err(|why| Error::corrupt(format!("invalid device identity ({why})")))?;
        Ok(Self {
            identity,
            name: name.into(),
        })
    }

    /// `AGE-SECRET-KEY-1…`（经 `SecretString` 包裹，避免误打印）。
    pub fn secret_string(&self) -> SecretString {
        self.identity.to_string()
    }

    /// 本机公钥，用于写入 `recipients.json`。
    pub fn recipient(&self) -> Recipient {
        self.identity.to_public()
    }

    /// `age1…` 形式的公钥文本。
    pub fn pubkey(&self) -> String {
        self.recipient().to_string()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// 用本机私钥解密密文。委托给 `boxcrypto::decrypt_with`。
    ///
    /// 失败 → `Locked`，消息可行动（提示本设备可能已被 `devices rm` 排除）。
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        boxcrypto::decrypt_with(&self.identity, ciphertext)
    }

    /// 原子写入并设 `0600`。
    pub fn save(&self, path: &Path) -> Result<()> {
        // 私钥副本在离开作用域时清零，不留在堆上。
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(self.secret_string().expose_secret().as_bytes());
        bytes.push(b'\n');
        paths::atomic_write(path, &bytes, paths::FILE_MODE)
    }

    /// 读取前先校验权限位；他人可读即拒绝（退出码 4）。
    pub fn load(path: &Path, name: impl Into<String>) -> Result<Self> {
        paths::ensure_private(path)?;
        let bytes = Zeroizing::new(paths::read_file(path)?);
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| Error::corrupt(format!("{} is not valid UTF-8: {e}", path.display())))?;
        Self::parse(text, name)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn generate_save_load_keeps_the_same_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let device = DeviceIdentity::generate("macbook");
        device.save(&path).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(
            written.starts_with("AGE-SECRET-KEY-1"),
            "secret file must hold an age secret key, got {:?}",
            &written[..written.len().min(24)]
        );

        let loaded = DeviceIdentity::load(&path, "macbook").unwrap();
        assert_eq!(loaded.pubkey(), device.pubkey());
        assert!(loaded.pubkey().starts_with("age1"), "{}", loaded.pubkey());
        assert_eq!(loaded.name(), "macbook");
    }

    #[test]
    fn save_writes_0600_and_load_rejects_other_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        DeviceIdentity::generate("macbook").save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity must be owner-only, got {mode:o}");

        // 同组可读 = 身份泄露，读取必须拒绝而不是照常解密。
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = match DeviceIdentity::load(&path, "macbook") {
            Ok(_) => panic!("group-readable identity file must not load"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn parse_rejects_garbage_and_accepts_trailing_newline() {
        let err = DeviceIdentity::parse("not an age key at all", "macbook")
            .err()
            .expect("garbage must not parse as an identity");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 1);

        let device = DeviceIdentity::generate("macbook");
        let with_newline = format!("{}\n", device.secret_string().expose_secret());
        let parsed = DeviceIdentity::parse(&with_newline, "macbook").unwrap();
        assert_eq!(parsed.pubkey(), device.pubkey());
    }

    #[test]
    fn device_decrypts_its_own_ciphertext_only() {
        let publisher = DeviceIdentity::generate("publisher");
        let other = DeviceIdentity::generate("other");

        let ciphertext = boxcrypto::encrypt_to(&[publisher.recipient()], b"x").unwrap();
        assert_eq!(publisher.decrypt(&ciphertext).unwrap(), b"x");

        let err = other
            .decrypt(&ciphertext)
            .err()
            .expect("a device that is not a recipient must not decrypt");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);
    }
}

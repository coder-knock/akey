//! Device identity: one age X25519 keypair per machine; the secret key stays machine-local and never enters git.

use std::path::Path;
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient};
use zeroize::Zeroizing;

use crate::crypto::boxcrypto;
use crate::error::{Error, Result};
use crate::paths;

/// This machine's device identity.
pub struct DeviceIdentity {
    identity: Identity,
    name: String,
}

impl DeviceIdentity {
    /// Generates a brand-new identity.
    pub fn generate(name: impl Into<String>) -> Self {
        Self {
            identity: Identity::generate(),
            name: name.into(),
        }
    }

    /// Parses from `AGE-SECRET-KEY-1…` text.
    ///
    /// Leading/trailing whitespace is allowed: `save` writes a trailing newline, so the content
    /// read back from the file is not a clean single line.
    pub fn parse(secret: &str, name: impl Into<String>) -> Result<Self> {
        let identity = Identity::from_str(secret.trim())
            .map_err(|why| Error::corrupt(format!("invalid device identity ({why})")))?;
        Ok(Self {
            identity,
            name: name.into(),
        })
    }

    /// `AGE-SECRET-KEY-1…` (wrapped in `SecretString` to prevent accidental printing).
    pub fn secret_string(&self) -> SecretString {
        self.identity.to_string()
    }

    /// This machine's public key, written into `recipients.json`.
    pub fn recipient(&self) -> Recipient {
        self.identity.to_public()
    }

    /// Public-key text in `age1…` form.
    pub fn pubkey(&self) -> String {
        self.recipient().to_string()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Decrypts ciphertext with this machine's secret key. Delegates to `boxcrypto::decrypt_with`.
    ///
    /// Failure → `Locked`, with an actionable message (hinting that this device may have been
    /// excluded by `devices rm`).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        boxcrypto::decrypt_with(&self.identity, ciphertext)
    }

    /// Atomic write with mode `0600`.
    pub fn save(&self, path: &Path) -> Result<()> {
        // The secret-key copy is zeroized when it leaves scope, not left on the heap.
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(self.secret_string().expose_secret().as_bytes());
        bytes.push(b'\n');
        paths::atomic_write(path, &bytes, paths::FILE_MODE)
    }

    /// Checks the permission bits before reading; readable by others is refused (exit code 4).
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
    #[cfg(unix)]
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

    /// Mode bits have no Windows equivalent, and there is no way to construct the negative case
    /// there either: the temp dir already sits inside the profile, so the profile check passes.
    /// The Windows guard is covered instead by `paths::profile_containment_*`.
    #[cfg(unix)]
    #[test]
    fn save_writes_0600_and_load_rejects_other_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        DeviceIdentity::generate("macbook").save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity must be owner-only, got {mode:o}");

        // Group-readable = identity leak, so reading must be refused rather than decrypting anyway.
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

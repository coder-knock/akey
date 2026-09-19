//! age wrapper: multi-recipient encryption/decryption and passphrase encryption/decryption.
//!
//! This module is the sole cryptography entry point — layers above must not call `age` directly.

use std::io::{Read, Write};
use std::iter;

use age::secrecy::SecretString;
use age::x25519::{Identity, Recipient};

use crate::error::{Error, Result};

/// Encrypts to multiple recipients (all non-revoked devices + the bootstrap identity).
///
/// Empty recipient list → `usage` (the caller guarantees at least one; silently producing a file
/// nobody can open is an incident).
pub fn encrypt_to(recipients: &[Recipient], plaintext: &[u8]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(Error::usage(
            "refusing to encrypt without recipients: nobody could ever decrypt the result",
        ));
    }

    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| Error::crypto(format!("cannot encrypt to the given recipients: {e}")))?;
    seal(encryptor, plaintext)
}

/// Decrypts with this machine's identity. Not a recipient / corrupt ciphertext → `locked` (exit code 4).
pub fn decrypt_with(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
    open(ciphertext, iter::once(identity as &dyn age::Identity))
}

/// passphrase mode (scrypt). Used only for `recovery.age`.
pub fn encrypt_with_passphrase(passphrase: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal(age::Encryptor::with_user_passphrase(passphrase.clone()), plaintext)
}

/// Wrong passphrase → `locked` (exit code 4).
pub fn decrypt_with_passphrase(passphrase: &SecretString, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let identity = age::scrypt::Identity::new(passphrase.clone());
    open(ciphertext, iter::once(&identity as &dyn age::Identity))
}

/// Writes out a complete age v1 ciphertext.
///
/// `StreamWriter::finish` must be called, otherwise what lands on disk is a truncated file.
fn seal(encryptor: age::Encryptor, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| Error::crypto(format!("cannot start age encryption: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| Error::crypto(format!("age encryption failed: {e}")))?;
    writer
        .finish()
        .map_err(|e| Error::crypto(format!("age encryption failed: {e}")))?;
    Ok(out)
}

/// Opens ciphertext with one or more identities; any failure — not a recipient, corrupt ciphertext, wrong scrypt passphrase — is `locked`.
fn open<'a>(
    ciphertext: &[u8],
    identities: impl Iterator<Item = &'a dyn age::Identity>,
) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|e| cannot_open(&e))?;
    let mut reader = decryptor
        .decrypt(identities)
        .map_err(|e| cannot_open(&e))?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| cannot_open(&e))?;
    Ok(plaintext)
}

/// The outward wording for a decryption failure: make clear it "may be that this device was removed", not just "cannot open".
fn cannot_open(reason: &dyn std::fmt::Display) -> Error {
    Error::locked(format!(
        "cannot decrypt the vault ({reason}); if this device was removed, re-add it with \
         `akey devices add` — see `akey devices list`"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text.to_string())
    }

    #[test]
    fn every_recipient_can_decrypt() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let plaintext = b"shared vault payload";

        let ciphertext = encrypt_to(&[alice.to_public(), bob.to_public()], plaintext).unwrap();

        assert_eq!(decrypt_with(&alice, &ciphertext).unwrap(), plaintext);
        assert_eq!(decrypt_with(&bob, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn a_non_recipient_is_locked_out() {
        let alice = Identity::generate();
        let stranger = Identity::generate();
        let ciphertext = encrypt_to(&[alice.to_public()], b"top secret").unwrap();

        let err = decrypt_with(&stranger, &ciphertext)
            .err()
            .expect("a stranger must not decrypt");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn empty_recipient_list_is_a_usage_error() {
        let err = encrypt_to(&[], b"unreachable")
            .err()
            .expect("encrypting with no recipients must be refused");
        assert!(matches!(err, Error::Usage(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn truncated_ciphertext_is_locked_not_panicking() {
        let alice = Identity::generate();
        let mut ciphertext =
            encrypt_to(&[alice.to_public()], b"a payload long enough to leave a real stream")
                .unwrap();
        let dropped = ciphertext.split_off(ciphertext.len() - 20);
        assert_eq!(dropped.len(), 20);

        let err = decrypt_with(&alice, &ciphertext)
            .err()
            .expect("truncated ciphertext must not decrypt");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn passphrase_roundtrip_and_wrong_passphrase_is_locked() {
        let right = passphrase("correct horse battery staple");
        let ciphertext = encrypt_with_passphrase(&right, b"recovery blob").unwrap();
        assert_eq!(
            decrypt_with_passphrase(&right, &ciphertext).unwrap(),
            b"recovery blob"
        );

        let wrong = passphrase("correct horse battery stapl3");
        let err = decrypt_with_passphrase(&wrong, &ciphertext)
            .err()
            .expect("a wrong passphrase must not decrypt");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn ciphertext_never_embeds_the_plaintext() {
        let alice = Identity::generate();
        let plaintext = b"CANARY-3f9a";

        let ciphertext = encrypt_to(&[alice.to_public()], plaintext).unwrap();
        assert!(
            !ciphertext
                .windows(plaintext.len())
                .any(|window| window == plaintext),
            "plaintext leaked into the ciphertext"
        );
        assert_eq!(decrypt_with(&alice, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn encrypting_twice_yields_different_ciphertexts() {
        let alice = Identity::generate();
        let recipient = alice.to_public();
        let plaintext = b"same plaintext";

        let first = encrypt_to(std::slice::from_ref(&recipient), plaintext).unwrap();
        let second = encrypt_to(&[recipient], plaintext).unwrap();

        assert_ne!(first, second, "age must not be deterministic");
    }
}

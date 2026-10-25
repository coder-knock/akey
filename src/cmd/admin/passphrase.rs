//! Recovery-passphrase acquisition and length policy.

use std::io::{IsTerminal, Read};

use age::secrecy::{ExposeSecret, SecretString};

use super::MIN_PASSPHRASE_LEN;
use crate::error::{Error, Result};

/// Obtain the recovery passphrase. Order: the `AKEY_RECOVERY_PASSPHRASE` environment
/// variable → read stdin when not a TTY → prompt when a TTY.
///
/// A non-interactive run never blocks: with no TTY and no environment variable, reading
/// stdin to EOF fails instead of hanging on a prompt.
///
/// `confirm = true` means **this passphrase is being newly created**, in which case the
/// minimum length applies no matter where it came from. `min_len` overrides the
/// `MIN_PASSPHRASE_LEN` default for this call.
pub(super) fn read_passphrase(confirm: bool, min_len: usize) -> Result<SecretString> {
    if let Ok(value) = std::env::var("AKEY_RECOVERY_PASSPHRASE")
        && !value.is_empty()
    {
        return enforce_min(SecretString::from(value), confirm, min_len);
    }

    if !std::io::stdin().is_terminal() {
        let mut raw = String::new();
        std::io::stdin().read_to_string(&mut raw)?;
        let line = raw.lines().next().unwrap_or("").to_string();
        if line.is_empty() {
            return Err(Error::usage(crate::msg!(
                "no passphrase available: set AKEY_RECOVERY_PASSPHRASE or pipe it on stdin",
                "没有可用的恢复密码：请设置 AKEY_RECOVERY_PASSPHRASE，或通过 stdin 传入"
            )));
        }
        return enforce_min(SecretString::from(line), confirm, min_len);
    }

    let first = rpassword::prompt_password(crate::i18n::m("Recovery passphrase: ", "恢复密码："))?;
    if confirm {
        let second =
            rpassword::prompt_password(crate::i18n::m("Repeat passphrase: ", "重复密码："))?;
        if first != second {
            return Err(Error::usage(crate::msg!(
                "passphrases do not match",
                "两次输入的密码不一致"
            )));
        }
    }
    enforce_min(SecretString::from(first), confirm, min_len)
}

/// Resolve the effective minimum length: the caller's explicit flag (if any), else
/// `$AKEY_RECOVERY_MIN_LEN`, else the compile-time default.
pub(super) fn resolve_min_passphrase_len(flag: Option<u16>) -> usize {
    flag.map(|n| n as usize)
        .or_else(|| {
            std::env::var("AKEY_RECOVERY_MIN_LEN")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
        })
        .unwrap_or(MIN_PASSPHRASE_LEN)
}

/// Enforce the length limit only for a **new** passphrase.
///
/// The other way round (enforcing it on existing passphrases too) would make tightening the
/// policy suicidal: once an old vault's passphrase is shorter than the new minimum, it could
/// no longer be unlocked / rotated / bootstrapped, when it should still work.
pub(super) fn enforce_min(
    passphrase: SecretString,
    is_new: bool,
    min_len: usize,
) -> Result<SecretString> {
    let len = passphrase.expose_secret().len();
    if !is_new {
        return Ok(passphrase);
    }
    if min_len < crate::vault::generator::MIN_PASSPHRASE_LEN_FLOOR {
        return Err(Error::usage(crate::msg!(
            "--min-passphrase-len {} is below the {} floor; refusing to weaken policy",
            "--min-passphrase-len {} 小于下限 {}；拒绝以此放宽策略",
            min_len,
            crate::vault::generator::MIN_PASSPHRASE_LEN_FLOOR
        )));
    }
    if min_len > crate::vault::generator::MIN_PASSPHRASE_LEN_CEIL {
        return Err(Error::usage(crate::msg!(
            "--min-passphrase-len {} exceeds the {} ceiling",
            "--min-passphrase-len {} 超出上限 {}",
            min_len,
            crate::vault::generator::MIN_PASSPHRASE_LEN_CEIL
        )));
    }
    if len < min_len {
        return Err(Error::usage(crate::msg!(
            "passphrase must be at least {} characters",
            "恢复密码至少需要 {} 个字符",
            min_len
        )));
    }
    Ok(passphrase)
}

/// Obtain the **new** recovery passphrase. `AKEY_NEW_RECOVERY_PASSPHRASE` lets it be given
/// separately from the old one — otherwise a non-interactive rotate could only read the same
/// value twice.
pub(super) fn read_new_passphrase(min_len: usize) -> Result<SecretString> {
    if let Ok(value) = std::env::var("AKEY_NEW_RECOVERY_PASSPHRASE")
        && !value.is_empty()
    {
        return enforce_min(SecretString::from(value), true, min_len);
    }
    read_passphrase(true, min_len)
}

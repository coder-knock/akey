//! Error classification and exit codes.
//!
//! Exit codes are part of the **public contract** (see `REQUIREMENTS.md` FR-3); changing them breaks compatibility.

use serde::Serialize;

/// Stable error-code string, appearing in the `--json` envelope and the audit log.
pub type Code = &'static str;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Argument/usage error. Exit 2.
    #[error("{0}")]
    Usage(String),

    /// Entry, field, device, or token does not exist. Exit 3.
    #[error("{0}")]
    NotFound(String),

    /// Name is not unique enough to pin down a target. Exit 3.
    #[error("{0}")]
    Ambiguous(String),

    /// No identity / cannot decrypt / wrong passphrase / invalid token. Exit 4.
    #[error("{0}")]
    Locked(String),

    /// Sync produced a conflict that needs manual resolution. Exit 5.
    #[error("{0}")]
    Conflict(String),

    /// git or remote operation failed. Exit 6.
    #[error("{0}")]
    SyncFailed(String),

    /// reveal rejected by policy (entry reveal=deny, AKEY_NO_REVEAL, token deny_reveal). Exit 7.
    #[error("{0}")]
    Denied(String),

    /// Token scope is insufficient. Exit 8.
    #[error("{0}")]
    TokenScope(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Encryption/decryption failed. Exit 1.
    #[error("{0}")]
    Crypto(String),

    /// Ciphertext or file structure is corrupt. Exit 1.
    #[error("{0}")]
    Corrupt(String),

    /// git subprocess misbehaved. Exit 1 (distinct from SyncFailed: that is a business-level sync failure).
    #[error("{0}")]
    Git(String),

    /// Feature not implemented or platform unsupported. Exit 1.
    #[error("{0}")]
    Unsupported(String),
}

impl Error {
    pub fn code(&self) -> Code {
        match self {
            Error::Usage(_) => "usage",
            Error::NotFound(_) => "not_found",
            Error::Ambiguous(_) => "ambiguous",
            Error::Locked(_) => "locked",
            Error::Conflict(_) => "conflict",
            Error::SyncFailed(_) => "sync_failed",
            Error::Denied(_) => "denied",
            Error::TokenScope(_) => "token_scope",
            Error::Io(_) => "io",
            Error::Crypto(_) => "crypto",
            Error::Corrupt(_) => "corrupt",
            Error::Git(_) => "git",
            Error::Unsupported(_) => "unsupported",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::NotFound(_) | Error::Ambiguous(_) => 3,
            Error::Locked(_) => 4,
            Error::Conflict(_) => 5,
            Error::SyncFailed(_) => 6,
            Error::Denied(_) => 7,
            Error::TokenScope(_) => 8,
            Error::Io(_) | Error::Crypto(_) | Error::Corrupt(_) | Error::Git(_)
            | Error::Unsupported(_) => 1,
        }
    }

    /// Next-step hint aimed at an agent. Returned only when there is a concrete action.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Error::NotFound(_) => Some("run `akey list` to see available entries"),
            Error::Ambiguous(_) => Some("use the entry ID instead of the name"),
            Error::Locked(_) => Some("run `akey doctor` to diagnose the vault state"),
            Error::Conflict(_) => Some("run `akey conflicts` then `akey resolve <name> --ours|--theirs`"),
            Error::Denied(_) => Some("inject with `akey run` instead of reading the value"),
            Error::TokenScope(_) => Some("ask an operator to widen the token's --allow list"),
            _ => None,
        }
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        Error::Usage(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }

    pub fn locked(msg: impl Into<String>) -> Self {
        Error::Locked(msg.into())
    }

    pub fn denied(msg: impl Into<String>) -> Self {
        Error::Denied(msg.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `--json` failure envelope.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: Code,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
}

impl From<&Error> for ErrorBody {
    fn from(e: &Error) -> Self {
        ErrorBody {
            code: e.code(),
            message: e.to_string(),
            hint: e.hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exit codes are a public contract; pinned one by one.
    #[test]
    fn exit_codes_match_contract() {
        let cases: Vec<(Error, i32, Code)> = vec![
            (Error::Usage("x".into()), 2, "usage"),
            (Error::NotFound("x".into()), 3, "not_found"),
            (Error::Ambiguous("x".into()), 3, "ambiguous"),
            (Error::Locked("x".into()), 4, "locked"),
            (Error::Conflict("x".into()), 5, "conflict"),
            (Error::SyncFailed("x".into()), 6, "sync_failed"),
            (Error::Denied("x".into()), 7, "denied"),
            (
                Error::TokenScope("x".into()),
                8,
                "token_scope",
            ),
            (Error::Crypto("x".into()), 1, "crypto"),
            (Error::Corrupt("x".into()), 1, "corrupt"),
            (Error::Git("x".into()), 1, "git"),
            (Error::Unsupported("x".into()), 1, "unsupported"),
        ];
        for (err, code, name) in cases {
            assert_eq!(err.exit_code(), code, "exit code for {name}");
            assert_eq!(err.code(), name);
        }
    }

    #[test]
    fn error_body_omits_missing_hint() {
        let body = ErrorBody::from(&Error::Usage("bad flag".into()));
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["code"], "usage");
        assert!(json.get("hint").is_none(), "hint must be absent, not null");

        let body = ErrorBody::from(&Error::NotFound("nope".into()));
        let json = serde_json::to_value(&body).unwrap();
        assert!(json["hint"].is_string());
    }
}

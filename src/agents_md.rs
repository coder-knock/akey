//! Agent documentation shipped with the binary.
//!
//! Compiled into the binary (`include_str!`) and written into the sync repo by `akey init` —
//! so any agent that gets the repo can bootstrap itself without external docs.

/// The `AGENTS.md` written into the vault repo.
pub const VAULT_AGENTS_MD: &str = include_str!("../assets/AGENTS.vault.md");

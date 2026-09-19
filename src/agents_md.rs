//! 随二进制分发的 agent 说明书。
//!
//! 编译进二进制（`include_str!`），`akey init` 时写进同步仓库——这样拿到仓库的
//! 任何 agent 都能自举，不需要外部文档。

/// 写进金库仓库的 `AGENTS.md`。
pub const VAULT_AGENTS_MD: &str = include_str!("../assets/AGENTS.vault.md");

//! akey —— 供 AI 使用的加密凭证库。
//!
//! 分层：`vault`(数据) → `crypto`(加解密) → `reference`(寻址) → `inject`(交付) → `cmd`(命令面)。
//! 契约细节见仓库根的 `REQUIREMENTS.md` / `DESIGN.md`。

// 测试里用 `.err().expect(..)` 而非 `unwrap_err()` 是有意的：`unwrap_err()` 要求
// `Ok` 类型实现 `Debug`，而 `DeviceIdentity` / `age::x25519::Identity` 这类
// 握着秘密的类型刻意不实现 Debug，免得被 `{:?}` 顺手打印出去。
#![cfg_attr(test, allow(clippy::err_expect))]

pub mod agents_md;
pub mod audit;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod crypto;
pub mod error;
pub mod inject;
pub mod output;
pub mod paths;
pub mod reference;
pub mod sync;
pub mod vault;

pub use error::{Error, Result};

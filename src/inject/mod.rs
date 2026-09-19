//! 注入与遮蔽。

pub mod mask;
pub mod run;

pub use mask::{MIN_SECRET_LEN, Masker};
pub use run::Injection;

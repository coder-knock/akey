//! 密码学。唯一入口——上层不得直接依赖 `age`。

pub mod boxcrypto;
pub mod identity;
pub mod token;

pub use boxcrypto::{decrypt_with, decrypt_with_passphrase, encrypt_to, encrypt_with_passphrase};
pub use identity::DeviceIdentity;
pub use token::IssuedToken;

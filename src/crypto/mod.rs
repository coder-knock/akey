//! Cryptography. The sole entry point — layers above must not depend on `age` directly.

pub mod boxcrypto;
pub mod identity;
pub mod token;

pub use boxcrypto::{decrypt_with, decrypt_with_passphrase, encrypt_to, encrypt_with_passphrase};
pub use identity::DeviceIdentity;
pub use token::IssuedToken;

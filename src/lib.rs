//! akey — a credential vault for AI agents.
//!
//! Layers: `vault` (data) → `crypto` (cryptography) → `reference` (addressing) → `inject` (delivery) → `cmd` (command surface).
//! See `REQUIREMENTS.md` / `DESIGN.md` at the repo root for the contract details.

// Using `.err().expect(..)` instead of `unwrap_err()` in tests is deliberate: `unwrap_err()`
// requires the `Ok` type to implement `Debug`, and secret-holding types such as
// `DeviceIdentity` / `age::x25519::Identity` deliberately do not implement Debug, lest
// `{:?}` print them out in passing.
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

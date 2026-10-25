//! Entry commands: CRUD, copy and rename, templates, conflict resolution.
//!
//! Each command function only does **argument shuttling + persistence orchestration**: every
//! decision is factored into a pure function taking `&Vault` / `&mut Vault`, so unit tests need
//! not build a `Ctx` (whose fields are private). Writes all go through `Store::update`
//! (read-modify-write + exclusive lock + atomic persist); `--dry-run` runs the same computation
//! on an in-memory copy, persisting nothing and writing no audit entry.
//!
//! Output discipline: human text and JSON data are emitted by **the same `emit` call** — one source for both.
//!
//! Commands are grouped by responsibility: `read` (get/list), `write` (set/edit),
//! `lifecycle` (rm/restore/cp/mv), `template`, and `conflict` (conflicts/resolve).

mod conflict;
mod input;
mod lifecycle;
mod read;
mod template;
mod write;

pub use conflict::{conflicts, resolve};
pub use lifecycle::{cp, mv, restore, rm};
pub use read::{get, list};
pub use template::template;
pub use write::{edit, set};

use crate::error::Error;

/// JSON serialization failures are I/O errors at this layer: the data is ours, so a failure means the writer broke.
fn json_err(err: serde_json::Error) -> Error {
    Error::Io(std::io::Error::other(err))
}

#[cfg(test)]
mod tests;

//! Delivery commands: hand secrets to a child process or a template without going through the caller.
//!
//! This module is where the "plaintext exits" concentrate, so every exit passes the token-scope gate:
//! - [`read`] / [`doc`] take plaintext → `Ctx::gate_reveal` (entry policy + environment switch + token policy)
//! - [`run`] / [`inject`] hand plaintext to a child process or a file → `Ctx::authorize_references` / `Ctx::authorize`
//! - [`export`] dumps the whole vault → `gate_reveal` + only entries inside the scope are exported
//! - [`import`] / `doc put` write to the vault → `Ctx::gate_write` (tokens are read-only credentials)
//! - [`mcp`] exposes metadata only, and **never exposes field values**
//!
//! Commands are grouped by responsibility: `handoff` (read/run/inject), `export` / `import`,
//! `doc` for attachments, and `mcp` for the metadata-only JSON-RPC channel.

mod doc;
mod export;
mod handoff;
mod import;
mod mcp;

pub use doc::doc;
pub use export::export;
pub use handoff::{inject, read, run};
pub use import::import;
pub use mcp::mcp;

use std::io::{Read as _, Write as _};
use std::path::Path;

use crate::error::{Error, Result};

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    Ok(raw)
}

fn read_text_file(path: &Path, what: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            crate::msg!(
                "cannot read {} {}: {}",
                "无法读取{} {}：{}",
                what,
                path.display(),
                e
            ),
        ))
    })
}

#[cfg(test)]
mod tests;

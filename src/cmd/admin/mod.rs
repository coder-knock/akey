//! Lifecycle commands: init, devices, recovery passphrase, capability tokens, self-check,
//! audit, schema, completion.
//!
//! Commands are grouped by responsibility: `init` (vault creation / join), `devices`
//! (trust and revocation), `recovery` (bootstrap passphrase), `token` (capability tokens),
//! `diagnostics` (`whoami` / `doctor`), and `reference` (audit log, schema, completion).
//! Passphrase acquisition and policy live in `passphrase`; the Git/error helpers shared
//! across groups live here.

mod devices;
mod diagnostics;
mod init;
mod passphrase;
mod recovery;
mod reference;
mod token;

pub use devices::devices;
pub use diagnostics::{doctor, whoami};
pub use init::init;
pub use recovery::recovery;
pub use reference::{completion, log, schema};
pub use token::token;

use crate::error::Error;
use crate::sync::Git;
use crate::vault::store::Store;

/// Minimum recovery-passphrase length. It is the vault's last resort, so do not let it
/// become the weakest link.
pub const MIN_PASSPHRASE_LEN: usize = 12;

fn git_for(store: &Store) -> Git {
    let name = store.config.device_name.clone();
    Git::new(
        store.repo(),
        &name,
        format!("akey+{}@akey.invalid", sanitise(&name)),
    )
}

fn sanitise(device: &str) -> String {
    device
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// JSON serialization failures are I/O errors at this layer: the data is ours, so a failure means the writer broke.
fn internal(e: serde_json::Error) -> Error {
    Error::Io(std::io::Error::other(e))
}

#[cfg(test)]
mod tests;

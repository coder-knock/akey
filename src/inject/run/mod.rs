//! Injection mechanism: parse references → build the environment → spawn the child → mask the echo.
//!
//! Division of labour with `cmd::deliver`: this module is mechanism only, no argument parsing and no policy decisions.
//!
//! `resolve` builds the environment and the authorization surface (`Touch`); `spawn` runs the
//! child and masks its output. `Injection` is the value they share.

mod resolve;
mod spawn;

pub use resolve::{Touch, env_name, parse_dotenv, render_template, resolve, touch};
pub use spawn::execute;

use std::collections::BTreeSet;

use zeroize::Zeroizing;

/// The complete environment of one injection.
#[derive(Debug, Default)]
pub struct Injection {
    /// Variable name → plaintext. The order is stable, which helps tests and `--dry-run` previews.
    pub vars: Vec<(String, Zeroizing<String>)>,
    /// The **individual** plaintexts substituted into those values.
    ///
    /// The masker has to register them as well. Register only the final values and
    /// `--with AUTH="Bearer akey://a/b"` leaks plaintext when the child prints the part after
    /// `Bearer ` (`${AUTH#Bearer }`) — measured, it really does leak.
    pub plaintexts: Vec<Zeroizing<String>>,
}

impl Injection {
    /// Build from the variable table alone (tests and internal use). `plaintexts` only affects the masking surface, not the injected content.
    pub fn from_vars(vars: Vec<(String, Zeroizing<String>)>) -> Self {
        Injection {
            vars,
            plaintexts: Vec::new(),
        }
    }

    /// The plaintext list for the masking pipeline: the final values plus the substituted single values.
    pub fn secrets(&self) -> Vec<String> {
        let mut all: BTreeSet<String> = self.vars.iter().map(|(_, v)| v.to_string()).collect();
        all.extend(self.plaintexts.iter().map(|p| p.to_string()));
        all.into_iter().collect()
    }
}

#[cfg(test)]
mod tests;

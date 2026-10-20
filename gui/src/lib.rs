//! `akey-gui` — the desktop front end for `akey`.
//!
//! Architecture (`DESIGN.md` §18): the GUI is a **separate process** from the vault. Every
//! operation is an `akey --json <verb>` invocation whose answer is the frozen envelope
//! from `REQUIREMENTS.md` FR-3. The GUI never links the vault library and never
//! reimplements a policy gate — a refused reveal is the CLI's exit 7, not the GUI's
//! opinion.
//!
//! Layers:
//!
//! * [`backend`] — locate and invoke the CLI, classify the result.
//! * [`verbs`] — one named method per vault operation, so the exact argv is written down
//!   once and asserted by tests.
//! * [`model`] — typed views over the JSON payloads.
//! * [`revealed`] — the only type that may hold plaintext, plus the rules that end it.
//! * [`app`] / views — GPUI rendering, behind the `gpui` feature.
//!
//! Everything above `app` compiles without `gpui`, which is what lets
//! `cargo test -p akey-gui` run on a machine with no GPU toolchain.

pub mod backend;
pub mod i18n;
pub mod model;
pub mod revealed;
pub mod theme;
pub mod verbs;

#[cfg(test)]
pub mod testing;

#[cfg(feature = "gpui")]
pub mod app;
#[cfg(feature = "gpui")]
pub mod assets;
#[cfg(feature = "gpui")]
pub mod views;

#[cfg(feature = "gpui")]
pub use app::AkeyApp;

pub use backend::{Backend, BackendError, Outcome};
pub use revealed::{RevealState, Revealed};
pub use verbs::{Akey, ConflictSide, ListFilter, Startup, SyncResult};

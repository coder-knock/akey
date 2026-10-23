//! Harness integration: one pipeline that installs akey into AI agent harnesses.
//!
//! The module is split by responsibility rather than by agent:
//!
//! * [`registry`] answers **what harnesses exist and where their files live**.
//! * [`config`] answers **how one config file is inspected, planned, and edited**.
//! * [`skill`] answers **how the agent-facing skill document is installed and versioned**.
//! * `selection` answers **which harnesses a command applies to**.
//! * `native` answers **how a harness CLI is invoked when it can add an entry**.
//! * `install` and `uninstall` own the two write lifecycles; `inspect` owns the
//!   read-only commands (`list`, `status`, `print`).
//!
//! Nothing here branches on an agent name except the registry table. Adding a harness is
//! a registry row (plus an adapter arm only when its config grammar is new), not another
//! installer.
//!
//! Everything is planned before anything is applied. A malformed config or a hand-edited
//! skill therefore stops the whole install instead of leaving a half-configured machine;
//! because every writer is idempotent, rerunning after a failure is always safe.

pub mod config;
mod inspect;
mod install;
mod native;
pub mod registry;
mod selection;
pub mod skill;
mod uninstall;

use std::path::Path;

pub use inspect::{
    HarnessInfo, HarnessPrint, HarnessStatus, ListReport, McpPrint, McpStatus, NativeStatus,
    PrintReport, PrintRequest, SkillPrint, SkillStatus, StatusReport, StatusRequest, list, print,
    status,
};
pub use install::{
    HarnessInstall, InstallReport, InstallRequest, McpInstall, SkillInstall, install,
};
pub use native::NativeMode;
pub use registry::{Only, Scope};
pub use selection::{Selection, select, supported_ids};
pub use uninstall::{
    HarnessUninstall, McpUninstall, SkillUninstall, UninstallReport, UninstallRequest, uninstall,
};

/// Render a path relative to the user home, so `agent` output is readable and portable.
fn display_path(path: &Path, home: &Path) -> String {
    if let Ok(rest) = path.strip_prefix(home)
        && !rest.as_os_str().is_empty()
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests;

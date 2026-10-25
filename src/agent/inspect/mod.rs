//! Read-only harness inspection: `list`, `status`, and `print`.
//!
//! These commands never modify a harness. `status` is deliberately tolerant of bad user
//! data: an unreadable config or an unmanaged skill becomes a row, not a failed command,
//! so one broken harness cannot hide the state of the rest.

mod list;
mod print;
mod status;

pub use list::{HarnessInfo, ListReport, list};
pub use print::{HarnessPrint, McpPrint, PrintReport, PrintRequest, SkillPrint, print};
pub use status::{
    HarnessStatus, McpStatus, NativeStatus, SkillStatus, StatusReport, StatusRequest, status,
};

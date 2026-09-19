//! Audit log: machine-local append-only JSONL.
//!
//! Records **who** (device name) did **what** to **which entry** **when**, plus the outcome.
//! Plaintext values are never recorded — that is NFR-9, pinned by a test.

use std::fs::OpenOptions;
use std::io::Write;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths::{self, Paths};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Init,
    Read,
    Reveal,
    Inject,
    Write,
    Delete,
    Restore,
    Sync,
    DeviceAdd,
    DeviceRemove,
    TokenIssue,
    TokenRevoke,
    Recover,
    Export,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        serde_plain_name(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub device: String,
    pub action: Action,
    /// Entry name or device name; never the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// `ok` / `denied` / an error code.
    pub outcome: String,
}

/// Appends one record. Auditing is a MUST (FR-12); if it cannot be written that is a real failure — never silently swallowed.
pub fn record(
    paths: &Paths,
    device: &str,
    action: Action,
    subject: Option<&str>,
    outcome: &str,
) -> Result<()> {
    let record = AuditRecord {
        ts: Utc::now(),
        device: device.to_string(),
        action,
        subject: subject.map(str::to_string),
        outcome: outcome.to_string(),
    };
    append(paths, &record)
}

fn append(paths: &Paths, record: &AuditRecord) -> Result<()> {
    paths.ensure()?;
    let mut line =
        serde_json::to_string(record).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    line.push('\n');

    let mut file =
        paths::owner_only(OpenOptions::new().create(true).append(true)).open(&paths.audit)?;
    file.write_all(line.as_bytes())?;
    file.sync_data()?;
    Ok(())
}

/// Reads the most recent `limit` records (returned in ascending time order).
pub fn tail(paths: &Paths, limit: usize) -> Result<Vec<AuditRecord>> {
    if !paths.audit.is_file() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&paths.audit)?;
    let mut records: Vec<AuditRecord> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if records.len() > limit {
        records.drain(..records.len() - limit);
    }
    Ok(records)
}

/// The `serde` `snake_case` name, for human output.
fn serde_plain_name(action: Action) -> &'static str {
    match action {
        Action::Init => "init",
        Action::Read => "read",
        Action::Reveal => "reveal",
        Action::Inject => "inject",
        Action::Write => "write",
        Action::Delete => "delete",
        Action::Restore => "restore",
        Action::Sync => "sync",
        Action::DeviceAdd => "device_add",
        Action::DeviceRemove => "device_remove",
        Action::TokenIssue => "token_issue",
        Action::TokenRevoke => "token_revoke",
        Action::Recover => "recover",
        Action::Export => "export",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("akey"));
        paths.ensure().unwrap();
        (dir, paths)
    }

    #[test]
    fn records_round_trip_in_append_order() {
        let (_guard, paths) = setup();
        record(&paths, "macbook", Action::Read, Some("openai"), "ok").unwrap();
        record(&paths, "macbook", Action::Write, Some("github"), "ok").unwrap();

        let records = tail(&paths, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, Action::Read);
        assert_eq!(records[1].action, Action::Write);
        assert_eq!(records[1].subject.as_deref(), Some("github"));
    }

    #[test]
    fn tail_returns_only_the_most_recent_records() {
        let (_guard, paths) = setup();
        for i in 0..5 {
            record(&paths, "d", Action::Read, Some(&format!("e{i}")), "ok").unwrap();
        }
        let records = tail(&paths, 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].subject.as_deref(), Some("e3"));
        assert_eq!(records[1].subject.as_deref(), Some("e4"));
    }

    /// NFR-9: plaintext field values must never appear in the audit log.
    #[test]
    fn log_never_contains_secret_material() {
        let (_guard, paths) = setup();
        record(&paths, "macbook", Action::Reveal, Some("openai"), "ok").unwrap();

        let raw = std::fs::read_to_string(&paths.audit).unwrap();
        assert!(raw.contains("openai"), "subject should be recorded");
        assert!(raw.contains("macbook"));
        for forbidden in ["sk-", "hunter2", "Bearer"] {
            assert!(!raw.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn audit_file_is_owner_only() {
        let (_guard, paths) = setup();
        record(&paths, "d", Action::Init, None, "ok").unwrap();
        assert!(!paths::permissions_exposed(&paths.audit).unwrap());
    }

    #[test]
    fn missing_log_reads_as_empty() {
        let (_guard, paths) = setup();
        assert!(tail(&paths, 10).unwrap().is_empty());
    }
}

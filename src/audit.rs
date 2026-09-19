//! 审计日志：本地 append-only JSONL。
//!
//! 记录**谁**（设备名）在**何时**对**哪个条目**做了**什么**以及结果。
//! 绝不记录明文值——这是 NFR-9，有测试钉住。

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

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
    /// 条目名或设备名；不含值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// `ok` / `denied` / 错误码。
    pub outcome: String,
}

/// 追加一条记录。审计是 MUST（FR-12），写不进去就是真失败——不静默吞掉。
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
    let mut line = serde_json::to_string(record).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(paths::FILE_MODE)
        .open(&paths.audit)?;
    file.write_all(line.as_bytes())?;
    file.sync_data()?;
    Ok(())
}

/// 读取最近 `limit` 条（返回时间升序）。
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

/// `serde` 的 `snake_case` 名，供人类输出使用。
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

    /// NFR-9：审计日志里永远不得出现明文字段值。
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

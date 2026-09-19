//! `recipients.json` —— 仓库内的公开收件人清单（设备 + 引导身份）。
//!
//! 只含公钥，泄露无害；`revoked_at` 一旦置位即不再作为加密收件人。

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths;

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecipientKind {
    /// 某台设备的身份。
    Device,
    /// 恢复密码解出的引导身份。
    Bootstrap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientRecord {
    pub name: String,
    pub kind: RecipientKind,
    pub added_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl RecipientRecord {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipients {
    pub version: u32,
    pub recipients: BTreeMap<String, RecipientRecord>,
}

impl Default for Recipients {
    fn default() -> Self {
        Recipients {
            version: FORMAT_VERSION,
            recipients: BTreeMap::new(),
        }
    }
}

impl Recipients {
    /// 加入一个公钥。已存在且未吊销时只刷新 `last_seen_at`。
    ///
    /// 已吊销的记录视为**重新加入**：清掉 `revoked_at`，用调用方给的名字/类型覆盖，
    /// 并刷新 `last_seen_at`；`added_at` 保留首次加入时间（历史不丢）。
    pub fn add(&mut self, pubkey: &str, name: &str, kind: RecipientKind, now: DateTime<Utc>) {
        match self.recipients.get_mut(pubkey) {
            Some(record) => {
                if record.revoked_at.take().is_some() {
                    // 重新加入：身份可能换了名字/类型，要跟上。
                    record.name = name.to_string();
                    record.kind = kind;
                }
                record.last_seen_at = Some(now);
            }
            None => {
                self.recipients.insert(
                    pubkey.to_string(),
                    RecipientRecord {
                        name: name.to_string(),
                        kind,
                        added_at: now,
                        last_seen_at: Some(now),
                        revoked_at: None,
                    },
                );
            }
        }
    }

    /// 标记吊销。名字不存在 → `not_found`。已吊销时幂等（不覆盖原 `revoked_at`）。
    pub fn revoke(&mut self, name: &str, now: DateTime<Utc>) -> Result<()> {
        match self.recipients.iter_mut().find(|(_, r)| r.name == name) {
            Some((_, record)) => {
                if record.revoked_at.is_none() {
                    record.revoked_at = Some(now);
                }
                Ok(())
            }
            None => Err(Error::not_found(format!("no recipient named {name}"))),
        }
    }

    /// 未吊销的公钥文本，供加密使用。`BTreeMap` 保证按 pubkey 升序 → 顺序确定。
    pub fn active_pubkeys(&self) -> Vec<String> {
        self.recipients
            .iter()
            .filter(|(_, r)| r.is_active())
            .map(|(pubkey, _)| pubkey.clone())
            .collect()
    }

    /// 未吊销的 `(name, pubkey)`，按 name 升序。
    pub fn active_named(&self) -> Vec<(&str, &str)> {
        let mut named: Vec<(&str, &str)> = self
            .recipients
            .iter()
            .filter(|(_, r)| r.is_active())
            .map(|(pubkey, r)| (r.name.as_str(), pubkey.as_str()))
            .collect();
        named.sort_unstable();
        named
    }

    pub fn find_by_name(&self, name: &str) -> Option<(&String, &RecipientRecord)> {
        self.recipients.iter().find(|(_, r)| r.name == name)
    }

    /// 解析为 age 收件人。任一公钥非法 → `corrupt`（消息里带上那个公钥）。
    pub fn to_recipients(&self) -> Result<Vec<age::x25519::Recipient>> {
        self.active_pubkeys()
            .into_iter()
            .map(|pubkey| {
                pubkey.parse::<age::x25519::Recipient>().map_err(|_| {
                    Error::corrupt(format!("invalid age recipient public key: {pubkey}"))
                })
            })
            .collect()
    }

    /// 读取 `recipients.json`。文件不存在 → `locked`（提示先 `akey init`）；
    /// JSON 不合法 → `corrupt`。
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = paths::read_file(path)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            Error::corrupt(format!("{}: invalid recipients json: {e}", path.display()))
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::corrupt(format!("failed to serialize recipients: {e}")))?;
        bytes.push(b'\n');
        paths::atomic_write(path, &bytes, paths::FILE_MODE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// 真实公钥（私钥随即丢弃）。
    fn key() -> String {
        age::x25519::Identity::generate().to_public().to_string()
    }

    /// 固定时间戳，测试确定性。
    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid fixed timestamp")
    }

    #[test]
    fn add_creates_then_refreshes_last_seen_without_duplicating() {
        let pubkey = key();
        let mut recipients = Recipients::default();
        recipients.add(&pubkey, "macbook", RecipientKind::Device, at(0));

        assert_eq!(recipients.active_pubkeys(), vec![pubkey.clone()]);
        let (found_key, record) = recipients.find_by_name("macbook").expect("record");
        assert_eq!(found_key, &pubkey);
        assert_eq!(record.added_at, at(0));
        assert_eq!(record.last_seen_at, Some(at(0)));
        assert!(record.is_active());

        // 同一公钥再次加入：只刷新 last_seen_at，不产生第二条记录。
        recipients.add(&pubkey, "macbook", RecipientKind::Device, at(60));
        assert_eq!(recipients.recipients.len(), 1);
        let record = &recipients.find_by_name("macbook").expect("record").1;
        assert_eq!(record.last_seen_at, Some(at(60)));
        assert_eq!(record.added_at, at(0));
    }

    #[test]
    fn revoke_hides_pubkey_and_unknown_name_is_not_found() {
        let kept = key();
        let dropped = key();
        let mut recipients = Recipients::default();
        recipients.add(&kept, "desktop", RecipientKind::Device, at(0));
        recipients.add(&dropped, "macbook", RecipientKind::Device, at(0));

        recipients.revoke("macbook", at(10)).expect("revoke");
        assert_eq!(recipients.active_pubkeys(), vec![kept.clone()]);
        assert_eq!(recipients.active_named(), vec![("desktop", kept.as_str())]);
        assert!(!recipients.active_pubkeys().contains(&dropped));

        // 幂等：再次吊销不覆盖原 revoked_at。
        recipients.revoke("macbook", at(99)).expect("idempotent");
        let revoked = recipients.find_by_name("macbook").expect("record").1;
        assert_eq!(revoked.revoked_at, Some(at(10)));

        let err = recipients
            .revoke("ghost", at(1))
            .expect_err("unknown name must fail");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn rejoin_after_revoke_clears_revoked_at() {
        let pubkey = key();
        let mut recipients = Recipients::default();
        recipients.add(&pubkey, "old-laptop", RecipientKind::Device, at(0));
        recipients.revoke("old-laptop", at(10)).expect("revoke");
        assert!(recipients.active_pubkeys().is_empty());
        assert!(recipients.to_recipients().expect("no keys").is_empty());

        // 同一公钥重新加入 → 重新变活跃。
        recipients.add(&pubkey, "new-laptop", RecipientKind::Device, at(20));
        assert_eq!(recipients.active_pubkeys(), vec![pubkey.clone()]);
        let record = &recipients.find_by_name("new-laptop").expect("record").1;
        assert!(record.revoked_at.is_none());
        assert_eq!(record.last_seen_at, Some(at(20)));
        assert_eq!(record.added_at, at(0));
        // 旧名字不再指向任何记录。
        assert!(recipients.find_by_name("old-laptop").is_none());
    }

    #[test]
    fn to_recipients_skips_revoked_and_rejects_invalid_pubkey() {
        let live = key();
        let dead = key();
        let mut recipients = Recipients::default();
        recipients.add(&live, "live", RecipientKind::Device, at(0));
        recipients.add(&dead, "dead", RecipientKind::Device, at(0));
        recipients.revoke("dead", at(1)).expect("revoke");

        let parsed = recipients.to_recipients().expect("valid keys");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_string(), live);

        recipients.add("age1not-a-real-key", "bogus", RecipientKind::Bootstrap, at(2));
        let err = recipients
            .to_recipients()
            .expect_err("invalid pubkey must fail");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert!(err.to_string().contains("age1not-a-real-key"), "{err}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn save_then_load_roundtrips_with_private_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recipients.json");

        let mut recipients = Recipients::default();
        recipients.add(&key(), "macbook", RecipientKind::Device, at(0));
        recipients.add(&key(), "bootstrap", RecipientKind::Bootstrap, at(5));
        recipients.add(&key(), "retired", RecipientKind::Device, at(6));
        recipients.revoke("retired", at(7)).expect("revoke");

        recipients.save(&path).expect("save");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, paths::FILE_MODE);

        let back = Recipients::load(&path).expect("load");
        assert_eq!(back, recipients);
        assert_eq!(back.active_pubkeys(), recipients.active_pubkeys());
        assert_eq!(back.active_named(), recipients.active_named());
    }

    #[test]
    fn load_missing_file_is_locked_and_malformed_json_is_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");

        let missing = dir.path().join("absent.json");
        let err = Recipients::load(&missing).expect_err("missing file");
        assert!(matches!(err, Error::Locked(_)), "{err:?}");
        assert_eq!(err.exit_code(), 4);
        assert!(err.to_string().contains("akey init"), "{err}");

        let broken = dir.path().join("broken.json");
        fs::write(&broken, b"{\"version\": 1, ").unwrap();
        let err = Recipients::load(&broken).expect_err("malformed json");
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn active_lists_are_sorted_and_independent_of_insertion_order() {
        let mut keys: Vec<String> = (0..5).map(|_| key()).collect();
        keys.sort();

        // 名字与公钥顺序**反向**：若实现漏了按 name 排序，立刻暴露。
        let name_of = |i: usize| format!("dev-{}", keys.len() - 1 - i);

        let mut forward = Recipients::default();
        let mut backward = Recipients::default();
        for (i, pubkey) in keys.iter().enumerate() {
            forward.add(pubkey, &name_of(i), RecipientKind::Device, at(0));
        }
        for (i, pubkey) in keys.iter().enumerate().rev() {
            backward.add(pubkey, &name_of(i), RecipientKind::Device, at(0));
        }

        // 公钥按字典序，且与插入顺序无关。
        assert_eq!(forward.active_pubkeys(), keys);
        assert_eq!(backward.active_pubkeys(), keys);

        let mut expected: Vec<(String, String)> = keys
            .iter()
            .enumerate()
            .map(|(i, pubkey)| (name_of(i), pubkey.clone()))
            .collect();
        expected.sort();
        let expected: Vec<(&str, &str)> = expected
            .iter()
            .map(|(name, pubkey)| (name.as_str(), pubkey.as_str()))
            .collect();

        assert_eq!(forward.active_named(), expected);
        assert_eq!(backward.active_named(), expected);
    }
}

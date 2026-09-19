//! 三方合并。纯函数、无 IO、确定性——同输入必得同输出。
//!
//! 规则表见 `REQUIREMENTS.md` §11.1；两条工程约束见 `DESIGN.md` §9：
//! 冲突副本 ID 必须可复现（否则每次同步都会再产出一个副本），且删除不比修改强。

use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use ulid::Ulid;

use crate::vault::model::{Entry, MAX_NAME_LEN, TokenMeta, Vault};

/// 冲突副本额外携带的标签。
pub const CONFLICT_TAG: &str = "conflict";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// 双方各自修改了同一条目。
    ValueDiverged,
    /// 一边软删、一边修改。
    DeleteVsEdit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    /// 冲突所在的原条目 ID。
    pub id: Ulid,
    pub name: String,
    pub kind: ConflictKind,
    /// 对端版本被保留为独立条目时的 ID。
    pub conflict_id: Ulid,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MergeStats {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub conflicts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeResult {
    pub vault: Vault,
    pub conflicts: Vec<Conflict>,
    pub stats: MergeStats,
}

/// 冲突副本的 ID：由 (原 ID, 对端 updated_at, 对端内容哈希) 派生。
///
/// 两台设备独立合并同一分歧时必须算出同一个 ID，否则每轮同步都会再生一个副本。
pub fn conflict_copy_id(id: Ulid, updated_at: DateTime<Utc>, value_hash: [u8; 32]) -> Ulid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(id.to_bytes());
    // 时间戳按 RFC3339 纳秒精度入哈希：`vault.age` 解密后两台设备看到的是同一段 JSON，
    // 只要序列化可无损往返（chrono 的 serde 编解码即是如此），摘要就逐位一致。
    hasher.update(updated_at.to_rfc3339_opts(SecondsFormat::Nanos, true).as_bytes());
    hasher.update(value_hash);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Ulid::from_bytes(bytes)
}

/// 冲突副本的条目名：`<name>.conflict.<短ID>`。
///
/// 条目名上限是 `MAX_NAME_LEN`，而原名本身可以长到该上限，直接拼接会越界——
/// 原名过长时按字符边界截断再拼（合法名是纯 ASCII，截断不会切坏 UTF-8），
/// 保证 `is_valid_name(conflict_copy_name(name, id))` 对任何合法 `name` 都成立。
pub fn conflict_copy_name(name: &str, conflict_id: Ulid) -> String {
    let tag = conflict_id.to_string();
    let suffix = format!(".conflict.{}", tag[tag.len() - 8..].to_lowercase());
    let budget = MAX_NAME_LEN.saturating_sub(suffix.len());
    let head = if name.len() > budget {
        let cut = (0..=budget)
            .rev()
            .find(|&i| name.is_char_boundary(i))
            .unwrap_or(0);
        &name[..cut]
    } else {
        name
    };
    format!("{head}{suffix}")
}

/// 单条目的合并结论。
///
/// 变体体积差异大是刻意的：它是**转瞬即逝**的中间值，装箱反而多一次堆分配。
#[allow(clippy::large_enum_variant)]
enum Resolution {
    /// 结果里不含这个条目（删除生效，或已被墓碑抑制）。
    Drop,
    /// 原 ID 保留这个版本。
    Keep(Entry),
    /// 双方分歧：ours 占用原 ID，theirs 另存为冲突副本。
    KeepWithCopy {
        winner: Entry,
        copy: Entry,
        kind: ConflictKind,
    },
}

/// 三方合并。纯函数：不读盘、不取系统时间、不产生随机数。
pub fn merge3(base: &Vault, ours: &Vault, theirs: &Vault) -> MergeResult {
    let purged = merge_purged(&ours.purged, &theirs.purged);

    let mut vault = Vault {
        // 容器元数据以本机工作区为准（两台设备上的 vault 名与格式版本本就相同，
        // 取谁都一样，固定取 ours 是为了"同输入必得同输出"）。
        version: ours.version,
        vault: ours.vault.clone(),
        entries: BTreeMap::new(),
        tokens: BTreeMap::new(),
        purged,
    };

    // 三方的 ID 取并集；`BTreeSet` 迭代天然有序，保证输出与遍历顺序无关。
    let mut ids: BTreeSet<Ulid> = BTreeSet::new();
    ids.extend(base.entries.keys().copied());
    ids.extend(ours.entries.keys().copied());
    ids.extend(theirs.entries.keys().copied());

    let mut conflicts: Vec<Conflict> = Vec::new();
    for id in ids {
        // 墓碑优先于一切：被 purge 过的 ID 不得被对端复活，也不报冲突。
        if vault.purged.contains_key(&id) {
            continue;
        }
        match resolve_entry(
            base.entries.get(&id),
            ours.entries.get(&id),
            theirs.entries.get(&id),
        ) {
            Resolution::Drop => {}
            Resolution::Keep(entry) => {
                vault.entries.insert(id, entry);
            }
            Resolution::KeepWithCopy { winner, copy, kind } => {
                let conflict_id = copy.id;
                conflicts.push(Conflict {
                    id,
                    name: winner.name.clone(),
                    kind,
                    conflict_id,
                });
                vault.entries.insert(id, winner);
                vault.entries.insert(conflict_id, copy);
            }
        }
    }

    // 令牌按同一套规则合并（令牌没有"内容分歧"的概念，选择见 `merge_token`）。
    let mut token_ids: BTreeSet<Ulid> = BTreeSet::new();
    token_ids.extend(base.tokens.keys().copied());
    token_ids.extend(ours.tokens.keys().copied());
    token_ids.extend(theirs.tokens.keys().copied());
    for id in token_ids {
        let merged = match (ours.tokens.get(&id), theirs.tokens.get(&id)) {
            (Some(o), Some(t)) => merge_token(base.tokens.get(&id), o, t),
            (Some(o), None) => o.clone(),
            (None, Some(t)) => t.clone(),
            // 只存在于 base：双方都把它去掉了（吊销后清理），不复活。
            (None, None) => continue,
        };
        vault.tokens.insert(id, merged);
    }

    // 遍历已有序，这里只是把"按条目 ID 排序"写成显式契约。
    conflicts.sort_by_key(|c| c.id);

    let stats = stats_against(ours, &vault.entries, conflicts.len());
    MergeResult {
        vault,
        conflicts,
        stats,
    }
}

/// 按条目 ID 对齐的合并规则（`REQUIREMENTS.md` §11.1 的逐条实现）。
fn resolve_entry(
    base: Option<&Entry>,
    ours: Option<&Entry>,
    theirs: Option<&Entry>,
) -> Resolution {
    match (base, ours, theirs) {
        // 两边都没有：只可能来自 base——双方都去掉了它（`rm --purge` 后墓碑已过 90 天）。
        (_, None, None) => Resolution::Drop,

        // 只有本机有。
        (b, Some(o), None) => match b {
            // 本机没动过 → 对端的删除生效（墓碑过期后同样只剩"对端没有"这一种证据）。
            Some(b) if o == b => Resolution::Drop,
            // 本机改过 → 保留本机改动，绝不静默丢数据。对端那一侧没有任何版本可言，
            // 无从保留，因此不计冲突。
            _ => Resolution::Keep(o.clone()),
        },

        // 只有对端有——上面那条的镜像。
        (b, None, Some(t)) => match b {
            Some(b) if t == b => Resolution::Drop,
            _ => Resolution::Keep(t.clone()),
        },

        (b, Some(o), Some(t)) => {
            if o == t {
                // 两边一致（含"各自新增了同一条"）：取一方即可。
                return Resolution::Keep(o.clone());
            }
            if let Some(base) = b {
                if o == base {
                    // 只有对端改过 → 取 theirs。
                    return Resolution::Keep(with_newer_updated_at(t, o, t));
                }
                if t == base {
                    // 只有本机改过 → 取 ours。
                    return Resolution::Keep(with_newer_updated_at(o, o, t));
                }
            }
            // 双方都改过且不同（含双方各自新增了同 ID 的不同内容）→ 冲突：
            // ours 占原 ID，theirs 落为可复现 ID 的独立副本；一边软删一边改时，
            // 改动版本照样被保留下来（"删除不比修改强"）。
            let copy = conflict_copy(t);
            let kind = if o.is_deleted() == t.is_deleted() {
                ConflictKind::ValueDiverged
            } else {
                ConflictKind::DeleteVsEdit
            };
            Resolution::KeepWithCopy {
                winner: with_newer_updated_at(o, o, t),
                copy,
                kind,
            }
        }
    }
}

/// 合并结果里的 `updated_at` 取双方较新者（相等取 ours）。
///
/// `max` 可交换，因此两台设备对同一分歧算出的时间戳一致。
fn with_newer_updated_at(winner: &Entry, ours: &Entry, theirs: &Entry) -> Entry {
    let mut entry = winner.clone();
    entry.updated_at = max(ours.updated_at, theirs.updated_at);
    entry
}

/// 把对端版本复制成独立条目：ID 与名字都由对端版本的内容派生。
fn conflict_copy(source: &Entry) -> Entry {
    let id = conflict_copy_id(source.id, source.updated_at, source.value_hash());
    let mut copy = source.clone();
    copy.id = id;
    copy.name = conflict_copy_name(&source.name, id);
    if !copy.tags.iter().any(|tag| tag == CONFLICT_TAG) {
        copy.tags.push(CONFLICT_TAG.to_string());
    }
    copy
}

/// 墓碑取并集；同一 ID 取**较早**的删除时间（先删的那一刻才是事实）。
fn merge_purged(
    ours: &BTreeMap<Ulid, DateTime<Utc>>,
    theirs: &BTreeMap<Ulid, DateTime<Utc>>,
) -> BTreeMap<Ulid, DateTime<Utc>> {
    let mut merged = ours.clone();
    for (id, at) in theirs {
        merged
            .entry(*id)
            .and_modify(|existing| *existing = min(*existing, *at))
            .or_insert(*at);
    }
    merged
}

/// 令牌元数据按 ID 合并。
///
/// 选择说明：`last_used_at` 只是"有没有被用过"，不足以判定内容分歧的胜负，因此
/// 双方都改过且不同时取 `last_used_at` 较新的一方（相等取 ours）——两台设备独立
/// 合并同一分歧时会算出同一份结果。
///
/// 但**撤销不可逆**：任一侧已 `revoked_at`，结果就是已撤销的，撤销时间取较早者。
/// 否则一台设备刚吊销的令牌，会被另一台设备上更早写下的 `last_used_at` 复活
/// ——这是安全回归，与条目层"墓碑不得被复活"同源。
fn merge_token(base: Option<&TokenMeta>, ours: &TokenMeta, theirs: &TokenMeta) -> TokenMeta {
    let mut winner = if ours == theirs {
        ours.clone()
    } else if base == Some(ours) {
        theirs.clone()
    } else if base == Some(theirs) {
        ours.clone()
    } else {
        match (ours.last_used_at, theirs.last_used_at) {
            (Some(a), Some(b)) if b > a => theirs.clone(),
            (None, Some(_)) => theirs.clone(),
            _ => ours.clone(),
        }
    };
    winner.revoked_at = match (ours.revoked_at, theirs.revoked_at) {
        (Some(a), Some(b)) => Some(min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    winner
}

/// 统计相对本机工作区真实发生的动作：新增 / 更新 / 移除 / 冲突。
fn stats_against(
    ours: &Vault,
    merged: &BTreeMap<Ulid, Entry>,
    conflicts: usize,
) -> MergeStats {
    let added = merged
        .keys()
        .filter(|id| !ours.entries.contains_key(id))
        .count();
    let updated = merged
        .iter()
        .filter(|(id, entry)| ours.entries.get(id).is_some_and(|before| before != *entry))
        .count();
    let removed = ours
        .entries
        .keys()
        .filter(|id| !merged.contains_key(id))
        .count();
    MergeStats {
        added,
        updated,
        removed,
        conflicts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{is_valid_name, Category, Field, FieldType};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("in-range test timestamp")
    }

    fn id(n: u8) -> Ulid {
        Ulid::from_bytes([n; 16])
    }

    fn entry(id: Ulid, name: &str, value: &str, updated: i64) -> Entry {
        let mut e = Entry::new(id, name.to_string(), Category::Apikey, ts(updated - 10));
        e.fields = vec![Field::new(
            "credential",
            FieldType::Concealed,
            value.to_string(),
        )];
        e.updated_at = ts(updated);
        e
    }

    fn with_value(entry: &Entry, value: &str, updated: i64) -> Entry {
        let mut e = entry.clone();
        e.fields = vec![Field::new(
            "credential",
            FieldType::Concealed,
            value.to_string(),
        )];
        e.updated_at = ts(updated);
        e
    }

    fn deleted(entry: &Entry, at: i64) -> Entry {
        let mut e = entry.clone();
        e.deleted_at = Some(ts(at));
        e.updated_at = ts(at);
        e
    }

    fn vault(entries: Vec<Entry>) -> Vault {
        let mut v = Vault::default();
        for e in entries {
            v.entries.insert(e.id, e);
        }
        v
    }

    fn value_of(entry: &Entry) -> &str {
        entry
            .field("credential")
            .map(Field::value)
            .expect("fixture always carries a credential field")
    }

    /// 双方各自改了同一条目——多数冲突用例的底座。
    fn diverged() -> (Vault, Vault, Vault) {
        let original = entry(id(1), "openai", "v0", 1_000);
        (
            vault(vec![original.clone()]),
            vault(vec![with_value(&original, "ours", 2_000)]),
            vault(vec![with_value(&original, "theirs", 3_000)]),
        )
    }

    // ---- 规则表逐条 ----

    #[test]
    fn rule_new_on_ours_only_keeps_ours() {
        let added = entry(id(1), "openai", "v1", 2_000);
        let ours = vault(vec![added.clone()]);
        let r = merge3(&Vault::default(), &ours, &Vault::default());

        assert_eq!(r.vault.entries.get(&id(1)), Some(&added));
        assert!(r.conflicts.is_empty());
        assert_eq!(
            r.stats,
            MergeStats {
                added: 0,
                updated: 0,
                removed: 0,
                conflicts: 0
            }
        );
    }

    #[test]
    fn rule_new_on_theirs_only_keeps_theirs() {
        let added = entry(id(1), "openai", "v1", 2_000);
        let theirs = vault(vec![added.clone()]);
        let r = merge3(&Vault::default(), &Vault::default(), &theirs);

        assert_eq!(r.vault.entries.get(&id(1)), Some(&added));
        assert!(r.conflicts.is_empty());
        assert_eq!(r.stats.added, 1);
        assert_eq!(r.stats.conflicts, 0);
    }

    #[test]
    fn rule_both_new_identical_keeps_one() {
        let added = entry(id(1), "openai", "v1", 2_000);
        let r = merge3(
            &Vault::default(),
            &vault(vec![added.clone()]),
            &vault(vec![added.clone()]),
        );

        assert_eq!(r.vault.entries.get(&id(1)), Some(&added));
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.entries.len(), 1);
    }

    #[test]
    fn rule_both_new_different_conflicts() {
        let ours = vault(vec![entry(id(1), "openai", "ours", 2_000)]);
        let theirs = vault(vec![entry(id(1), "openai", "theirs", 3_000)]);
        let r = merge3(&Vault::default(), &ours, &theirs);

        assert_eq!(r.conflicts.len(), 1);
        let conflict = &r.conflicts[0];
        assert_eq!(conflict.id, id(1));
        assert_eq!(conflict.kind, ConflictKind::ValueDiverged);
        assert_eq!(value_of(&r.vault.entries[&id(1)]), "ours");
        assert_eq!(value_of(&r.vault.entries[&conflict.conflict_id]), "theirs");
        assert_eq!(r.vault.entries.len(), 2);
    }

    #[test]
    fn rule_theirs_changed_takes_theirs() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let theirs_edit = with_value(&original, "changed", 3_000);
        let r = merge3(
            &vault(vec![original.clone()]),
            &vault(vec![original.clone()]),
            &vault(vec![theirs_edit.clone()]),
        );

        assert!(r.conflicts.is_empty());
        assert_eq!(value_of(&r.vault.entries[&id(1)]), "changed");
        assert_eq!(r.vault.entries[&id(1)].updated_at, ts(3_000));
        assert_eq!(r.stats.updated, 1);
    }

    #[test]
    fn rule_ours_changed_takes_ours() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let ours_edit = with_value(&original, "changed", 2_000);
        let r = merge3(
            &vault(vec![original.clone()]),
            &vault(vec![ours_edit.clone()]),
            &vault(vec![original.clone()]),
        );

        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.entries[&id(1)], ours_edit);
        assert_eq!(
            r.stats.updated, 0,
            "取的就是本机版本，本机没有需要改的东西"
        );
    }

    #[test]
    fn rule_both_changed_identically_takes_ours() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let edited = with_value(&original, "same", 2_000);
        let r = merge3(
            &vault(vec![original]),
            &vault(vec![edited.clone()]),
            &vault(vec![edited.clone()]),
        );

        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.entries[&id(1)], edited);
        assert_eq!(r.vault.entries.len(), 1);
    }

    #[test]
    fn rule_both_changed_differently_keeps_ours_and_copies_theirs() {
        let (base, ours, theirs) = diverged();
        let r = merge3(&base, &ours, &theirs);

        assert_eq!(r.conflicts.len(), 1);
        let conflict = &r.conflicts[0];
        assert_eq!(conflict.id, id(1));
        assert_eq!(conflict.name, "openai", "冲突锚在原条目的名字上");
        assert_eq!(conflict.kind, ConflictKind::ValueDiverged);

        // ours 留在原 ID，且 updated_at 取较新者
        let kept = &r.vault.entries[&id(1)];
        assert_eq!(value_of(kept), "ours");
        assert_eq!(kept.updated_at, ts(3_000));

        // theirs 落为独立副本，内容一字不改
        let copy = &r.vault.entries[&conflict.conflict_id];
        assert_eq!(value_of(copy), "theirs");
        assert_eq!(copy.updated_at, ts(3_000));
        assert!(copy.tags.iter().any(|t| t == CONFLICT_TAG));
        assert_ne!(conflict.conflict_id, id(1));
        assert_eq!(r.stats.conflicts, 1);
        assert_eq!(r.stats.added, 1, "副本是一条真实新增的条目");
    }

    #[test]
    fn rule_delete_beats_unmodified_peer() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let removal = deleted(&original, 2_000);
        let r = merge3(
            &vault(vec![original.clone()]),
            &vault(vec![removal.clone()]),
            &vault(vec![original.clone()]),
        );

        assert!(r.conflicts.is_empty(), "对端未改，删除直接生效");
        assert!(r.vault.entries[&id(1)].is_deleted());
        assert_eq!(r.vault.entries[&id(1)], removal);
    }

    #[test]
    fn rule_delete_with_peer_gone_stays_deleted() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let removal = deleted(&original, 2_000);
        let r = merge3(
            &vault(vec![original]),
            &vault(vec![removal.clone()]),
            &Vault::default(),
        );

        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.entries.get(&id(1)), Some(&removal));
    }

    #[test]
    fn disjoint_additions_merge_without_conflicts() {
        let ours_entry = entry(id(1), "openai", "a", 2_000);
        let theirs_entry = entry(id(2), "tavily", "b", 3_000);
        let base = vault(vec![entry(id(9), "legacy", "old", 500)]);
        let r = merge3(
            &base,
            &vault(vec![ours_entry.clone(), base.entries[&id(9)].clone()]),
            &vault(vec![theirs_entry.clone(), base.entries[&id(9)].clone()]),
        );

        assert!(r.conflicts.is_empty(), "不同条目的改动必须自动合上");
        assert_eq!(r.vault.entries.len(), 3);
        assert_eq!(r.vault.entries.get(&id(1)), Some(&ours_entry));
        assert_eq!(r.vault.entries.get(&id(2)), Some(&theirs_entry));
        assert_eq!(r.stats.added, 1);
        assert_eq!(r.stats.removed, 0);
    }

    // ---- 工程约束 ----

    #[test]
    fn determinism_same_input_same_bytes() {
        let (base, ours, theirs) = rich_fixture();
        let expected = serde_json::to_string(&merge3(&base, &ours, &theirs)).expect("serializable");
        for round in 0..100 {
            let again = serde_json::to_string(&merge3(&base, &ours, &theirs)).expect("serializable");
            assert_eq!(again, expected, "第 {round} 次合并与首次不逐字节相同");
        }
    }

    #[test]
    fn conflict_id_reproducible_across_devices() {
        let (base, ours, theirs) = diverged();
        let source = theirs.entries[&id(1)].clone();

        // 设备 A 的合并结果
        let a = merge3(&base, &ours, &theirs);
        // 设备 C 独立合并：本机版本与 A 不同，但拿到的对端版本是同一份
        let mut other_local = ours.clone();
        other_local.entries.insert(id(1), with_value(&source, "third-device", 4_000));
        let c = merge3(&base, &other_local, &theirs);

        let expected = conflict_copy_id(source.id, source.updated_at, source.value_hash());
        assert_eq!(a.conflicts[0].conflict_id, expected);
        assert_eq!(c.conflicts[0].conflict_id, expected);
        assert_eq!(
            a.vault.entries[&expected].name,
            conflict_copy_name(&source.name, expected)
        );
        assert_eq!(
            c.vault.entries[&expected].name,
            a.vault.entries[&expected].name
        );
        assert_ne!(expected, source.id, "副本 ID 撞原 ID 会直接覆盖原条目");

        // 两台设备只是通过 `vault.age` 的 JSON 看到对端版本的，往返必须无损
        let reread: Entry =
            serde_json::from_str(&serde_json::to_string(&source).expect("serializable"))
                .expect("deserializable");
        assert_eq!(
            conflict_copy_id(reread.id, reread.updated_at, reread.value_hash()),
            expected
        );

        // 同输入重跑（sync 的 push 重试）不得再生一个副本
        let retry = merge3(&base, &ours, &theirs);
        assert_eq!(retry.vault, a.vault);
        assert_eq!(
            retry.vault
                .entries
                .values()
                .filter(|e| e.tags.iter().any(|t| t == CONFLICT_TAG))
                .count(),
            1
        );
    }

    #[test]
    fn delete_vs_edit_keeps_edit_and_records_conflict() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let base = vault(vec![original.clone()]);
        let removal = vault(vec![deleted(&original, 2_000)]);
        let edit = vault(vec![with_value(&original, "v2", 3_000)]);

        // 本机删、对端改 → 原 ID 保留本机的软删状态，改动落到冲突副本里
        let r = merge3(&base, &removal, &edit);
        assert_eq!(r.conflicts.len(), 1);
        let conflict = &r.conflicts[0];
        assert_eq!(conflict.kind, ConflictKind::DeleteVsEdit);
        assert_eq!(conflict.id, id(1));
        assert!(r.vault.entries[&id(1)].is_deleted());
        let copy = &r.vault.entries[&conflict.conflict_id];
        assert_eq!(value_of(copy), "v2", "改动不得被静默丢弃");
        assert!(!copy.is_deleted());

        // 反向：本机改、对端删 → 改动留在原 ID，删除决定记在冲突里
        let r2 = merge3(&base, &edit, &removal);
        assert_eq!(r2.conflicts.len(), 1);
        assert_eq!(r2.conflicts[0].kind, ConflictKind::DeleteVsEdit);
        assert_eq!(value_of(&r2.vault.entries[&id(1)]), "v2");
        let copy2 = &r2.vault.entries[&r2.conflicts[0].conflict_id];
        assert!(copy2.is_deleted(), "对端的软删决定同样不得被静默丢弃");
    }

    #[test]
    fn purge_tombstone_suppresses_resurrection() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let base = vault(vec![original.clone()]);
        let ours = vault(vec![with_value(&original, "still-editing", 2_000)]);

        let mut theirs = Vault::default();
        theirs.purged.insert(id(1), ts(1_500));

        let r = merge3(&base, &ours, &theirs);
        assert!(!r.vault.entries.contains_key(&id(1)), "墓碑不得被复活");
        assert_eq!(r.vault.purged.get(&id(1)), Some(&ts(1_500)));
        assert!(r.conflicts.is_empty(), "被 purge 的条目不是冲突");
        assert_eq!(r.stats.removed, 1);

        // 反向：本机 purge、对端还留着（甚至改过）
        let mut ours_purged = Vault::default();
        ours_purged.purged.insert(id(1), ts(1_500));
        let r2 = merge3(&base, &ours_purged, &ours);
        assert!(!r2.vault.entries.contains_key(&id(1)));

        // 墓碑取并集，同一 ID 取较早时间
        let mut a = Vault::default();
        a.purged.insert(id(1), ts(5_000));
        let mut b = Vault::default();
        b.purged.insert(id(1), ts(1_000));
        b.purged.insert(id(2), ts(2_000));
        let r3 = merge3(&a, &a, &b);
        assert_eq!(r3.vault.purged.get(&id(1)), Some(&ts(1_000)));
        assert_eq!(r3.vault.purged.get(&id(2)), Some(&ts(2_000)));
    }

    #[test]
    fn identical_three_way_merge_is_a_no_op() {
        let mut v = Vault::default();
        v.entries.insert(id(1), entry(id(1), "openai", "v0", 1_000));
        v.entries.insert(id(2), deleted(&entry(id(2), "gone", "v1", 1_100), 1_200));
        v.tokens.insert(id(3), token(&entry(id(3), "ci", "v2", 1_300)));
        v.purged.insert(id(4), ts(900));

        let r = merge3(&v, &v, &v);
        assert_eq!(r.vault, v);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.stats, MergeStats::default());
    }

    #[test]
    fn conflict_copy_name_is_valid_and_distinct() {
        for name in ["openai", "a", "0start", "a.b_c-d", "deep.seek.key"] {
            let original = entry(id(1), name, "v0", 1_000);
            let base = vault(vec![original.clone()]);
            let ours = vault(vec![with_value(&original, "ours", 2_000)]);
            let theirs = vault(vec![with_value(&original, "theirs", 3_000)]);

            let r = merge3(&base, &ours, &theirs);
            let conflict = &r.conflicts[0];
            let copy = &r.vault.entries[&conflict.conflict_id];

            assert!(
                is_valid_name(&copy.name),
                "冲突副本名非法：{}",
                copy.name
            );
            assert_ne!(copy.name, name);
            assert!(
                copy.name.starts_with(&format!("{name}.conflict.")),
                "副本名应挂在原名下：{}",
                copy.name
            );
            assert!(copy.tags.iter().any(|t| t == CONFLICT_TAG));
            assert_eq!(copy.tags.iter().filter(|t| *t == CONFLICT_TAG).count(), 1);
        }
    }

    #[test]
    fn conflict_copy_name_stays_valid_for_max_length_names() {
        for len in [1usize, 46, 47, 48, MAX_NAME_LEN] {
            let name = "a".repeat(len);
            let copy = conflict_copy_name(&name, id(7));
            assert!(
                is_valid_name(&copy),
                "{len} 字符的原名生成了非法副本名：{copy}"
            );
            assert_ne!(copy, name);
        }
        // 副本名不得重复打标签（对端版本本来就带 `conflict`）
        let original = entry(id(1), "openai", "v0", 1_000);
        let mut theirs_entry = with_value(&original, "theirs", 3_000);
        theirs_entry.tags.push(CONFLICT_TAG.to_string());
        let r = merge3(
            &vault(vec![original.clone()]),
            &vault(vec![with_value(&original, "ours", 2_000)]),
            &vault(vec![theirs_entry]),
        );
        let copy = &r.vault.entries[&r.conflicts[0].conflict_id];
        assert_eq!(copy.tags.iter().filter(|t| *t == CONFLICT_TAG).count(), 1);
    }

    // ---- 令牌 ----

    fn token(source: &Entry) -> TokenMeta {
        TokenMeta {
            id: source.id,
            name: source.name.clone(),
            hash: zeroize::Zeroizing::new("hash".to_string()),
            allow: None,
            deny_reveal: false,
            expires_at: None,
            created_at: source.created_at,
            last_used_at: None,
            revoked_at: None,
        }
    }

    fn token_vault(tokens: Vec<TokenMeta>) -> Vault {
        let mut v = Vault::default();
        for t in tokens {
            v.tokens.insert(t.id, t);
        }
        v
    }

    #[test]
    fn tokens_merge_and_revocation_is_irreversible() {
        let seed = entry(id(5), "ci", "v0", 1_000);
        let base_token = token(&seed);

        // 一方吊销、另一方刚用过 → 吊销必须赢，否则被吊销的令牌会被复活
        let mut revoked = base_token.clone();
        revoked.revoked_at = Some(ts(3_000));
        let mut used = base_token.clone();
        used.last_used_at = Some(ts(4_000));
        let r = merge3(
            &token_vault(vec![base_token.clone()]),
            &token_vault(vec![revoked]),
            &token_vault(vec![used]),
        );
        let merged = r.vault.tokens.get(&id(5)).expect("令牌不得消失");
        assert_eq!(merged.revoked_at, Some(ts(3_000)));
        assert_eq!(merged.last_used_at, Some(ts(4_000)), "较新的使用时间要留下");

        // 都无法吊销 → 取 last_used_at 较新者，且两台设备算出同一份
        let mut older = base_token.clone();
        older.last_used_at = Some(ts(5_000));
        let mut newer = base_token.clone();
        newer.last_used_at = Some(ts(6_000));
        let empty = Vault::default();
        let a = merge3(&empty, &token_vault(vec![older.clone()]), &token_vault(vec![newer.clone()]));
        let b = merge3(&empty, &token_vault(vec![newer]), &token_vault(vec![older]));
        assert_eq!(a.vault, b.vault);
        assert_eq!(a.vault.tokens[&id(5)].last_used_at, Some(ts(6_000)));

        // 只在一侧出现的令牌保留；只剩 base 的令牌不复活
        let lone = token(&entry(id(6), "solo", "v1", 1_100));
        let r2 = merge3(
            &token_vault(vec![base_token]),
            &Vault::default(),
            &token_vault(vec![lone.clone()]),
        );
        assert_eq!(r2.vault.tokens.len(), 1);
        assert_eq!(r2.vault.tokens.get(&id(6)), Some(&lone));
    }

    // ---- 统计与排序 ----

    #[test]
    fn stats_count_real_actions() {
        let (base, ours, theirs) = rich_fixture();
        let r = merge3(&base, &ours, &theirs);

        // 相对本机（ours）：对端带来 1 条新条目（id 3）+ 2 个冲突副本
        assert_eq!(r.stats.added, 3);
        // id 1 分歧保留 ours 但 updated_at 取新、id 4 删除 vs 修改、id 6 对端软删 → 都是内容变化
        assert_eq!(r.stats.updated, 3);
        // id 8 对端物理删除且本机未改 → 从本机结果里消失
        assert_eq!(r.stats.removed, 1);
        assert_eq!(r.stats.conflicts, 2);
        assert_eq!(r.conflicts.len(), 2);

        let mut ids: Vec<Ulid> = r.conflicts.iter().map(|c| c.id).collect();
        let sorted = {
            let mut copy = ids.clone();
            copy.sort_unstable();
            copy
        };
        assert_eq!(ids, sorted, "conflicts 必须按条目 ID 排序");
        ids.dedup();
        assert_eq!(ids.len(), r.conflicts.len());
    }

    /// 覆盖全部规则分支的一份输入：分歧、各自新增、删除 vs 修改、双方同改、对端软删、对端物理删。
    fn rich_fixture() -> (Vault, Vault, Vault) {
        let mutable = entry(id(1), "openai", "v0", 1_000);
        let same_edit = entry(id(5), "both", "v0", 1_000);
        let doomed = entry(id(6), "doomed", "v0", 1_000);
        let doomed_removal = deleted(&doomed, 3_000);
        let deleted_edit = entry(id(4), "github", "v0", 1_000);
        let dropped = entry(id(8), "dropped", "v0", 700);
        let shared = entry(id(9), "shared", "v0", 800);

        let mut base = vault(vec![
            mutable.clone(),
            same_edit.clone(),
            doomed.clone(),
            deleted_edit.clone(),
            dropped.clone(),
            shared.clone(),
        ]);
        base.tokens.insert(id(7), token(&entry(id(7), "ci", "v0", 900)));

        let mut ours = vault(vec![
            with_value(&mutable, "ours", 2_000),
            with_value(&same_edit, "both-edited", 2_500),
            deleted(&deleted_edit, 2_400),
            doomed.clone(),
            dropped,
            shared.clone(),
            entry(id(2), "only-ours", "x", 2_100),
        ]);
        ours.tokens.insert(id(7), token(&entry(id(7), "ci", "v0", 900)));

        let mut theirs = vault(vec![
            with_value(&mutable, "theirs", 3_000),
            with_value(&same_edit, "both-edited", 2_500),
            with_value(&deleted_edit, "edited", 3_100),
            doomed_removal,
            shared,
            entry(id(3), "only-theirs", "y", 3_200),
        ]);
        let mut theirs_token = token(&entry(id(7), "ci", "v0", 900));
        theirs_token.last_used_at = Some(ts(3_300));
        theirs.tokens.insert(id(7), theirs_token);

        (base, ours, theirs)
    }
}

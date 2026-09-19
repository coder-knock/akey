//! Three-way merge. Pure, no I/O, deterministic — the same input always yields the same output.
//!
//! The rule table is in `REQUIREMENTS.md` §11.1; the two engineering constraints are in `DESIGN.md` §9:
//! conflict-copy IDs must be reproducible (otherwise every sync mints yet another copy), and a delete must not outrank an edit.

use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use ulid::Ulid;

use crate::vault::model::{Entry, MAX_NAME_LEN, TokenMeta, Vault};

/// The extra tag every conflict copy carries.
pub const CONFLICT_TAG: &str = "conflict";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Both sides edited the same entry.
    ValueDiverged,
    /// One side soft-deleted while the other edited.
    DeleteVsEdit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    /// ID of the original entry the conflict sits on.
    pub id: Ulid,
    pub name: String,
    pub kind: ConflictKind,
    /// ID under which the remote version is kept as a standalone entry.
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

/// ID of a conflict copy: derived from (original ID, remote `updated_at`, remote content hash).
///
/// Two devices merging the same divergence independently must compute the same ID, or every sync round mints another copy.
pub fn conflict_copy_id(id: Ulid, updated_at: DateTime<Utc>, value_hash: [u8; 32]) -> Ulid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(id.to_bytes());
    // The timestamp enters the hash at RFC3339 nanosecond precision: once `vault.age` is decrypted
    // both devices see the same JSON, so a lossless round trip (chrono's serde codec) keeps the digest bit-identical.
    hasher.update(updated_at.to_rfc3339_opts(SecondsFormat::Nanos, true).as_bytes());
    hasher.update(value_hash);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Ulid::from_bytes(bytes)
}

/// Entry name of a conflict copy: `<name>.conflict.<short ID>`.
///
/// Entry names are capped at `MAX_NAME_LEN`, and the original name can already sit at that cap,
/// so naive concatenation overflows it — an over-long name is truncated on a character boundary
/// before the suffix is appended (valid names are pure ASCII, so the cut never breaks UTF-8),
/// keeping `is_valid_name(conflict_copy_name(name, id))` true for every valid `name`.
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

/// The merge verdict for a single entry.
///
/// The wide spread in variant sizes is deliberate: this is a **short-lived** intermediate value, so boxing it would only buy an extra heap allocation.
#[allow(clippy::large_enum_variant)]
enum Resolution {
    /// The result carries no such entry (the deletion won, or a tombstone suppressed it).
    Drop,
    /// The original ID keeps this version.
    Keep(Entry),
    /// The sides diverged: ours holds the original ID, theirs is stored as a conflict copy.
    KeepWithCopy {
        winner: Entry,
        copy: Entry,
        kind: ConflictKind,
    },
}

/// Three-way merge. Pure: it reads no disk, takes no system time, and produces no randomness.
pub fn merge3(base: &Vault, ours: &Vault, theirs: &Vault) -> MergeResult {
    let purged = merge_purged(&ours.purged, &theirs.purged);

    let mut vault = Vault {
        // Container metadata follows the local workspace (the vault name and format version are
        // the same on both devices, so either side would do; pinning `ours` is what makes "same input, same output" hold).
        version: ours.version,
        vault: ours.vault.clone(),
        entries: BTreeMap::new(),
        tokens: BTreeMap::new(),
        purged,
    };

    // The three sides' IDs are unioned; `BTreeSet` iterates in an ordered way, so the output never depends on traversal order.
    let mut ids: BTreeSet<Ulid> = BTreeSet::new();
    ids.extend(base.entries.keys().copied());
    ids.extend(ours.entries.keys().copied());
    ids.extend(theirs.entries.keys().copied());

    let mut conflicts: Vec<Conflict> = Vec::new();
    for id in ids {
        // Tombstones outrank everything: a purged ID must not be revived by the remote side, nor reported as a conflict.
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

    // Tokens merge under the same rules (a token has no notion of "content divergence"; see `merge_token` for the choice).
    let mut token_ids: BTreeSet<Ulid> = BTreeSet::new();
    token_ids.extend(base.tokens.keys().copied());
    token_ids.extend(ours.tokens.keys().copied());
    token_ids.extend(theirs.tokens.keys().copied());
    for id in token_ids {
        let merged = match (ours.tokens.get(&id), theirs.tokens.get(&id)) {
            (Some(o), Some(t)) => merge_token(base.tokens.get(&id), o, t),
            (Some(o), None) => o.clone(),
            (None, Some(t)) => t.clone(),
            // Only in base: both sides dropped it (cleanup after revocation); do not revive it.
            (None, None) => continue,
        };
        vault.tokens.insert(id, merged);
    }

    // Iteration is ordered already; this only writes "sorted by entry ID" down as an explicit contract.
    conflicts.sort_by_key(|c| c.id);

    let stats = stats_against(ours, &vault.entries, conflicts.len());
    MergeResult {
        vault,
        conflicts,
        stats,
    }
}

/// Merge rules aligned by entry ID (a clause-by-clause implementation of `REQUIREMENTS.md` §11.1).
fn resolve_entry(
    base: Option<&Entry>,
    ours: Option<&Entry>,
    theirs: Option<&Entry>,
) -> Resolution {
    match (base, ours, theirs) {
        // On neither side: it can only come from base — both sides dropped it (its tombstone aged past 90 days after `rm --purge`).
        (_, None, None) => Resolution::Drop,

        // Only the local side has it.
        (b, Some(o), None) => match b {
            // The local side never touched it → the remote deletion wins (once a tombstone expires, "the remote lacks it" is the only evidence left).
            Some(b) if o == b => Resolution::Drop,
            // The local side edited it → keep the local edit; never drop data silently. The remote
            // side offers no version at all, so nothing can be preserved and no conflict is counted.
            _ => Resolution::Keep(o.clone()),
        },

        // Only the remote side has it — the mirror image of the clause above.
        (b, None, Some(t)) => match b {
            Some(b) if t == b => Resolution::Drop,
            _ => Resolution::Keep(t.clone()),
        },

        (b, Some(o), Some(t)) => {
            if o == t {
                // The sides agree (including "each added the same entry"): either copy will do.
                return Resolution::Keep(o.clone());
            }
            if let Some(base) = b {
                if o == base {
                    // Only the remote side edited it → take theirs.
                    return Resolution::Keep(with_newer_updated_at(t, o, t));
                }
                if t == base {
                    // Only the local side edited it → take ours.
                    return Resolution::Keep(with_newer_updated_at(o, o, t));
                }
            }
            // Both sides edited it, differently (including each adding different content under
            // the same ID) → conflict: ours holds the original ID, theirs lands as a standalone copy
            // with a reproducible ID; when one side soft-deleted while the other edited, the
            // edited version is still kept ("a delete does not outrank an edit").
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

/// The merged `updated_at` is the newer of the two sides (ours on a tie).
///
/// `max` is commutative, so two devices compute the same timestamp for the same divergence.
fn with_newer_updated_at(winner: &Entry, ours: &Entry, theirs: &Entry) -> Entry {
    let mut entry = winner.clone();
    entry.updated_at = max(ours.updated_at, theirs.updated_at);
    entry
}

/// Copy the remote version into a standalone entry: both its ID and its name derive from that version's content.
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

/// Tombstones are unioned; for the same ID take the **earlier** deletion time (the first deletion is the fact).
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

/// Token metadata is merged by ID.
///
/// Why this choice: `last_used_at` only says "it has been used", too weak to settle a content
/// divergence, so when both sides changed it differently we take the side with the newer
/// `last_used_at` (ours on a tie) — two devices merging the same divergence independently reach the same result.
///
/// But **revocation is irreversible**: if either side has a `revoked_at`, the result is revoked, with the earlier revocation time.
/// Otherwise a token one device just revoked would be revived by an earlier `last_used_at` written
/// on another device — a security regression, born of the same rule as "a tombstone must not be revived" at the entry layer.
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

/// Count the actions that really happened relative to the local workspace: added / updated / removed / conflicted.
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

    /// Both sides edited the same entry — the base for most conflict cases.
    fn diverged() -> (Vault, Vault, Vault) {
        let original = entry(id(1), "openai", "v0", 1_000);
        (
            vault(vec![original.clone()]),
            vault(vec![with_value(&original, "ours", 2_000)]),
            vault(vec![with_value(&original, "theirs", 3_000)]),
        )
    }

    // ---- The rule table, clause by clause ----

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
            "the local version is the one taken, so the local side has nothing to update"
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
        assert_eq!(conflict.name, "openai", "the conflict is anchored on the original entry's name");
        assert_eq!(conflict.kind, ConflictKind::ValueDiverged);

        // ours stays under the original ID, with the newer updated_at
        let kept = &r.vault.entries[&id(1)];
        assert_eq!(value_of(kept), "ours");
        assert_eq!(kept.updated_at, ts(3_000));

        // theirs lands as a standalone copy, its content untouched
        let copy = &r.vault.entries[&conflict.conflict_id];
        assert_eq!(value_of(copy), "theirs");
        assert_eq!(copy.updated_at, ts(3_000));
        assert!(copy.tags.iter().any(|t| t == CONFLICT_TAG));
        assert_ne!(conflict.conflict_id, id(1));
        assert_eq!(r.stats.conflicts, 1);
        assert_eq!(r.stats.added, 1, "the copy is a genuinely added entry");
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

        assert!(r.conflicts.is_empty(), "the remote did not edit, so the deletion takes effect directly");
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

        assert!(r.conflicts.is_empty(), "edits to different entries must merge automatically");
        assert_eq!(r.vault.entries.len(), 3);
        assert_eq!(r.vault.entries.get(&id(1)), Some(&ours_entry));
        assert_eq!(r.vault.entries.get(&id(2)), Some(&theirs_entry));
        assert_eq!(r.stats.added, 1);
        assert_eq!(r.stats.removed, 0);
    }

    // ---- Engineering constraints ----

    #[test]
    fn determinism_same_input_same_bytes() {
        let (base, ours, theirs) = rich_fixture();
        let expected = serde_json::to_string(&merge3(&base, &ours, &theirs)).expect("serializable");
        for round in 0..100 {
            let again = serde_json::to_string(&merge3(&base, &ours, &theirs)).expect("serializable");
            assert_eq!(again, expected, "merge #{round} is not byte-identical to the first");
        }
    }

    #[test]
    fn conflict_id_reproducible_across_devices() {
        let (base, ours, theirs) = diverged();
        let source = theirs.entries[&id(1)].clone();

        // Device A's merge result
        let a = merge3(&base, &ours, &theirs);
        // Device C merges independently: its local version differs from A's, but the remote version it holds is the same one
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
        assert_ne!(expected, source.id, "a copy ID colliding with the original ID would overwrite the original entry outright");

        // The devices only ever see the remote version through `vault.age` JSON, so the round trip must be lossless
        let reread: Entry =
            serde_json::from_str(&serde_json::to_string(&source).expect("serializable"))
                .expect("deserializable");
        assert_eq!(
            conflict_copy_id(reread.id, reread.updated_at, reread.value_hash()),
            expected
        );

        // Re-running on the same input (a sync push retry) must not mint another copy
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

        // Local delete vs remote edit → the original ID keeps the local soft-delete, the edit lands in the conflict copy
        let r = merge3(&base, &removal, &edit);
        assert_eq!(r.conflicts.len(), 1);
        let conflict = &r.conflicts[0];
        assert_eq!(conflict.kind, ConflictKind::DeleteVsEdit);
        assert_eq!(conflict.id, id(1));
        assert!(r.vault.entries[&id(1)].is_deleted());
        let copy = &r.vault.entries[&conflict.conflict_id];
        assert_eq!(value_of(copy), "v2", "the edit must not be dropped silently");
        assert!(!copy.is_deleted());

        // The reverse: local edit vs remote delete → the edit stays on the original ID, the deletion decision goes in the conflict
        let r2 = merge3(&base, &edit, &removal);
        assert_eq!(r2.conflicts.len(), 1);
        assert_eq!(r2.conflicts[0].kind, ConflictKind::DeleteVsEdit);
        assert_eq!(value_of(&r2.vault.entries[&id(1)]), "v2");
        let copy2 = &r2.vault.entries[&r2.conflicts[0].conflict_id];
        assert!(copy2.is_deleted(), "the remote soft-delete decision must not be dropped silently either");
    }

    #[test]
    fn purge_tombstone_suppresses_resurrection() {
        let original = entry(id(1), "openai", "v0", 1_000);
        let base = vault(vec![original.clone()]);
        let ours = vault(vec![with_value(&original, "still-editing", 2_000)]);

        let mut theirs = Vault::default();
        theirs.purged.insert(id(1), ts(1_500));

        let r = merge3(&base, &ours, &theirs);
        assert!(!r.vault.entries.contains_key(&id(1)), "a tombstone must not be revived");
        assert_eq!(r.vault.purged.get(&id(1)), Some(&ts(1_500)));
        assert!(r.conflicts.is_empty(), "a purged entry is not a conflict");
        assert_eq!(r.stats.removed, 1);

        // The reverse: the local side purged while the remote still has it (or even edited it)
        let mut ours_purged = Vault::default();
        ours_purged.purged.insert(id(1), ts(1_500));
        let r2 = merge3(&base, &ours_purged, &ours);
        assert!(!r2.vault.entries.contains_key(&id(1)));

        // Tombstones are unioned, and the same ID takes the earlier time
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
                "illegal conflict-copy name: {}",
                copy.name
            );
            assert_ne!(copy.name, name);
            assert!(
                copy.name.starts_with(&format!("{name}.conflict.")),
                "the copy name should hang off the original name: {}",
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
                "an original name of {len} chars produced an illegal copy name: {copy}"
            );
            assert_ne!(copy, name);
        }
        // The copy name must not be tagged twice (the remote version already carries `conflict`)
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

    // ---- Tokens ----

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

        // One side revoked while the other just used it → revocation must win, or the revoked token would come back
        let mut revoked = base_token.clone();
        revoked.revoked_at = Some(ts(3_000));
        let mut used = base_token.clone();
        used.last_used_at = Some(ts(4_000));
        let r = merge3(
            &token_vault(vec![base_token.clone()]),
            &token_vault(vec![revoked]),
            &token_vault(vec![used]),
        );
        let merged = r.vault.tokens.get(&id(5)).expect("the token must not disappear");
        assert_eq!(merged.revoked_at, Some(ts(3_000)));
        assert_eq!(merged.last_used_at, Some(ts(4_000)), "the newer use time must be kept");

        // Neither revokes → take the newer last_used_at, and both devices compute the same thing
        let mut older = base_token.clone();
        older.last_used_at = Some(ts(5_000));
        let mut newer = base_token.clone();
        newer.last_used_at = Some(ts(6_000));
        let empty = Vault::default();
        let a = merge3(&empty, &token_vault(vec![older.clone()]), &token_vault(vec![newer.clone()]));
        let b = merge3(&empty, &token_vault(vec![newer]), &token_vault(vec![older]));
        assert_eq!(a.vault, b.vault);
        assert_eq!(a.vault.tokens[&id(5)].last_used_at, Some(ts(6_000)));

        // A token present on only one side is kept; a token left only in base is not revived
        let lone = token(&entry(id(6), "solo", "v1", 1_100));
        let r2 = merge3(
            &token_vault(vec![base_token]),
            &Vault::default(),
            &token_vault(vec![lone.clone()]),
        );
        assert_eq!(r2.vault.tokens.len(), 1);
        assert_eq!(r2.vault.tokens.get(&id(6)), Some(&lone));
    }

    // ---- Stats and ordering ----

    #[test]
    fn stats_count_real_actions() {
        let (base, ours, theirs) = rich_fixture();
        let r = merge3(&base, &ours, &theirs);

        // Relative to the local side (ours): the remote brings 1 new entry (id 3) + 2 conflict copies
        assert_eq!(r.stats.added, 3);
        // id 1 diverged and keeps ours with a newer updated_at, id 4 delete vs edit, id 6 remote soft-delete → all content changes
        assert_eq!(r.stats.updated, 3);
        // id 8 was hard-deleted remotely and the local side never touched it → it vanishes from the local result
        assert_eq!(r.stats.removed, 1);
        assert_eq!(r.stats.conflicts, 2);
        assert_eq!(r.conflicts.len(), 2);

        let mut ids: Vec<Ulid> = r.conflicts.iter().map(|c| c.id).collect();
        let sorted = {
            let mut copy = ids.clone();
            copy.sort_unstable();
            copy
        };
        assert_eq!(ids, sorted, "conflicts must be sorted by entry ID");
        ids.dedup();
        assert_eq!(ids.len(), r.conflicts.len());
    }

    /// One fixture covering every rule branch: divergence, an addition on either side, delete vs edit, both edited, remote soft-delete, remote hard-delete.
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

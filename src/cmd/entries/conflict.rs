//! `conflicts` / `resolve`: list merge-produced conflict copies and settle them.
//!
//! A merge names losing copies `<name>.conflict.<tag>`; resolution either drops every copy
//! (`--ours`) or overwrites the original-name entry with the newest copy (`--theirs`).

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use ulid::Ulid;

use super::json_err;
use crate::audit::{self, Action};
use crate::cli::{ConflictsArgs, ResolveArgs};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::vault::model::Vault;

const CONFLICT_MARK: &str = ".conflict.";
const CONFLICT_TAG: &str = "conflict";

/// List the conflict copies a merge produced.
pub fn conflicts(ctx: &Ctx, _args: &ConflictsArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let rows = conflict_views(&vault);

    audit::record(&ctx.paths, store.identity.name(), Action::Read, None, "ok")?;

    let human = if rows.is_empty() {
        "no conflicts".to_string()
    } else {
        rows.iter()
            .map(|row| match (&row.original, row.original_exists) {
                (Some(original), true) => format!("{}  (conflict copy of '{original}')", row.name),
                (Some(original), false) => {
                    format!("{}  (original '{original}' is missing)", row.name)
                }
                (None, _) => row.name.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let json_rows = serde_json::to_value(&rows).map_err(json_err)?;
    ctx.out.emit(
        human,
        &json!({ "count": rows.len(), "conflicts": json_rows }),
    )
}

/// Resolve one conflict: `--ours` drops the copy, `--theirs` overwrites the original-name entry with the copy's content.
pub fn resolve(ctx: &Ctx, args: &ResolveArgs) -> Result<()> {
    ctx.gate_write()?;
    let side = match (args.ours, args.theirs) {
        (true, false) => Side::Ours,
        (false, true) => Side::Theirs,
        _ => {
            return Err(Error::usage(crate::msg!(
                "resolve needs exactly one of --ours or --theirs",
                "`resolve` 需要且仅需要 --ours 或 --theirs 之一"
            )));
        }
    };
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_resolve(&mut vault, &args.name, side, now)?
    } else {
        store.update(|vault| apply_resolve(vault, &args.name, side, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.name),
            "ok",
        )?;
    }
    let data = json!({
        "action": "resolved",
        "name": outcome.name,
        "id": outcome.id.to_string(),
        "side": outcome.side.as_str(),
        "kept": outcome.kept,
        "removed": outcome.removed,
        "dry_run": dry,
    });
    let human = format!(
        "{} conflict on '{}': kept {} side from '{}', removed {} copy/copies",
        if dry {
            "dry run: would resolve"
        } else {
            "resolved"
        },
        outcome.name,
        outcome.side.as_str(),
        outcome.kept,
        outcome.removed.len(),
    );
    ctx.out.emit(human, &data)
}
#[derive(Debug, Serialize)]
pub(super) struct ConflictView {
    name: String,
    id: Ulid,
    pub(super) original: Option<String>,
    pub(super) original_exists: bool,
    tags: Vec<String>,
    updated_at: DateTime<Utc>,
}

fn conflict_base(name: &str) -> Option<&str> {
    name.rsplit_once(CONFLICT_MARK)
        .map(|(base, _)| base)
        .filter(|base| !base.is_empty())
}

pub(super) fn conflict_views(vault: &Vault) -> Vec<ConflictView> {
    let mut rows: Vec<ConflictView> = vault
        .entries
        .values()
        .filter(|entry| {
            !entry.is_deleted()
                && entry
                    .tags
                    .iter()
                    .any(|tag| tag.eq_ignore_ascii_case(CONFLICT_TAG))
        })
        .map(|entry| {
            let original = conflict_base(&entry.name).map(str::to_string);
            let original_exists = original.as_ref().is_some_and(|base| {
                vault
                    .entries
                    .values()
                    .any(|e| &e.name == base && !e.is_deleted())
            });
            ConflictView {
                name: entry.name.clone(),
                id: entry.id,
                original,
                original_exists,
                tags: entry.tags.clone(),
                updated_at: entry.updated_at,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    Ours,
    Theirs,
}

impl Side {
    fn as_str(self) -> &'static str {
        match self {
            Side::Ours => "ours",
            Side::Theirs => "theirs",
        }
    }
}

#[derive(Debug)]
pub(super) struct ResolveOutcome {
    name: String,
    id: Ulid,
    side: Side,
    /// Where the content came from (with `--ours`, the original-name entry itself).
    kept: String,
    pub(super) removed: Vec<String>,
}

/// Normalize a conflict target: both `<name>` and `<name>.conflict.<tag>` locate the **original-name entry**.
fn conflict_target(vault: &Vault, key: &str) -> Result<String> {
    let found = match vault.find(key) {
        Ok(entry) => Some(entry.name.clone()),
        Err(Error::NotFound(_)) => None,
        Err(err) => return Err(err),
    };
    let candidates = found.iter().map(String::as_str).chain(conflict_base(key));
    for candidate in candidates {
        if let Some(stem) = conflict_base(candidate)
            && vault.entries.values().any(|e| e.name == stem)
        {
            return Ok(stem.to_string());
        }
        if vault.entries.values().any(|e| e.name == candidate) {
            return Ok(candidate.to_string());
        }
    }
    Err(Error::not_found(crate::msg!(
        "no entry named '{}'",
        "没有名为 '{}' 的条目",
        key
    )))
}

pub(super) fn apply_resolve(
    vault: &mut Vault,
    key: &str,
    side: Side,
    now: DateTime<Utc>,
) -> Result<ResolveOutcome> {
    let base = conflict_target(vault, key)?;
    let base_id = vault
        .entries
        .values()
        .find(|e| e.name == base)
        .map(|e| e.id)
        .ok_or_else(|| {
            Error::not_found(crate::msg!(
                "no entry named '{}'",
                "没有名为 '{}' 的条目",
                base
            ))
        })?;

    let prefix = format!("{base}{CONFLICT_MARK}");
    let mut copies: Vec<(Ulid, String, DateTime<Utc>)> = vault
        .entries
        .values()
        .filter(|entry| entry.name.starts_with(&prefix))
        .map(|entry| (entry.id, entry.name.clone(), entry.updated_at))
        .collect();
    if copies.is_empty() {
        return Err(Error::usage(crate::msg!(
            "no conflict copy found for '{}'; run `akey conflicts` first",
            "没有找到 '{}' 的冲突副本；请先运行 `akey conflicts`",
            base
        )));
    }
    // With several copies, take the newest one, the name as tiebreaker, so the result is reproducible.
    copies.sort_by(|a, b| a.2.cmp(&b.2).then(a.1.cmp(&b.1)));
    let (source_id, source_name, _) = copies.last().expect("checked non-empty").clone();
    let source = vault.entries.get(&source_id).cloned().ok_or_else(|| {
        Error::not_found(crate::msg!(
            "conflict copy '{}' vanished",
            "冲突副本 '{}' 已消失",
            source_name
        ))
    })?;

    let entry = vault.entries.get_mut(&base_id).ok_or_else(|| {
        Error::not_found(crate::msg!(
            "no entry named '{}'",
            "没有名为 '{}' 的条目",
            base
        ))
    })?;
    if side == Side::Theirs {
        entry.category = source.category;
        entry.title = source.title.clone();
        entry.fields = source.fields.clone();
        entry.tags = source.tags.clone();
        entry.favorite = source.favorite;
        entry.url = source.url.clone();
        entry.notes = source.notes.clone();
        entry.expires_at = source.expires_at;
        entry.reveal = source.reveal;
    }
    entry.tags.retain(|t| !t.eq_ignore_ascii_case(CONFLICT_TAG));
    entry.updated_at = now;

    let mut removed = Vec::with_capacity(copies.len());
    for (id, name, _) in &copies {
        vault.entries.remove(id);
        // The tombstone makes the resolution stable on the remote too, so the copy is not merged back in.
        vault.purged.insert(*id, now);
        removed.push(name.clone());
    }
    Ok(ResolveOutcome {
        name: base,
        id: base_id,
        side,
        kept: source_name,
        removed,
    })
}

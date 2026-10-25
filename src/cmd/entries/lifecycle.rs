//! `rm` / `restore` / `cp` / `mv`: lifecycle and batch operations.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use ulid::Ulid;

use crate::audit::{self, Action};
use crate::cli::{CpArgs, MvArgs, RestoreArgs, RmArgs};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::vault::model::{Vault, is_valid_name};

/// Delete an entry: soft by default; `--purge` hard-deletes and writes a tombstone.
pub fn rm(ctx: &Ctx, args: &RmArgs) -> Result<()> {
    ctx.gate_write()?;
    if args.items.is_empty() {
        return Err(Error::usage(crate::msg!(
            "rm needs at least one item",
            "`rm` 至少需要一个条目"
        )));
    }
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;
    let purge = args.purge;

    let report = if dry {
        let mut vault = store.load()?;
        apply_rm(&mut vault, &args.items, purge, now)
    } else {
        store.update(|vault| Ok(apply_rm(vault, &args.items, purge, now)))?
    };

    if !dry {
        record_batch(ctx, &store, Action::Delete, &report)?;
    }
    if let Some(err) = report.error() {
        return Err(err);
    }
    ctx.out.emit(report.human(), &report.data(dry))
}

/// Restore a soft-deleted entry.
pub fn restore(ctx: &Ctx, args: &RestoreArgs) -> Result<()> {
    ctx.gate_write()?;
    if args.items.is_empty() {
        return Err(Error::usage(crate::msg!(
            "restore needs at least one item",
            "`restore` 至少需要一个条目"
        )));
    }
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let report = if dry {
        let mut vault = store.load()?;
        apply_restore(&mut vault, &args.items, now)
    } else {
        store.update(|vault| Ok(apply_restore(vault, &args.items, now)))?
    };

    if !dry {
        record_batch(ctx, &store, Action::Restore, &report)?;
    }
    if let Some(err) = report.error() {
        return Err(err);
    }
    ctx.out.emit(report.human(), &report.data(dry))
}

/// Copy an entry: a new ID and a new name, with the source untouched.
pub fn cp(ctx: &Ctx, args: &CpArgs) -> Result<()> {
    ctx.gate_write()?;
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_cp(&mut vault, &args.source, &args.destination, now)?
    } else {
        store.update(|vault| apply_cp(vault, &args.source, &args.destination, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.destination),
            "ok",
        )?;
    }
    let data = json!({
        "action": "copied",
        "source": outcome.source,
        "source_id": outcome.source_id.to_string(),
        "destination": outcome.destination,
        "destination_id": outcome.id.to_string(),
        "field_count": outcome.fields,
        "dry_run": dry,
    });
    let human = format!(
        "{} '{}' -> '{}' ({})",
        if dry { "dry run: would copy" } else { "copied" },
        outcome.source,
        outcome.destination,
        outcome.id,
    );
    ctx.out.emit(human, &data)
}

/// Rename an entry: the ID stays, so references keep resolving.
pub fn mv(ctx: &Ctx, args: &MvArgs) -> Result<()> {
    ctx.gate_write()?;
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_mv(&mut vault, &args.old, &args.new, now)?
    } else {
        store.update(|vault| apply_mv(vault, &args.old, &args.new, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.new_name),
            "ok",
        )?;
    }
    let data = json!({
        "action": "renamed",
        "id": outcome.id.to_string(),
        "old": outcome.old_name,
        "new": outcome.new_name,
        "dry_run": dry,
    });
    let human = format!(
        "{} '{}' -> '{}' ({})",
        if dry {
            "dry run: would rename"
        } else {
            "renamed"
        },
        outcome.old_name,
        outcome.new_name,
        outcome.id,
    );
    ctx.out.emit(human, &data)
}
/// The result of a batch operation. A failing item does not block the others — successful changes are persisted as usual.
#[derive(Default)]
pub(super) struct BatchReport {
    pub(super) results: Vec<BatchResult>,
    pub(super) failed: Vec<(String, Error)>,
}

#[derive(Debug)]
pub(super) struct BatchResult {
    item: String,
    name: String,
    pub(super) action: &'static str,
}

impl BatchReport {
    fn push(&mut self, item: &str, name: &str, action: &'static str) {
        self.results.push(BatchResult {
            item: item.to_string(),
            name: name.to_string(),
            action,
        });
    }

    fn fail(&mut self, item: &str, err: Error) {
        self.failed.push((item.to_string(), err));
    }

    fn succeeded(&self) -> Vec<String> {
        self.results.iter().map(|r| r.name.clone()).collect()
    }

    fn data(&self, dry: bool) -> Value {
        json!({
            "dry_run": dry,
            "results": self
                .results
                .iter()
                .map(|r| json!({ "item": r.item, "name": r.name, "action": r.action }))
                .collect::<Vec<_>>(),
            "failed": self
                .failed
                .iter()
                .map(|(item, err)| json!({
                    "item": item,
                    "code": err.code(),
                    "message": err.to_string(),
                }))
                .collect::<Vec<_>>(),
        })
    }

    fn human(&self) -> String {
        let mut lines: Vec<String> = self
            .results
            .iter()
            .map(|r| {
                // `action` is a stable wire identifier that also goes into `--json`, so it is
                // mapped to prose here rather than localized where it is set.
                let verb = match r.action {
                    "deleted" => crate::i18n::m("deleted", "已删除"),
                    "already_deleted" => crate::i18n::m("already deleted", "此前已删除"),
                    "purged" => crate::i18n::m("purged", "已彻底移除"),
                    "restored" => crate::i18n::m("restored", "已恢复"),
                    "already_live" => crate::i18n::m("already live", "本来就是启用状态"),
                    other => other,
                };
                format!("{verb} '{}'", r.name)
            })
            .collect();
        lines.extend(
            self.failed
                .iter()
                .map(|(item, err)| crate::msg!("failed '{}': {}", "失败 '{}'：{}", item, err)),
        );
        if lines.is_empty() {
            return crate::i18n::m("nothing to do", "没有要做的事").to_string();
        }
        lines.join("\n")
    }

    /// Returns an error when any item failed (keeping the first item's kind and exit code), naming the successful items in the message.
    pub(super) fn error(&self) -> Option<Error> {
        if self.failed.is_empty() {
            return None;
        }
        let succeeded = self.succeeded();
        let (_, first) = &self.failed[0];
        let head = crate::msg!(
            "{} of {} item(s) failed ({}); {}",
            "{} / {} 个条目失败（{}）；{}",
            self.failed.len(),
            self.failed.len() + succeeded.len(),
            first,
            if succeeded.is_empty() {
                crate::msg!("nothing was changed", "没有做任何改动")
            } else {
                crate::msg!("succeeded: {}", "成功：{}", succeeded.join(", "))
            }
        );
        Some(match first.code() {
            "usage" => Error::Usage(head),
            "ambiguous" => Error::Ambiguous(head),
            _ => Error::NotFound(head),
        })
    }
}

pub(super) fn apply_rm(
    vault: &mut Vault,
    items: &[String],
    purge: bool,
    now: DateTime<Utc>,
) -> BatchReport {
    let mut report = BatchReport::default();
    for item in items {
        let found = vault
            .find(item)
            .map(|entry| (entry.id, entry.name.clone(), entry.is_deleted()));
        let (id, name, deleted) = match found {
            Ok(found) => found,
            Err(err) => {
                report.fail(item, err);
                continue;
            }
        };
        if purge {
            vault.entries.remove(&id);
            // Tombstone: keeps a remote sync from reviving an entry that was removed outright.
            vault.purged.insert(id, now);
            report.push(item, &name, "purged");
        } else if deleted {
            report.push(item, &name, "already_deleted");
        } else if let Some(entry) = vault.entries.get_mut(&id) {
            entry.deleted_at = Some(now);
            entry.updated_at = now;
            report.push(item, &name, "deleted");
        }
    }
    report
}

pub(super) fn apply_restore(
    vault: &mut Vault,
    items: &[String],
    now: DateTime<Utc>,
) -> BatchReport {
    let mut report = BatchReport::default();
    for item in items {
        let found = vault
            .find(item)
            .map(|entry| (entry.id, entry.name.clone(), entry.is_deleted()));
        let (id, name, deleted) = match found {
            Ok(found) => found,
            Err(err) => {
                report.fail(item, err);
                continue;
            }
        };
        if !deleted {
            report.push(item, &name, "already_live");
            continue;
        }
        if vault.name_taken(&name, id) {
            report.fail(
                item,
                Error::usage(crate::msg!(
                    "cannot restore '{}': another entry already uses that name; rename one of them first",
                    "无法恢复 '{}'：另一个条目已使用该名字；请先重命名其中一个",
                    name
                )),
            );
            continue;
        }
        if let Some(entry) = vault.entries.get_mut(&id) {
            entry.deleted_at = None;
            entry.updated_at = now;
            report.push(item, &name, "restored");
        }
    }
    report
}

#[derive(Debug)]
pub(super) struct CpOutcome {
    source: String,
    source_id: Ulid,
    destination: String,
    pub(super) id: Ulid,
    fields: usize,
}

pub(super) fn apply_cp(
    vault: &mut Vault,
    source: &str,
    destination: &str,
    now: DateTime<Utc>,
) -> Result<CpOutcome> {
    if !is_valid_name(destination) {
        return Err(Error::usage(crate::msg!(
            "invalid entry name '{}': expected ^[a-z0-9][a-z0-9._-]*$",
            "非法条目名 '{}'：应为 ^[a-z0-9][a-z0-9._-]*$",
            destination
        )));
    }
    let origin = vault.find(source)?.clone();
    if vault.entries.values().any(|e| e.name == destination) {
        return Err(Error::usage(crate::msg!(
            "entry '{}' already exists; pick another name",
            "条目 '{}' 已存在；请换一个名字",
            destination
        )));
    }
    let mut copy = origin.clone();
    copy.id = Ulid::generate();
    copy.name = destination.to_string();
    copy.created_at = now;
    copy.updated_at = now;
    copy.last_used_at = None;
    copy.deleted_at = None;
    let outcome = CpOutcome {
        source: origin.name.clone(),
        source_id: origin.id,
        destination: copy.name.clone(),
        id: copy.id,
        fields: copy.fields.len(),
    };
    vault.entries.insert(copy.id, copy);
    Ok(outcome)
}

#[derive(Debug)]
pub(super) struct MvOutcome {
    pub(super) id: Ulid,
    old_name: String,
    new_name: String,
}

pub(super) fn apply_mv(
    vault: &mut Vault,
    old: &str,
    new: &str,
    now: DateTime<Utc>,
) -> Result<MvOutcome> {
    if !is_valid_name(new) {
        return Err(Error::usage(crate::msg!(
            "invalid entry name '{}': expected ^[a-z0-9][a-z0-9._-]*$",
            "非法条目名 '{}'：应为 ^[a-z0-9][a-z0-9._-]*$",
            new
        )));
    }
    let entry = vault.find(old)?.clone();
    if entry.name != new && vault.name_taken(new, entry.id) {
        return Err(Error::usage(crate::msg!(
            "entry '{}' already exists; pick another name",
            "条目 '{}' 已存在；请换一个名字",
            new
        )));
    }
    let outcome = MvOutcome {
        id: entry.id,
        old_name: entry.name.clone(),
        new_name: new.to_string(),
    };
    if let Some(target) = vault.entries.get_mut(&entry.id) {
        target.name = new.to_string();
        target.updated_at = now;
    }
    Ok(outcome)
}
fn record_batch(
    ctx: &Ctx,
    store: &crate::vault::store::Store,
    action: Action,
    report: &BatchReport,
) -> Result<()> {
    let outcome = if report.failed.is_empty() {
        "ok"
    } else {
        "partial"
    };
    for result in &report.results {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            action,
            Some(&result.name),
            outcome,
        )?;
    }
    for (item, err) in &report.failed {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            action,
            Some(item),
            err.code(),
        )?;
    }
    Ok(())
}

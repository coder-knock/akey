//! Entry commands: CRUD, copy and rename, templates, conflict resolution.
//!
//! Each command function only does **argument shuttling + persistence orchestration**: every
//! decision is factored into a pure function taking `&Vault` / `&mut Vault`, so unit tests need
//! not build a `Ctx` (whose fields are private). Writes all go through `Store::update`
//! (read-modify-write + exclusive lock + atomic persist); `--dry-run` runs the same computation
//! on an in-memory copy, persisting nothing and writing no audit entry.
//!
//! Output discipline: human text and JSON data are emitted by **the same `emit` call** — one source for both.

use std::io::Read as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::audit::{self, Action};
use crate::cli::{
    ConflictsArgs, CpArgs, EditArgs, GetArgs, ListArgs, MvArgs, ResolveArgs, RestoreArgs,
    RevealPolicy, RmArgs, SetArgs, TemplateArgs, TemplateCommand,
};
use crate::cmd::{Ctx, parse_duration};
use crate::error::{Error, Result};
use crate::output::REDACTED;
use crate::paths;
use crate::reference::{Attribute, Reference};
use crate::vault::model::{
    Category, DEFAULT_VAULT, Entry, Field, FieldType, MAX_NAME_LEN, Reveal, Vault, is_valid_name,
    slug,
};

/// Infix of a conflict-copy name, matching the names `vault::merge` generates.
const CONFLICT_MARK: &str = ".conflict.";
/// Conflict-entry tag, matching the tag `vault::merge` applies.
const CONFLICT_TAG: &str = "conflict";

const ALL_CATEGORIES: [Category; 7] = [
    Category::Apikey,
    Category::Login,
    Category::Token,
    Category::Database,
    Category::SshKey,
    Category::SecureNote,
    Category::EnvBundle,
];

// ─────────────────────────────── Command entry points ───────────────────────────────

/// Show an entry. `concealed` fields are hidden by default; `--reveal` must pass a three-fold policy gate.
pub fn get(ctx: &Ctx, args: &GetArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let entry = vault.find(&args.item)?;
    // Token scope is always checked; the path is the same with or without a token.
    ctx.authorize(&vault, &entry.name)?;
    if args.reveal {
        ctx.gate_reveal(&vault, Some(entry))?;
    }

    let selected = select_fields(entry, &args.fields)?;
    let mut view = build_view(entry, selected, args.reveal);
    if args.otp {
        fill_otp(&vault, &mut view, Utc::now())?;
    }

    audit::record(
        &ctx.paths,
        store.identity.name(),
        if args.reveal { Action::Reveal } else { Action::Read },
        Some(&entry.name),
        "ok",
    )?;

    ctx.out.emit(render_entry_human(&view), &view)
}

/// Create or update an entry. With the name unchanged, a second `set` is an **update** (ID and `created_at` stay put).
pub fn set(ctx: &Ctx, args: &SetArgs) -> Result<()> {
    ctx.gate_write()?;
    if args.item.is_empty() {
        return Err(Error::usage("set needs an item name"));
    }
    let plan = SetPlan::from_args(args)?;
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_set(&mut vault, &plan, now)?
    } else {
        store.update(|vault| apply_set(vault, &plan, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.entry.name),
            "ok",
        )?;
    }
    warn_argv_secrets(ctx, &plan, &outcome.entry);

    let verb = if outcome.created { "create" } else { "update" };
    let human = format!(
        "{} entry '{}' ({}, {} field(s))",
        if dry {
            format!("dry run: would {verb}")
        } else if outcome.created {
            "created".to_string()
        } else {
            "updated".to_string()
        },
        outcome.entry.name,
        outcome.entry.id,
        outcome.entry.fields.len(),
    );
    let mut data = json!({
        "action": if outcome.created { "created" } else { "updated" },
        "name": outcome.entry.name,
        "id": outcome.entry.id.to_string(),
        "category": outcome.entry.category,
        "field_count": outcome.entry.fields.len(),
        "dry_run": dry,
    });
    if dry {
        // In the preview, concealed fields show only the placeholder — plaintext never enters JSON (NFR-9).
        let preview = serde_json::to_value(entry_view(&outcome.entry, false)).map_err(json_err)?;
        ctx.out.note(&serde_json::to_string_pretty(&preview).map_err(json_err)?);
        data["entry"] = preview;
    }
    ctx.out.emit(human, &data)
}

/// Edit an existing entry; never creates one. Any flag left out means "leave it alone".
pub fn edit(ctx: &Ctx, args: &EditArgs) -> Result<()> {
    ctx.gate_write()?;
    let plan = EditPlan::from_args(args)?;
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_edit(&mut vault, &plan, now)?
    } else {
        store.update(|vault| apply_edit(vault, &plan, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.entry.name),
            "ok",
        )?;
    }
    warn_argv_secrets_edit(ctx, &plan.assignments, &outcome.entry);

    let human = format!(
        "{} entry '{}' ({}, {} field(s))",
        if dry {
            "dry run: would update".to_string()
        } else {
            "updated".to_string()
        },
        outcome.entry.name,
        outcome.entry.id,
        outcome.entry.fields.len(),
    );
    let mut data = json!({
        "action": "updated",
        "name": outcome.entry.name,
        "id": outcome.entry.id.to_string(),
        "category": outcome.entry.category,
        "field_count": outcome.entry.fields.len(),
        "changed": outcome.changed,
        "dry_run": dry,
    });
    if dry {
        let preview = serde_json::to_value(entry_view(&outcome.entry, false)).map_err(json_err)?;
        ctx.out.note(&serde_json::to_string_pretty(&preview).map_err(json_err)?);
        data["entry"] = preview;
    }
    ctx.out.emit(human, &data)
}

/// Delete an entry: soft by default; `--purge` hard-deletes and writes a tombstone.
pub fn rm(ctx: &Ctx, args: &RmArgs) -> Result<()> {
    ctx.gate_write()?;
    if args.items.is_empty() {
        return Err(Error::usage("rm needs at least one item"));
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
    ctx.out.emit(report.human(), &report.data(dry))?;
    report.into_error()
}

/// Restore a soft-deleted entry.
pub fn restore(ctx: &Ctx, args: &RestoreArgs) -> Result<()> {
    ctx.gate_write()?;
    if args.items.is_empty() {
        return Err(Error::usage("restore needs at least one item"));
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
    ctx.out.emit(report.human(), &report.data(dry))?;
    report.into_error()
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
        if dry { "dry run: would rename" } else { "renamed" },
        outcome.old_name,
        outcome.new_name,
        outcome.id,
    );
    ctx.out.emit(human, &data)
}

/// List entries. **Field values never appear in JSON** — metadata only.
pub fn list(ctx: &Ctx, args: &ListArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let now = Utc::now();
    // With a token, list only the entries in scope. Probe with an empty name: a name is never
    // empty, so only "no token" or "the token does not restrict entries" returns Ok; `token_scope`
    // means each entry has to be judged individually.
    let unrestricted = match ctx.authorize(&vault, "") {
        Ok(_) => true,
        Err(Error::TokenScope(_)) => false,
        Err(err) => return Err(err),
    };
    let rows: Vec<EntrySummary> = select_entries(&vault, args, now)?
        .into_iter()
        .filter(|entry| unrestricted || ctx.authorize(&vault, &entry.name).is_ok())
        .map(EntrySummary::from_entry)
        .collect();

    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Read,
        None,
        "ok",
    )?;

    let json_rows = serde_json::to_value(&rows).map_err(json_err)?;
    let data = json!({ "count": rows.len(), "entries": json_rows });
    ctx.out.emit(render_list_human(&rows), &data)
}

/// Category templates: `list` enumerates categories, `get` prints an empty-value template.
///
/// A template is a **static contract**: it reads no vault and writes no audit — so it works with no repo at all (the same kind of command as `schema`).
pub fn template(ctx: &Ctx, args: &TemplateArgs) -> Result<()> {
    match &args.command {
        TemplateCommand::List => {
            let items: Vec<Value> = ALL_CATEGORIES
                .iter()
                .map(|cat| {
                    json!({
                        "category": cat.as_str(),
                        "default_secret_field": cat.default_secret_field(),
                        "fields": cat
                            .builtin_fields()
                            .iter()
                            .map(|(label, ty)| json!({ "label": label, "type": ty.as_str() }))
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();
            let human = ALL_CATEGORIES
                .iter()
                .map(|cat| {
                    let labels: Vec<&str> = cat.builtin_fields().iter().map(|(l, _)| *l).collect();
                    format!("{:<12} {}", cat.as_str(), labels.join(", "))
                })
                .collect::<Vec<_>>()
                .join("\n");
            ctx.out.emit(human, &json!({ "categories": items }))
        }
        TemplateCommand::Get { category, out_file } => {
            let value = category_template(*category);
            if let Some(path) = out_file {
                let rendered = serde_json::to_string_pretty(&value).map_err(json_err)?;
                paths::atomic_write(path, rendered.as_bytes(), paths::FILE_MODE)?;
                let data = json!({
                    "category": category.as_str(),
                    "out_file": path.to_string_lossy(),
                    "bytes": rendered.len(),
                });
                return ctx
                    .out
                    .emit(format!("wrote template for {category} to {}", path.display()), &data);
            }
            let rendered = serde_json::to_string_pretty(&value).map_err(json_err)?;
            ctx.out.emit(rendered, &value)
        }
    }
}

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
    ctx.out
        .emit(human, &json!({ "count": rows.len(), "conflicts": json_rows }))
}

/// Resolve one conflict: `--ours` drops the copy, `--theirs` overwrites the original-name entry with the copy's content.
pub fn resolve(ctx: &Ctx, args: &ResolveArgs) -> Result<()> {
    ctx.gate_write()?;
    let side = match (args.ours, args.theirs) {
        (true, false) => Side::Ours,
        (false, true) => Side::Theirs,
        _ => {
            return Err(Error::usage(
                "resolve needs exactly one of --ours or --theirs",
            ));
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
        if dry { "dry run: would resolve" } else { "resolved" },
        outcome.name,
        outcome.side.as_str(),
        outcome.kept,
        outcome.removed.len(),
    );
    ctx.out.emit(human, &data)
}

// ─────────────────────────────── Output views ───────────────────────────────

/// The outward view of a single field. Concealed fields show only the placeholder (unless explicitly revealed).
#[derive(Debug, Serialize)]
struct FieldView {
    id: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
    #[serde(rename = "type")]
    ty: FieldType,
    concealed: bool,
    value: String,
    /// For an agent to reference rather than read.
    reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    otp: Option<String>,
}

/// The entry view. `notes` is free text and is treated as concealed content.
#[derive(Debug, Serialize)]
struct EntryView {
    id: Ulid,
    name: String,
    category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    reveal: Reveal,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted_at: Option<DateTime<Utc>>,
    fields: Vec<FieldView>,
}

/// One summary row of `list`. **Carries no field values.**
#[derive(Debug, Serialize)]
struct EntrySummary {
    name: String,
    id: Ulid,
    category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    expires_at: Option<DateTime<Utc>>,
    deleted_at: Option<DateTime<Utc>>,
    field_count: usize,
}

impl EntrySummary {
    fn from_entry(entry: &Entry) -> EntrySummary {
        EntrySummary {
            name: entry.name.clone(),
            id: entry.id,
            category: entry.category,
            title: entry.title.clone(),
            tags: entry.tags.clone(),
            favorite: entry.favorite,
            expires_at: entry.expires_at,
            deleted_at: entry.deleted_at,
            field_count: entry.fields.len(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ConflictView {
    name: String,
    id: Ulid,
    original: Option<String>,
    original_exists: bool,
    tags: Vec<String>,
    updated_at: DateTime<Utc>,
}

fn reference_string(entry_name: &str, field: &Field) -> String {
    Reference {
        vault: DEFAULT_VAULT.to_string(),
        item: entry_name.to_string(),
        section: field.section.clone(),
        field: field.id.clone(),
        attribute: Attribute::Value,
    }
    .to_string()
}

fn entry_view(entry: &Entry, revealed: bool) -> EntryView {
    build_view(entry, entry.fields.iter().collect(), revealed)
}

fn build_view(entry: &Entry, fields: Vec<&Field>, revealed: bool) -> EntryView {
    EntryView {
        id: entry.id,
        name: entry.name.clone(),
        category: entry.category,
        title: entry.title.clone(),
        tags: entry.tags.clone(),
        favorite: entry.favorite,
        url: entry.url.clone(),
        notes: entry
            .notes
            .as_ref()
            .map(|n| if revealed { n.clone() } else { REDACTED.to_string() }),
        expires_at: entry.expires_at,
        reveal: entry.reveal,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        rotated_at: entry.rotated_at,
        deleted_at: entry.deleted_at,
        fields: fields
            .into_iter()
            .map(|field| FieldView {
                id: field.id.clone(),
                label: field.label.clone(),
                section: field.section.clone(),
                ty: field.ty,
                concealed: field.is_concealed(),
                value: field.display_value(revealed),
                reference: reference_string(&entry.name, field),
                otp: None,
            })
            .collect(),
    }
}

/// `--field` selection; every field when unspecified. Not found → `not_found`.
fn select_fields<'a>(entry: &'a Entry, wanted: &[String]) -> Result<Vec<&'a Field>> {
    if wanted.is_empty() {
        return Ok(entry.fields.iter().collect());
    }
    let mut selected = Vec::with_capacity(wanted.len());
    for label in wanted {
        let field = entry
            .field(label)
            .ok_or_else(|| Error::not_found(format!("entry '{}' has no field '{label}'", entry.name)))?;
        selected.push(field);
    }
    Ok(selected)
}

/// Compute a one-time password for `otp`-typed fields (through `reference::resolve`, the same code `read` uses).
fn fill_otp(vault: &Vault, view: &mut EntryView, now: DateTime<Utc>) -> Result<()> {
    let item = view.name.clone();
    for view_field in view.fields.iter_mut() {
        if view_field.ty != FieldType::Otp {
            continue;
        }
        let reference = Reference {
            vault: DEFAULT_VAULT.to_string(),
            item: item.clone(),
            section: view_field.section.clone(),
            field: view_field.id.clone(),
            attribute: Attribute::Otp,
        };
        view_field.otp = Some(crate::reference::resolve(vault, &reference, now)?.to_string());
    }
    Ok(())
}

fn render_entry_human(view: &EntryView) -> String {
    let mut lines = vec![
        format!("name: {}", view.name),
        format!("id: {}", view.id),
        format!("category: {}", view.category),
    ];
    if let Some(title) = &view.title {
        lines.push(format!("title: {title}"));
    }
    if !view.tags.is_empty() {
        lines.push(format!("tags: {}", view.tags.join(", ")));
    }
    lines.push(format!("favorite: {}", view.favorite));
    if let Some(url) = &view.url {
        lines.push(format!("url: {url}"));
    }
    if let Some(notes) = &view.notes {
        lines.push(format!("notes: {notes}"));
    }
    if let Some(expires) = view.expires_at {
        lines.push(format!("expires_at: {expires}"));
    }
    if let Some(rotated) = view.rotated_at {
        lines.push(format!("rotated_at: {rotated}"));
    }
    if let Some(deleted) = view.deleted_at {
        lines.push(format!("deleted_at: {deleted}"));
    }
    lines.push(format!("reveal: {}", view.reveal.as_str()));

    let width = view.fields.iter().map(|f| f.label.len()).max().unwrap_or(0);
    for field in &view.fields {
        let mut line = format!("{:<width$} = {}", field.label, field.value, width = width);
        if field.concealed {
            line.push_str(&format!("  ({})", field.reference));
        }
        if let Some(otp) = &field.otp {
            line.push_str(&format!("  otp={otp}"));
        }
        lines.push(line);
    }
    lines.join("\n")
}

fn render_list_human(rows: &[EntrySummary]) -> String {
    if rows.is_empty() {
        return "no entries".to_string();
    }
    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let cat_width = rows.iter().map(|r| r.category.as_str().len()).max().unwrap_or(0);
    rows.iter()
        .map(|row| {
            let mut line = format!(
                "{:<name_width$}  {:<cat_width$}  {}",
                row.name,
                row.category.as_str(),
                row.id,
                name_width = name_width,
                cat_width = cat_width,
            );
            if !row.tags.is_empty() {
                line.push_str(&format!("  tags:{}", row.tags.join(",")));
            }
            if row.favorite {
                line.push_str("  favorite");
            }
            if let Some(expires) = row.expires_at {
                line.push_str(&format!("  expires:{expires}"));
            }
            if row.deleted_at.is_some() {
                line.push_str("  [deleted]");
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────── Assignments and field editing ───────────────────────────

/// One assignment: `[<section>.]<field>[[<type>]]=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Assignment {
    section: Option<String>,
    label: String,
    ty: Option<FieldType>,
    action: AssignAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssignAction {
    Set(String),
    Delete,
}

const ASSIGNABLE_TYPES: [FieldType; 10] = [
    FieldType::String,
    FieldType::Concealed,
    FieldType::Email,
    FieldType::Url,
    FieldType::Otp,
    FieldType::Date,
    FieldType::Number,
    FieldType::File,
    FieldType::SshKey,
    FieldType::Notes,
];

/// Characters a backslash may escape (any other `\x` is kept verbatim, so a private key or regex containing a backslash survives).
fn is_escapable(c: char) -> bool {
    matches!(c, '.' | '=' | '[' | ']' | '\\')
}

/// Find the **first unescaped** separator and split the input in two.
fn split_unescaped(input: &str, sep: char) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (idx, c) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' && input[idx + 1..].chars().next().is_some_and(is_escapable) {
            escaped = true;
            continue;
        }
        if c == sep {
            return Some((&input[..idx], &input[idx + c.len_utf8()..]));
        }
    }
    None
}

fn unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().copied().is_some_and(is_escapable) {
            out.push(chars.next().expect("peeked"));
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_field_type(raw: &str, spec: &str) -> Result<FieldType> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    if let Some(ty) = ASSIGNABLE_TYPES.iter().find(|ty| ty.as_str() == normalized) {
        return Ok(*ty);
    }
    Err(Error::usage(format!(
        "unknown field type '{raw}' in '{spec}'; expected one of string, concealed, email, url, otp, date, number, file, ssh-key, notes"
    )))
}

/// Parse `[section.]field[type]=value`; `value == [delete]` means delete that field.
fn parse_assignment(spec: &str) -> Result<Assignment> {
    let (lhs, raw_value) = split_unescaped(spec, '=').ok_or_else(|| {
        Error::usage(format!(
            "assignment '{spec}' is missing '='; expected [section.]field[[type]]=value"
        ))
    })?;

    let (head, ty) = match split_unescaped(lhs, '[') {
        Some((head, rest)) => {
            // Both spellings are accepted: `field[type]` and the 1Password-style `field[[type]]`.
            // DESIGN.md always wrote the latter while the parser only took the former — a doc and
            // an implementation disagreeing is itself a defect.
            let inner = rest
                .strip_suffix(']')
                .map(|inner| inner.strip_prefix('[').unwrap_or(inner))
                .map(|inner| inner.strip_suffix(']').unwrap_or(inner))
                .filter(|inner| !inner.is_empty() && !inner.contains(['[', ']']));
            let inner = inner.ok_or_else(|| {
                Error::usage(format!(
                    "malformed type suffix in '{spec}'; expected field[type]=value"
                ))
            })?;
            (head, Some(parse_field_type(inner, spec)?))
        }
        None => (lhs, None),
    };

    let (section, label) = match split_unescaped(head, '.') {
        Some((section, label)) => {
            if section.is_empty() {
                return Err(Error::usage(format!(
                    "assignment '{spec}' has an empty section"
                )));
            }
            (Some(unescape(section)), unescape(label))
        }
        None => (None, unescape(head)),
    };
    if label.is_empty() {
        return Err(Error::usage(format!(
            "assignment '{spec}' has an empty field name"
        )));
    }

    let value = unescape(raw_value);
    let action = if value == "[delete]" {
        AssignAction::Delete
    } else {
        AssignAction::Set(value)
    };
    Ok(Assignment {
        section,
        label,
        ty,
        action,
    })
}

fn field_matches(field: &Field, assignment: &Assignment) -> bool {
    let target = slug(&assignment.label);
    let name_hit = field.id == target
        || field.id == assignment.label
        || field.label.eq_ignore_ascii_case(&assignment.label);
    let section_hit = assignment
        .section
        .as_ref()
        .is_none_or(|s| field.section.as_deref() == Some(s.as_str()));
    name_hit && section_hit
}

/// Apply one assignment. If the field exists, change its value (filling in the given section / type); otherwise create it.
fn apply_assignment(entry: &mut Entry, assignment: &Assignment) {
    match &assignment.action {
        AssignAction::Delete => entry.fields.retain(|f| !field_matches(f, assignment)),
        AssignAction::Set(value) => {
            if let Some(field) = entry.fields.iter_mut().find(|f| field_matches(f, assignment)) {
                field.value = Zeroizing::new(value.clone());
                if let Some(section) = &assignment.section {
                    field.section = Some(section.clone());
                }
                if let Some(ty) = assignment.ty {
                    field.ty = ty;
                }
            } else {
                let ty = assignment.ty.unwrap_or(FieldType::Concealed);
                let mut field = Field::new(&assignment.label, ty, value.clone());
                field.section = assignment.section.clone();
                entry.fields.push(field);
            }
        }
    }
}

fn apply_assignments(entry: &mut Entry, assignments: &[Assignment]) {
    for assignment in assignments {
        apply_assignment(entry, assignment);
    }
}

/// Labels whose plaintext came in through argv and landed in a concealed field (for the warning). Empty values do not count.
fn argv_secret_labels(entry: &Entry, assignments: &[Assignment]) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for assignment in assignments {
        let AssignAction::Set(value) = &assignment.action else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if let Some(field) = entry.fields.iter().find(|f| field_matches(f, assignment))
            && field.is_concealed()
            && !labels.contains(&field.label)
        {
            labels.push(field.label.clone());
        }
    }
    labels
}

fn warn_argv_secrets(ctx: &Ctx, plan: &SetPlan, entry: &Entry) {
    warn_argv_secrets_edit(ctx, &plan.assignments, entry);
}

fn warn_argv_secrets_edit(ctx: &Ctx, assignments: &[Assignment], entry: &Entry) {
    let labels = argv_secret_labels(entry, assignments);
    if labels.is_empty() {
        return;
    }
    ctx.out.warn(&format!(
        "plaintext for {} came in through argv (visible to `ps` and shell history); prefer --stdin or --template",
        labels.join(", ")
    ));
}

// ─────────────────────────── stdin / password generation ───────────────────────────

fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// The two shapes of `--stdin`: lines containing `=` are parsed one by one as assignments; otherwise the whole input is a single secret value.
fn apply_stdin(entry: &mut Entry, text: &str, secret_field: Option<&str>) -> Result<()> {
    let body = text.trim_end_matches(['\n', '\r']);
    if body.trim().is_empty() {
        return Err(Error::usage("--stdin received no input"));
    }
    if body.lines().any(|line| line.contains('=')) {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let assignment = parse_assignment(line)?;
            apply_assignment(entry, &assignment);
        }
        return Ok(());
    }
    let label = match secret_field {
        Some(label) if !label.is_empty() => label.to_string(),
        _ => {
            let default = entry.category.default_secret_field();
            if default.is_empty() {
                return Err(Error::usage(format!(
                    "category '{}' has no default secret field; pass --secret-field",
                    entry.category
                )));
            }
            default.to_string()
        }
    };
    apply_assignment(
        entry,
        &Assignment {
            section: None,
            label,
            ty: None,
            action: AssignAction::Set(body.to_string()),
        },
    );
    Ok(())
}

const LETTER_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT_CHARS: &str = "0123456789";
/// No quotes, backslashes, or spaces, keeping shells and serialization out of trouble.
const SYMBOL_CHARS: &str = "!@#$%^&*()-_=+[]{}:,.?/";

const DEFAULT_PASSWORD_LEN: usize = 32;
const MAX_PASSWORD_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Recipe {
    letters: bool,
    digits: bool,
    symbols: bool,
    len: usize,
}

/// A recipe looks like `letters,digits,symbols,32`: character classes default to all, length to 32.
fn parse_recipe(raw: &str) -> Result<Recipe> {
    let mut letters = false;
    let mut digits = false;
    let mut symbols = false;
    let mut len: Option<usize> = None;
    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        match token.to_ascii_lowercase().as_str() {
            "letters" | "letter" | "alpha" => letters = true,
            "digits" | "digit" | "numbers" | "number" => digits = true,
            "symbols" | "symbol" | "punct" => symbols = true,
            other => match other.parse::<usize>() {
                Ok(n) if n > 0 && n <= MAX_PASSWORD_LEN => len = Some(n),
                Ok(n) => {
                    return Err(Error::usage(format!(
                        "password length {n} out of range; expected 1..={MAX_PASSWORD_LEN}"
                    )));
                }
                Err(_) => {
                    return Err(Error::usage(format!(
                        "unknown password recipe token '{token}'; expected letters, digits, symbols or a length"
                    )));
                }
            },
        }
    }
    if !(letters || digits || symbols) {
        letters = true;
        digits = true;
        symbols = true;
    }
    Ok(Recipe {
        letters,
        digits,
        symbols,
        len: len.unwrap_or(DEFAULT_PASSWORD_LEN),
    })
}

fn recipe_pool(recipe: &Recipe) -> Vec<char> {
    let mut pool = Vec::new();
    if recipe.letters {
        pool.extend(LETTER_CHARS.chars());
    }
    if recipe.digits {
        pool.extend(DIGIT_CHARS.chars());
    }
    if recipe.symbols {
        pool.extend(SYMBOL_CHARS.chars());
    }
    pool
}

/// Draw characters from a byte source. Bytes `>= limit` are rejected (removing modulo bias); if the source misbehaves, a final
/// modulo fallback guarantees the **length always equals the recipe length** without looping forever.
fn password_from_bytes<F: FnMut() -> u8>(recipe: &Recipe, mut next: F) -> String {
    let pool = recipe_pool(recipe);
    let size = pool.len();
    let limit = 256 - (256 % size);
    let mut out = String::with_capacity(recipe.len);
    let cap = recipe.len.saturating_mul(64).saturating_add(64);
    let mut attempts = 0usize;
    while out.len() < recipe.len && attempts < cap {
        attempts += 1;
        let byte = next();
        if (byte as usize) < limit {
            out.push(pool[byte as usize % size]);
        }
    }
    while out.len() < recipe.len {
        out.push(pool[next() as usize % size]);
    }
    out
}

fn generate_password(recipe: &Recipe) -> String {
    let mut buf = vec![0u8; recipe.len + recipe.len / 2 + 8];
    rand::fill(buf.as_mut_slice());
    let mut cursor = 0usize;
    password_from_bytes(recipe, || {
        if cursor >= buf.len() {
            rand::fill(buf.as_mut_slice());
            cursor = 0;
        }
        let byte = buf[cursor];
        cursor += 1;
        byte
    })
}

// ─────────────────────────────── Templates ───────────────────────────────

/// The shape of `--template` input: the whole set of **writable** `Entry` fields, every one optional.
/// `value` uses `Value` to accept non-string spellings such as numbers and booleans.
#[derive(Debug, Default, Deserialize)]
struct EntryTemplate {
    #[serde(default)]
    category: Option<Category>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    fields: Vec<FieldTemplate>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: Option<bool>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    reveal: Option<Reveal>,
}

#[derive(Debug, Deserialize)]
struct FieldTemplate {
    label: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "type")]
    ty: Option<FieldType>,
    #[serde(default)]
    section: Option<String>,
    #[serde(default)]
    value: Value,
}

fn json_value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl FieldTemplate {
    fn to_field(&self) -> Field {
        let mut field = Field::new(
            &self.label,
            self.ty.unwrap_or(FieldType::Concealed),
            json_value_to_string(&self.value),
        );
        field.id = self.id.clone().unwrap_or_else(|| slug(&self.label));
        field.section = self.section.clone();
        field
    }
}

impl EntryTemplate {
    fn to_entry(&self, id: Ulid, name: String, now: DateTime<Utc>) -> Entry {
        let mut entry = Entry::new(id, name, self.category.unwrap_or(Category::Apikey), now);
        self.overlay(&mut entry);
        entry
    }

    /// Overlay the template content onto the entry; preserving ID / name / `created_at` is the caller's job.
    /// An empty `fields` array does not overwrite (so an empty template cannot wipe existing fields).
    fn overlay(&self, entry: &mut Entry) {
        if let Some(category) = self.category {
            entry.category = category;
        }
        if let Some(title) = &self.title {
            entry.title = Some(title.clone());
        }
        if !self.fields.is_empty() {
            entry.fields = self.fields.iter().map(FieldTemplate::to_field).collect();
        }
        if !self.tags.is_empty() {
            entry.tags = self.tags.clone();
        }
        if let Some(favorite) = self.favorite {
            entry.favorite = favorite;
        }
        if let Some(url) = &self.url {
            entry.url = Some(url.clone());
        }
        if let Some(notes) = &self.notes {
            entry.notes = Some(notes.clone());
        }
        if let Some(expires_at) = self.expires_at {
            entry.expires_at = Some(expires_at);
        }
        if let Some(reveal) = self.reveal {
            entry.reveal = reveal;
        }
    }
}

fn read_template(path: &Path) -> Result<EntryTemplate> {
    // Use std::fs instead of paths::read_file: the latter is for akey's **own** files, and it reads
    // a missing file as "the repo is not initialized, go run akey init" — nonsense for a user-supplied template path.
    let bytes = std::fs::read(path).map_err(|e| {
        Error::usage(format!("cannot read template {}: {e}", path.display()))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::usage(format!("template {} is not valid JSON: {e}", path.display())))
}

/// The output of `template get <category>`: a skeleton of the built-in fields with empty values.
fn category_template(category: Category) -> Value {
    json!({
        "name": "",
        "category": category,
        "title": Value::Null,
        "fields": category
            .builtin_fields()
            .iter()
            .map(|(label, ty)| json!({
                "id": slug(label),
                "label": label,
                "type": ty.as_str(),
                "value": "",
            }))
            .collect::<Vec<_>>(),
        "tags": [],
        "favorite": false,
        "url": Value::Null,
        "notes": Value::Null,
        "expires_at": Value::Null,
        "reveal": Reveal::Allow,
    })
}

// ─────────────────────────────── Pure write-path functions ───────────────────────────────

fn skeleton(id: Ulid, name: String, category: Category, now: DateTime<Utc>) -> Entry {
    let mut entry = Entry::new(id, name, category, now);
    entry.fields = category
        .builtin_fields()
        .iter()
        .map(|(label, ty)| Field::new(label, *ty, String::new()))
        .collect();
    entry
}

/// A write command cannot revive a soft-deleted entry in place; `restore` first, then edit.
fn writable_entry(vault: &Vault, key: &str) -> Result<Option<Entry>> {
    match vault.find(key) {
        Ok(entry) if entry.is_deleted() => Err(Error::usage(format!(
            "entry '{}' is deleted; run `akey restore {}` first",
            entry.name, entry.name
        ))),
        Ok(entry) => Ok(Some(entry.clone())),
        Err(Error::NotFound(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

struct SetPlan {
    name: String,
    category: Option<Category>,
    title: Option<String>,
    tags: Option<Vec<String>>,
    template: Option<EntryTemplate>,
    stdin_text: Option<String>,
    secret_field: Option<String>,
    generate_password: Option<String>,
    assignments: Vec<Assignment>,
}

impl SetPlan {
    fn from_args(args: &SetArgs) -> Result<SetPlan> {
        if args.stdin && args.generate_password.is_some() {
            return Err(Error::usage(
                "--stdin and --generate-password cannot be combined",
            ));
        }
        let assignments = args
            .assignments
            .iter()
            .map(|spec| parse_assignment(spec))
            .collect::<Result<Vec<_>>>()?;
        let template = match &args.template {
            Some(path) => Some(read_template(path)?),
            None => None,
        };
        let stdin_text = if args.stdin {
            Some(read_stdin()?)
        } else {
            None
        };
        Ok(SetPlan {
            name: args.item.clone(),
            category: args.category,
            title: args.title.clone(),
            tags: (!args.tags.is_empty()).then(|| args.tags.clone()),
            template,
            stdin_text,
            secret_field: args.secret_field.clone(),
            generate_password: args.generate_password.clone(),
            assignments,
        })
    }
}

#[derive(Debug)]
struct SetOutcome {
    entry: Entry,
    created: bool,
}

fn apply_set(vault: &mut Vault, plan: &SetPlan, now: DateTime<Utc>) -> Result<SetOutcome> {
    if !is_valid_name(&plan.name) {
        return Err(Error::usage(format!(
            "invalid entry name '{}': expected ^[a-z0-9][a-z0-9._-]*$ with at most {MAX_NAME_LEN} chars",
            plan.name
        )));
    }
    let existing = writable_entry(vault, &plan.name)?;
    let created = existing.is_none();

    let mut entry = match (existing, &plan.template) {
        (Some(entry), Some(template)) => {
            let mut entry = entry;
            template.overlay(&mut entry);
            entry
        }
        (Some(entry), None) => entry,
        (None, Some(template)) => {
            template.to_entry(Ulid::generate(), plan.name.clone(), now)
        }
        (None, None) => skeleton(
            Ulid::generate(),
            plan.name.clone(),
            plan.category.unwrap_or(Category::Apikey),
            now,
        ),
    };
    if let Some(category) = plan.category {
        entry.category = category;
    }
    if let Some(title) = &plan.title {
        entry.title = Some(title.clone());
    }
    if let Some(tags) = &plan.tags {
        entry.tags = tags.clone();
    }
    apply_assignments(&mut entry, &plan.assignments);
    if let Some(text) = &plan.stdin_text {
        apply_stdin(&mut entry, text, plan.secret_field.as_deref())?;
    }
    if let Some(raw) = &plan.generate_password {
        let recipe = parse_recipe(raw)?;
        let label = plan
            .secret_field
            .clone()
            .unwrap_or_else(|| entry.category.default_secret_field().to_string());
        if label.is_empty() {
            return Err(Error::usage(format!(
                "category '{}' has no default secret field; pass --secret-field",
                entry.category
            )));
        }
        apply_assignment(
            &mut entry,
            &Assignment {
                section: None,
                label,
                ty: Some(FieldType::Concealed),
                action: AssignAction::Set(generate_password(&recipe)),
            },
        );
    }
    entry.updated_at = now;

    vault.entries.insert(entry.id, entry.clone());
    Ok(SetOutcome { entry, created })
}

struct EditPlan {
    item: String,
    title: Option<String>,
    tags: Option<Vec<String>>,
    template: Option<EntryTemplate>,
    favorite: bool,
    unfavorite: bool,
    rotate: bool,
    reveal_policy: Option<Reveal>,
    assignments: Vec<Assignment>,
}

impl EditPlan {
    fn from_args(args: &EditArgs) -> Result<EditPlan> {
        if args.favorite && args.unfavorite {
            return Err(Error::usage("--favorite and --unfavorite cannot be combined"));
        }
        let assignments = args
            .assignments
            .iter()
            .map(|spec| parse_assignment(spec))
            .collect::<Result<Vec<_>>>()?;
        let template = match &args.template {
            Some(path) => Some(read_template(path)?),
            None => None,
        };
        let plan = EditPlan {
            item: args.item.clone(),
            title: args.title.clone(),
            tags: (!args.tags.is_empty()).then(|| args.tags.clone()),
            template,
            favorite: args.favorite,
            unfavorite: args.unfavorite,
            rotate: args.rotate,
            reveal_policy: args.reveal_policy.map(|p| match p {
                RevealPolicy::Allow => Reveal::Allow,
                RevealPolicy::Deny => Reveal::Deny,
            }),
            assignments,
        };
        if !plan.changes_anything() {
            return Err(Error::usage(
                "nothing to change; pass assignments or one of --title/--tags/--favorite/--unfavorite/--rotate/--reveal-policy/--template",
            ));
        }
        Ok(plan)
    }

    fn changes_anything(&self) -> bool {
        !self.assignments.is_empty()
            || self.title.is_some()
            || self.tags.is_some()
            || self.template.is_some()
            || self.favorite
            || self.unfavorite
            || self.rotate
            || self.reveal_policy.is_some()
    }
}

#[derive(Debug)]
struct EditOutcome {
    entry: Entry,
    changed: bool,
}

fn apply_edit(vault: &mut Vault, plan: &EditPlan, now: DateTime<Utc>) -> Result<EditOutcome> {
    let mut entry = writable_entry(vault, &plan.item)?
        .ok_or_else(|| Error::not_found(format!("no entry named '{}'", plan.item)))?;

    if let Some(template) = &plan.template {
        template.overlay(&mut entry);
    }
    if let Some(title) = &plan.title {
        entry.title = Some(title.clone());
    }
    if let Some(tags) = &plan.tags {
        entry.tags = tags.clone();
    }
    if plan.favorite {
        entry.favorite = true;
    }
    if plan.unfavorite {
        entry.favorite = false;
    }
    if plan.rotate {
        entry.rotated_at = Some(now);
    }
    if let Some(reveal) = plan.reveal_policy {
        entry.reveal = reveal;
    }
    apply_assignments(&mut entry, &plan.assignments);
    entry.updated_at = now;

    vault.entries.insert(entry.id, entry.clone());
    Ok(EditOutcome {
        entry,
        changed: true,
    })
}

/// The result of a batch operation. A failing item does not block the others — successful changes are persisted as usual.
#[derive(Default)]
struct BatchReport {
    results: Vec<BatchResult>,
    failed: Vec<(String, Error)>,
}

#[derive(Debug)]
struct BatchResult {
    item: String,
    name: String,
    action: &'static str,
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
            .map(|r| format!("{} '{}'", r.action.replace('_', " "), r.name))
            .collect();
        lines.extend(
            self.failed
                .iter()
                .map(|(item, err)| format!("failed '{item}': {err}")),
        );
        if lines.is_empty() {
            return "nothing to do".to_string();
        }
        lines.join("\n")
    }

    /// Returns an error when any item failed (keeping the first item's kind and exit code), naming the successful items in the message.
    fn into_error(self) -> Result<()> {
        if self.failed.is_empty() {
            return Ok(());
        }
        let succeeded = self.succeeded();
        let (_, first) = &self.failed[0];
        let head = format!(
            "{} of {} item(s) failed ({first}); {}",
            self.failed.len(),
            self.failed.len() + succeeded.len(),
            if succeeded.is_empty() {
                "nothing was changed".to_string()
            } else {
                format!("succeeded: {}", succeeded.join(", "))
            }
        );
        Err(match first.code() {
            "usage" => Error::Usage(head),
            "ambiguous" => Error::Ambiguous(head),
            _ => Error::NotFound(head),
        })
    }
}

fn apply_rm(vault: &mut Vault, items: &[String], purge: bool, now: DateTime<Utc>) -> BatchReport {
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

fn apply_restore(vault: &mut Vault, items: &[String], now: DateTime<Utc>) -> BatchReport {
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
                Error::usage(format!(
                    "cannot restore '{name}': another entry already uses that name; rename one of them first"
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
struct CpOutcome {
    source: String,
    source_id: Ulid,
    destination: String,
    id: Ulid,
    fields: usize,
}

fn apply_cp(
    vault: &mut Vault,
    source: &str,
    destination: &str,
    now: DateTime<Utc>,
) -> Result<CpOutcome> {
    if !is_valid_name(destination) {
        return Err(Error::usage(format!(
            "invalid entry name '{destination}': expected ^[a-z0-9][a-z0-9._-]*$"
        )));
    }
    let origin = vault.find(source)?.clone();
    if vault.entries.values().any(|e| e.name == destination) {
        return Err(Error::usage(format!(
            "entry '{destination}' already exists; pick another name"
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
struct MvOutcome {
    id: Ulid,
    old_name: String,
    new_name: String,
}

fn apply_mv(vault: &mut Vault, old: &str, new: &str, now: DateTime<Utc>) -> Result<MvOutcome> {
    if !is_valid_name(new) {
        return Err(Error::usage(format!(
            "invalid entry name '{new}': expected ^[a-z0-9][a-z0-9._-]*$"
        )));
    }
    let entry = vault.find(old)?.clone();
    if entry.name != new && vault.name_taken(new, entry.id) {
        return Err(Error::usage(format!(
            "entry '{new}' already exists; pick another name"
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

// ─────────────────────────────── Filtering and conflicts ───────────────────────────────

/// `list` filtering: soft-deleted, tags (AND), category, favorite, expiry window. Results are sorted by name (deterministic).
fn select_entries<'a>(
    vault: &'a Vault,
    args: &ListArgs,
    now: DateTime<Utc>,
) -> Result<Vec<&'a Entry>> {
    let window = match &args.expiring {
        Some(raw) => Some((now, now + parse_duration(raw)?)),
        None => None,
    };
    let mut selected: Vec<&Entry> = vault
        .entries
        .values()
        .filter(|entry| args.all || !entry.is_deleted())
        .filter(|entry| {
            args.tags
                .iter()
                .all(|tag| entry.tags.iter().any(|t| t == tag))
        })
        .filter(|entry| args.category.is_none_or(|c| entry.category == c))
        .filter(|entry| !args.favorite || entry.favorite)
        .filter(|entry| match window {
            // An already-expired entry does not count as "about to expire".
            Some((start, end)) => entry.expires_at.is_some_and(|at| at >= start && at <= end),
            None => true,
        })
        .collect();
    selected.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(selected)
}

fn conflict_base(name: &str) -> Option<&str> {
    name.rsplit_once(CONFLICT_MARK)
        .map(|(base, _)| base)
        .filter(|base| !base.is_empty())
}

fn conflict_views(vault: &Vault) -> Vec<ConflictView> {
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
enum Side {
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
struct ResolveOutcome {
    name: String,
    id: Ulid,
    side: Side,
    /// Where the content came from (with `--ours`, the original-name entry itself).
    kept: String,
    removed: Vec<String>,
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
    Err(Error::not_found(format!("no entry named '{key}'")))
}

fn apply_resolve(
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
        .ok_or_else(|| Error::not_found(format!("no entry named '{base}'")))?;

    let prefix = format!("{base}{CONFLICT_MARK}");
    let mut copies: Vec<(Ulid, String, DateTime<Utc>)> = vault
        .entries
        .values()
        .filter(|entry| entry.name.starts_with(&prefix))
        .map(|entry| (entry.id, entry.name.clone(), entry.updated_at))
        .collect();
    if copies.is_empty() {
        return Err(Error::usage(format!(
            "no conflict copy found for '{base}'; run `akey conflicts` first"
        )));
    }
    // With several copies, take the newest one, the name as tiebreaker, so the result is reproducible.
    copies.sort_by(|a, b| a.2.cmp(&b.2).then(a.1.cmp(&b.1)));
    let (source_id, source_name, _) = copies.last().expect("checked non-empty").clone();
    let source = vault
        .entries
        .get(&source_id)
        .cloned()
        .ok_or_else(|| Error::not_found(format!("conflict copy '{source_name}' vanished")))?;

    let entry = vault
        .entries
        .get_mut(&base_id)
        .ok_or_else(|| Error::not_found(format!("no entry named '{base}'")))?;
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

// ─────────────────────────────── Small helpers ───────────────────────────────

fn json_err(err: serde_json::Error) -> Error {
    Error::Io(std::io::Error::other(err))
}

fn record_batch(ctx: &Ctx, store: &crate::vault::store::Store, action: Action, report: &BatchReport) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const CANARY: &str = "CANARY-3f9a-secret-value";

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn entry(name: &str, category: Category) -> Entry {
        Entry::new(Ulid::generate(), name.to_string(), category, now())
    }

    fn vault_with(entries: Vec<Entry>) -> Vault {
        let mut vault = Vault::default();
        for entry in entries {
            vault.entries.insert(entry.id, entry);
        }
        vault
    }

    fn set_plan(name: &str, category: Option<Category>, assignments: &[&str]) -> SetPlan {
        SetPlan {
            name: name.to_string(),
            category,
            title: None,
            tags: None,
            template: None,
            stdin_text: None,
            secret_field: None,
            generate_password: None,
            assignments: assignments
                .iter()
                .map(|spec| parse_assignment(spec).expect("test assignment must parse"))
                .collect(),
        }
    }

    fn list_args(tags: &[&str], all: bool, expiring: Option<&str>) -> ListArgs {
        ListArgs {
            tags: tags.iter().map(|t| t.to_string()).collect(),
            category: None,
            expiring: expiring.map(str::to_string),
            favorite: false,
            all,
        }
    }

    // 1. Assignment parsing
    #[test]
    fn assignment_parsing_table() {
        let cases: &[(&str, Assignment)] = &[
            (
                "credential=sk-1",
                Assignment {
                    section: None,
                    label: "credential".into(),
                    ty: None,
                    action: AssignAction::Set("sk-1".into()),
                },
            ),
            (
                "api.username=me",
                Assignment {
                    section: Some("api".into()),
                    label: "username".into(),
                    ty: None,
                    action: AssignAction::Set("me".into()),
                },
            ),
            (
                "notes[string]=hello",
                Assignment {
                    section: None,
                    label: "notes".into(),
                    ty: Some(FieldType::String),
                    action: AssignAction::Set("hello".into()),
                },
            ),
            (
                "token[ssh-key]=k",
                Assignment {
                    section: None,
                    label: "token".into(),
                    ty: Some(FieldType::SshKey),
                    action: AssignAction::Set("k".into()),
                },
            ),
            (
                // The value contains '=': only the first unescaped '=' is the separator.
                "dsn=postgres://u:p@h/db?sslmode=require",
                Assignment {
                    section: None,
                    label: "dsn".into(),
                    ty: None,
                    action: AssignAction::Set("postgres://u:p@h/db?sslmode=require".into()),
                },
            ),
            (
                // An escaped dot: the field name really contains a dot, not a section separator.
                r"a\.b=x",
                Assignment {
                    section: None,
                    label: "a.b".into(),
                    ty: None,
                    action: AssignAction::Set("x".into()),
                },
            ),
            (
                // An escaped equals sign stays in the value.
                r"password=pa\=ss",
                Assignment {
                    section: None,
                    label: "password".into(),
                    ty: None,
                    action: AssignAction::Set("pa=ss".into()),
                },
            ),
            (
                "custom=[delete]",
                Assignment {
                    section: None,
                    label: "custom".into(),
                    ty: None,
                    action: AssignAction::Delete,
                },
            ),
            (
                "sec.old[concealed]=[delete]",
                Assignment {
                    section: Some("sec".into()),
                    label: "old".into(),
                    ty: Some(FieldType::Concealed),
                    action: AssignAction::Delete,
                },
            ),
        ];
        for (spec, expected) in cases {
            let parsed = parse_assignment(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            assert_eq!(&parsed, expected, "{spec}");
        }

        for bad in ["nothing", "=x", "field[bogus]=1", "[delete]", "a[=1", "a[]=1", ".field=x"] {
            let err = parse_assignment(bad).unwrap_err();
            assert!(matches!(err, Error::Usage(_)), "{bad} -> {err:?}");
        }
    }

    #[test]
    fn assignment_applies_sections_and_deletes_only_matching_field() {
        let mut e = entry("x", Category::EnvBundle);
        apply_assignments(
            &mut e,
            &[
                parse_assignment("prod.token=one").unwrap(),
                parse_assignment("dev.token=two").unwrap(),
                parse_assignment("plain=three").unwrap(),
            ],
        );
        assert_eq!(e.field("token").map(|f| f.value()), Some("one"));
        assert_eq!(e.fields.len(), 3);

        // A delete with a section removes only that section's field.
        apply_assignments(&mut e, &[parse_assignment("prod.token=[delete]").unwrap()]);
        let remaining: Vec<&Field> = e.fields.iter().filter(|f| f.id == "token").collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].section.as_deref(), Some("dev"));

        // New fields are concealed by default — under D1, not asking for plaintext means concealed.
        let plain = e.field("plain").expect("plain");
        assert!(plain.is_concealed());
    }

    // 2. set: create → update
    #[test]
    fn set_creates_then_updates_in_place() {
        let mut vault = Vault::default();
        let t0 = now();
        let plan = set_plan("openai", Some(Category::Apikey), &["credential=sk-aaa"]);
        let created = apply_set(&mut vault, &plan, t0).unwrap();
        assert!(created.created);
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(created.entry.fields.len(), 2, "apikey skeleton");
        assert_eq!(
            created.entry.field("credential").map(|f| f.value()),
            Some("sk-aaa")
        );

        let t1 = t0 + Duration::seconds(5);
        let plan = set_plan("openai", None, &["credential=sk-bbb"]);
        let updated = apply_set(&mut vault, &plan, t1).unwrap();
        assert!(!updated.created);
        assert_eq!(vault.entries.len(), 1, "must not create a second entry");
        assert_eq!(updated.entry.id, created.entry.id);
        assert_eq!(updated.entry.created_at, created.entry.created_at);
        assert!(updated.entry.updated_at > created.entry.updated_at);
        assert_eq!(
            updated.entry.field("credential").map(|f| f.value()),
            Some("sk-bbb")
        );
        assert_eq!(updated.entry.category, Category::Apikey, "category kept");

        let bad = set_plan("Bad Name", None, &[]);
        assert!(matches!(
            apply_set(&mut vault, &bad, t1).unwrap_err(),
            Error::Usage(_)
        ));
        assert_eq!(vault.entries.len(), 1);
    }

    #[test]
    fn set_refuses_to_silently_resurrect_deleted_entry() {
        let mut vault = Vault::default();
        let t = now();
        apply_set(
            &mut vault,
            &set_plan("openai", Some(Category::Apikey), &[]),
            t,
        )
        .unwrap();
        apply_rm(&mut vault, &["openai".to_string()], false, t);
        assert!(matches!(
            apply_set(&mut vault, &set_plan("openai", None, &[]), t).unwrap_err(),
            Error::Usage(_)
        ));

        apply_restore(&mut vault, &["openai".to_string()], t);
        let outcome = apply_set(&mut vault, &set_plan("openai", None, &[]), t).unwrap();
        assert!(!outcome.created);
    }

    // 3. The two shapes of --stdin
    #[test]
    fn stdin_forms_land_in_the_right_fields() {
        let mut e = entry("github", Category::Login);
        e.fields = Category::Login
            .builtin_fields()
            .iter()
            .map(|(l, t)| Field::new(l, *t, String::new()))
            .collect();

        apply_stdin(&mut e, "username=me\npassword=pw\n", None).unwrap();
        assert_eq!(e.field("username").map(|f| f.value()), Some("me"));
        assert_eq!(e.field("password").map(|f| f.value()), Some("pw"));

        // A bare secret value lands in the category's default secret field, overwriting any existing value.
        apply_stdin(&mut e, CANARY, None).unwrap();
        assert_eq!(e.field("password").map(|f| f.value()), Some(CANARY));
        assert_eq!(e.field("username").map(|f| f.value()), Some("me"));

        // --secret-field overrides the default target.
        apply_stdin(&mut e, "token-value\n", Some("username")).unwrap();
        assert_eq!(e.field("username").map(|f| f.value()), Some("token-value"));

        // env-bundle has no default secret field.
        let err = apply_stdin(&mut entry("env", Category::EnvBundle), "raw", None).unwrap_err();
        assert!(matches!(err, Error::Usage(_)));
        apply_stdin(
            &mut entry("env", Category::EnvBundle),
            "raw",
            Some("API_KEY"),
        )
        .unwrap();
    }

    // 4. Password recipes
    #[test]
    fn password_recipe_parsing_and_charset() {
        let default = parse_recipe("").unwrap();
        assert_eq!(default.len, DEFAULT_PASSWORD_LEN);
        assert!(default.letters && default.digits && default.symbols);

        let digits_only = parse_recipe("digits,16").unwrap();
        assert_eq!(digits_only.len, 16);
        assert!(digits_only.digits && !digits_only.letters && !digits_only.symbols);

        let letters_only = parse_recipe("letters").unwrap();
        assert_eq!(letters_only.len, DEFAULT_PASSWORD_LEN);
        assert!(letters_only.letters && !letters_only.digits);

        assert!(matches!(parse_recipe("bogus").unwrap_err(), Error::Usage(_)));
        assert!(matches!(parse_recipe("0").unwrap_err(), Error::Usage(_)));
        assert!(matches!(parse_recipe("s,99999").unwrap_err(), Error::Usage(_)));

        // A fixed byte source → deterministic assertions on length and character set.
        let mut counter = 0u8;
        let generated = password_from_bytes(&digits_only, move || {
            let value = counter;
            counter = counter.wrapping_add(1);
            value
        });
        assert_eq!(generated.len(), 16);
        assert!(
            generated.chars().all(|c| c.is_ascii_digit()),
            "digits-only recipe leaked other classes: {generated}"
        );

        // The letters+digits pool: bytes 0..61 cover a-z, A-Z, 0-9 in order.
        let letters_digits = parse_recipe("letters,digits,62").unwrap();
        let mut counter = 0u8;
        let generated = password_from_bytes(&letters_digits, move || {
            let value = counter % 62;
            counter = counter.wrapping_add(1);
            value
        });
        assert_eq!(generated.len(), 62);
        assert!(generated.chars().any(|c| c.is_ascii_digit()));
        assert!(generated.chars().any(|c| c.is_ascii_alphabetic()));
        assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));

        // A truly random source must hold the length and character set too.
        let random = generate_password(&digits_only);
        assert_eq!(random.len(), 16);
        assert!(random.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn set_generate_password_fills_default_secret_field() {
        let mut vault = Vault::default();
        let mut plan = set_plan("db", Some(Category::Database), &[]);
        plan.generate_password = Some("digits,24".to_string());
        let outcome = apply_set(&mut vault, &plan, now()).unwrap();
        let password = outcome.entry.field("password").expect("password field");
        assert!(password.is_concealed());
        assert_eq!(password.value().len(), 24);
        assert!(password.value().chars().all(|c| c.is_ascii_digit()));

        let mut conflicting = set_plan("other", None, &[]);
        conflicting.generate_password = Some(String::new());
        conflicting.stdin_text = Some("x".to_string());
        // The CLI layer rejects this combination first; the pure-function layer only guarantees the generated password is non-empty.
        let outcome = apply_set(&mut vault, &conflicting, now()).unwrap();
        assert!(!outcome.entry.field("credential").unwrap().value().is_empty());
    }

    #[test]
    fn set_template_is_overridden_by_assignments() {
        let template: EntryTemplate = serde_json::from_str(
            r#"{"category":"token","title":"CI","tags":["ci"],
                "fields":[{"label":"token","type":"concealed","value":"from-template"},
                          {"label":"scopes","type":"string","value":"read"}]}"#,
        )
        .unwrap();
        let mut plan = set_plan("ci", None, &["token=from-argv"]);
        plan.template = Some(template);

        let mut vault = Vault::default();
        let outcome = apply_set(&mut vault, &plan, now()).unwrap();
        assert_eq!(outcome.entry.category, Category::Token);
        assert_eq!(outcome.entry.title.as_deref(), Some("CI"));
        assert_eq!(outcome.entry.tags, vec!["ci".to_string()]);
        assert_eq!(
            outcome.entry.field("token").map(|f| f.value()),
            Some("from-argv"),
            "argv must win over the template base"
        );
        assert_eq!(
            outcome.entry.field("scopes").map(|f| f.value()),
            Some("read")
        );
    }

    // 5. rm / purge
    #[test]
    fn rm_soft_deletes_then_purges_with_tombstone() {
        let source = entry("openai", Category::Apikey);
        let id = source.id;
        let mut vault = vault_with(vec![source]);
        let t = now();

        let report = apply_rm(&mut vault, &["openai".to_string()], false, t);
        assert!(report.failed.is_empty());
        assert_eq!(report.results[0].action, "deleted");
        assert!(vault.entries[&id].deleted_at.is_some());
        assert_eq!(select_entries(&vault, &list_args(&[], false, None), t).unwrap().len(), 0);
        assert_eq!(select_entries(&vault, &list_args(&[], true, None), t).unwrap().len(), 1);

        // Idempotent: deleting again is not a failure.
        let again = apply_rm(&mut vault, &["openai".to_string()], false, t);
        assert!(again.failed.is_empty());
        assert_eq!(again.results[0].action, "already_deleted");

        // A nonexistent entry → failure, but the report still carries the successful items.
        let third = apply_rm(
            &mut vault,
            &["openai".to_string(), "ghost".to_string()],
            false,
            t,
        );
        assert_eq!(third.results.len(), 1);
        assert_eq!(third.failed.len(), 1);
        let err = third.into_error().unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert!(err.to_string().contains("openai"), "{err}");

        let purged = apply_rm(&mut vault, &["openai".to_string()], true, t);
        assert_eq!(purged.results[0].action, "purged");
        assert!(!vault.entries.contains_key(&id));
        assert!(vault.purged.contains_key(&id), "purge must leave a tombstone");
    }

    // 6. restore
    #[test]
    fn restore_clears_marker_and_rejects_name_conflicts() {
        let mut source = entry("openai", Category::Apikey);
        source.deleted_at = Some(now());
        source.updated_at = now() - Duration::seconds(10);
        let id = source.id;
        let mut vault = vault_with(vec![source]);
        let t = now();

        let report = apply_restore(&mut vault, &[id.to_string()], t);
        assert!(report.failed.is_empty());
        assert_eq!(report.results[0].action, "restored");
        assert!(vault.entries[&id].deleted_at.is_none());
        assert!(vault.entries[&id].updated_at > t - Duration::seconds(1));

        let second = apply_restore(&mut vault, &[id.to_string()], t);
        assert_eq!(second.results[0].action, "already_live");

        // Name collision → usage.
        let mut other = entry("openai", Category::Apikey);
        other.deleted_at = Some(t);
        let other_id = other.id;
        vault.entries.insert(other_id, other);
        let report = apply_restore(&mut vault, &[other_id.to_string()], t);
        assert_eq!(report.failed.len(), 1);
        assert!(matches!(report.into_error().unwrap_err(), Error::Usage(_)));
        assert!(vault.entries[&other_id].deleted_at.is_some());
    }

    // 7. cp / mv
    #[test]
    fn cp_copies_with_new_id_and_mv_renames_in_place() {
        let mut vault = Vault::default();
        let t = now();
        let original = apply_set(
            &mut vault,
            &set_plan("openai", Some(Category::Apikey), &["credential=sk-1"]),
            t,
        )
        .unwrap()
        .entry;
        let original_id = original.id;

        let copy = apply_cp(&mut vault, "openai", "openai-prod", t).unwrap();
        assert_ne!(copy.id, original_id);
        assert_eq!(vault.entries.len(), 2);
        let source_after = &vault.entries[&original_id];
        assert_eq!(source_after.name, "openai");
        assert_eq!(
            source_after.field("credential").map(|f| f.value()),
            Some("sk-1")
        );
        assert_eq!(
            vault.entries[&copy.id]
                .field("credential")
                .map(|f| f.value()),
            Some("sk-1"),
            "copy carries the values"
        );

        assert!(matches!(
            apply_cp(&mut vault, "openai", "openai-prod", t).unwrap_err(),
            Error::Usage(_)
        ));
        assert!(matches!(
            apply_cp(&mut vault, "ghost", "x", t).unwrap_err(),
            Error::NotFound(_)
        ));
        assert!(matches!(
            apply_cp(&mut vault, "openai", "Bad Name", t).unwrap_err(),
            Error::Usage(_)
        ));

        let moved = apply_mv(&mut vault, &copy.id.to_string(), "openai-staging", t).unwrap();
        assert_eq!(moved.id, copy.id, "mv must keep the ID");
        assert_eq!(vault.entries[&copy.id].name, "openai-staging");
        assert_eq!(vault.entries.len(), 2);

        // Renaming onto a taken name → usage; renaming to itself must not false-alarm.
        assert!(matches!(
            apply_mv(&mut vault, "openai-staging", "openai", t).unwrap_err(),
            Error::Usage(_)
        ));
        assert!(apply_mv(&mut vault, "openai-staging", "openai-staging", t).is_ok());
        assert!(matches!(
            apply_mv(&mut vault, "openai-staging", "Bad Name", t).unwrap_err(),
            Error::Usage(_)
        ));
    }

    // 8. list filtering and ordering
    #[test]
    fn list_filters_and_ordering_are_deterministic() {
        let t = now();
        let mut prod = entry("prod-key", Category::Apikey);
        prod.tags = vec!["llm".into(), "prod".into()];
        prod.favorite = true;
        prod.expires_at = Some(t + Duration::days(31));

        let mut dev = entry("dev-key", Category::Login);
        dev.tags = vec!["llm".into()];
        dev.expires_at = Some(t + Duration::days(30));

        let mut soon = entry("soon", Category::Token);
        soon.expires_at = Some(t + Duration::days(3));

        let mut expired = entry("expired", Category::Token);
        expired.expires_at = Some(t - Duration::seconds(1));

        let mut gone = entry("gone", Category::Apikey);
        gone.deleted_at = Some(t);
        gone.tags = vec!["llm".into()];

        let vault = vault_with(vec![dev, prod, soon, expired, gone]);

        let all = select_entries(&vault, &list_args(&[], false, None), t).unwrap();
        let names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["dev-key", "expired", "prod-key", "soon"]);
        assert!(
            !names.contains(&"gone"),
            "soft-deleted entries are hidden by default"
        );

        let with_deleted = select_entries(&vault, &list_args(&[], true, None), t).unwrap();
        assert_eq!(with_deleted.len(), 5);

        // tags are AND semantics.
        let llm_prod = select_entries(&vault, &list_args(&["llm", "prod"], false, None), t).unwrap();
        assert_eq!(llm_prod.len(), 1);
        assert_eq!(llm_prod[0].name, "prod-key");

        // The --expiring boundary: exactly 30 days counts, 31 days does not, already expired does not, no date does not.
        let expiring = select_entries(&vault, &list_args(&[], false, Some("30d")), t).unwrap();
        let names: Vec<&str> = expiring.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["dev-key", "soon"], "boundary must be inclusive");

        let mut favorite = list_args(&[], false, None);
        favorite.favorite = true;
        let favored = select_entries(&vault, &favorite, t).unwrap();
        assert_eq!(favored.len(), 1);
        assert_eq!(favored[0].name, "prod-key");

        let mut category = list_args(&[], false, None);
        category.category = Some(Category::Token);
        let tokens = select_entries(&vault, &category, t).unwrap();
        let names: Vec<&str> = tokens.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["expired", "soon"]);

        assert!(matches!(
            select_entries(&vault, &list_args(&[], false, Some("nonsense")), t).unwrap_err(),
            Error::Usage(_)
        ));
    }

    // 9. conflicts / resolve
    #[test]
    fn conflicts_and_resolve_both_sides() {
        let t = now();
        let mut base = entry("openai", Category::Apikey);
        base.fields = vec![
            Field::new("credential", FieldType::Concealed, "ours-value".into()),
        ];
        let base_id = base.id;
        let created = base.created_at;

        let mut copy = entry("openai.conflict.9f2a", Category::Apikey);
        copy.fields = vec![
            Field::new("credential", FieldType::Concealed, "theirs-value".into()),
            Field::new("org", FieldType::String, "acme".into()),
        ];
        copy.tags = vec!["conflict".into(), "prod".into()];
        let copy_id = copy.id;

        let views = conflict_views(&vault_with(vec![base.clone(), copy.clone()]));
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].original.as_deref(), Some("openai"));
        assert!(views[0].original_exists);

        // --theirs: the content moves over, ID / created_at stay, the copy goes away, the tag is cleared.
        let mut vault = vault_with(vec![base.clone(), copy.clone()]);
        let outcome = apply_resolve(&mut vault, "openai", Side::Theirs, t).unwrap();
        assert_eq!(outcome.removed, vec!["openai.conflict.9f2a".to_string()]);
        let merged = &vault.entries[&base_id];
        assert_eq!(merged.id, base_id);
        assert_eq!(merged.created_at, created);
        assert_eq!(
            merged.field("credential").map(|f| f.value()),
            Some("theirs-value")
        );
        assert_eq!(merged.field("org").map(|f| f.value()), Some("acme"));
        assert_eq!(merged.tags, vec!["prod".to_string()], "conflict tag cleared");
        assert!(!vault.entries.contains_key(&copy_id));
        assert!(vault.purged.contains_key(&copy_id));
        assert!(conflict_views(&vault).is_empty());

        // --ours: the original-name entry keeps its content, the copy goes away.
        let mut vault = vault_with(vec![base.clone(), copy.clone()]);
        apply_resolve(&mut vault, "openai", Side::Ours, t).unwrap();
        let kept = &vault.entries[&base_id];
        assert_eq!(
            kept.field("credential").map(|f| f.value()),
            Some("ours-value")
        );
        assert!(kept.tags.is_empty());
        assert!(!vault.entries.contains_key(&copy_id));

        // The copy's name also locates the original-name entry.
        let mut vault = vault_with(vec![base.clone(), copy.clone()]);
        assert!(apply_resolve(&mut vault, "openai.conflict.9f2a", Side::Ours, t).is_ok());

        // No copy → usage; no such entry → not_found.
        let mut lonely = vault_with(vec![base.clone()]);
        assert!(matches!(
            apply_resolve(&mut lonely, "openai", Side::Ours, t).unwrap_err(),
            Error::Usage(_)
        ));
        assert!(matches!(
            apply_resolve(&mut lonely, "ghost", Side::Ours, t).unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[test]
    fn resolve_needs_a_side() {
        let ctx_side = |ours: bool, theirs: bool| match (ours, theirs) {
            (true, false) => Ok(Side::Ours),
            (false, true) => Ok(Side::Theirs),
            _ => Err::<Side, Error>(Error::usage("resolve needs exactly one of --ours or --theirs")),
        };
        assert_eq!(ctx_side(true, false).unwrap(), Side::Ours);
        assert_eq!(ctx_side(false, true).unwrap(), Side::Theirs);
        assert!(ctx_side(false, false).is_err());
        assert!(ctx_side(true, true).is_err());
    }

    // 10. Plaintext never appears in output
    #[test]
    fn json_output_never_leaks_field_values() {
        let mut e = entry("openai", Category::Apikey);
        e.fields = vec![
            Field::new("credential", FieldType::Concealed, CANARY.into()),
            Field::new("note", FieldType::Notes, CANARY.into()),
            Field::new("url", FieldType::Url, "https://example.test".into()),
        ];
        e.notes = Some(CANARY.to_string());

        let hidden = serde_json::to_string(&entry_view(&e, false)).unwrap();
        assert!(!hidden.contains(CANARY), "concealed value leaked: {hidden}");
        assert!(hidden.contains(REDACTED));
        assert!(hidden.contains("https://example.test"), "plain fields stay visible");
        assert!(hidden.contains("akey://default/openai/credential"));

        // The summary (list) does not even carry field values.
        let summary = serde_json::to_string(&EntrySummary::from_entry(&e)).unwrap();
        assert!(!summary.contains(CANARY));
        assert!(!summary.contains("https://example.test"));
        assert!(summary.contains("\"field_count\":3"));

        // The set --dry-run preview likewise shows only the placeholder.
        let mut vault = Vault::default();
        let plan = set_plan("leaky", Some(Category::Apikey), &[]);
        let outcome = apply_set(&mut vault, &plan, now()).unwrap();
        let mut leaky = outcome.entry;
        leaky.fields = vec![Field::new("credential", FieldType::Concealed, CANARY.into())];
        let preview = serde_json::to_string(&entry_view(&leaky, false)).unwrap();
        assert!(!preview.contains(CANARY), "dry-run preview leaked: {preview}");
        assert!(preview.contains(REDACTED));

        // The escape hatch: plaintext only on an explicit reveal.
        assert!(serde_json::to_string(&entry_view(&e, true)).unwrap().contains(CANARY));
    }

    #[test]
    fn argv_secret_warning_only_fires_for_concealed_fields() {
        let mut e = entry("openai", Category::Apikey);
        e.fields = Category::Apikey
            .builtin_fields()
            .iter()
            .map(|(l, t)| Field::new(l, *t, String::new()))
            .collect();
        let secret = parse_assignment("credential=sk-leak").unwrap();
        let plain = parse_assignment("url=https://example.test").unwrap();
        assert_eq!(
            argv_secret_labels(&e, &[secret.clone(), plain.clone()]),
            vec!["credential".to_string()]
        );
        // An empty value is not a leak.
        let empty = parse_assignment("credential=").unwrap();
        assert!(argv_secret_labels(&e, &[empty]).is_empty());
    }

    // A token is a read-only credential: every write command must be rejected before it touches the vault.
    #[test]
    fn write_commands_are_denied_for_capability_tokens() {
        use crate::cli::{Cli, Command};
        use clap::Parser as _;

        let home = tempfile::tempdir().unwrap();
        let home = home.path().to_str().unwrap().to_string();
        // The token value does not matter: the gate only looks at whether `AKEY_TOKEN`/`--token` is present.
        let ctx_for = |extra: &[&str]| {
            let mut argv = vec!["akey", "--home", home.as_str(), "--token", "tok"];
            argv.extend_from_slice(extra);
            let cli = Cli::parse_from(argv);
            let ctx = Ctx::new(&cli).expect("ctx");
            (cli, ctx)
        };
        let denied = |err: Error| {
            assert!(matches!(err, Error::Denied(_)), "{err:?}");
            assert_eq!(err.exit_code(), 7, "{err:?}");
        };

        let (cli, ctx) = ctx_for(&["set", "x"]);
        let Command::Set(args) = cli.command else {
            panic!("expected set")
        };
        denied(set(&ctx, &args).unwrap_err());

        for command in ["edit", "rm", "restore", "cp", "mv", "resolve"] {
            let operands: &[&str] = if matches!(command, "cp" | "mv") {
                &["x", "y"]
            } else {
                &["x"]
            };
            let mut argv = vec![command];
            argv.extend_from_slice(operands);
            let (cli, ctx) = ctx_for(&argv);
            let err = match cli.command {
                Command::Edit(args) => edit(&ctx, &args).unwrap_err(),
                Command::Rm(args) => rm(&ctx, &args).unwrap_err(),
                Command::Restore(args) => restore(&ctx, &args).unwrap_err(),
                Command::Cp(args) => cp(&ctx, &args).unwrap_err(),
                Command::Mv(args) => mv(&ctx, &args).unwrap_err(),
                Command::Resolve(args) => resolve(&ctx, &args).unwrap_err(),
                other => panic!("unexpected command {other:?}"),
            };
            denied(err);
        }
    }

    #[test]
    fn category_template_lists_builtin_fields_with_empty_values() {
        let value = category_template(Category::SshKey);
        assert_eq!(value["category"], "ssh-key");
        let fields = value["fields"].as_array().expect("fields");
        assert_eq!(fields.len(), Category::SshKey.builtin_fields().len());
        assert_eq!(fields[0]["id"], "private-key");
        assert_eq!(fields[0]["type"], "ssh-key");
        assert_eq!(fields[0]["value"], "");

        for category in ALL_CATEGORIES {
            let value = category_template(category);
            assert_eq!(value["category"], category.as_str());
            if !category.builtin_fields().is_empty() {
                assert!(!value["fields"].as_array().unwrap().is_empty());
            }
        }
        assert_eq!(ALL_CATEGORIES.len(), 7);
    }
}

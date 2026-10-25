//! `get` / `list`: render one entry, or the metadata-only summary of many.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use ulid::Ulid;

use super::json_err;
use crate::audit::{self, Action};
use crate::cli::{GetArgs, ListArgs};
use crate::cmd::{Ctx, parse_duration};
use crate::error::{Error, Result};
use crate::output::REDACTED;
use crate::reference::{Attribute, Reference};
use crate::vault::model::{Category, DEFAULT_VAULT, Entry, Field, FieldType, Reveal, Vault};

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
        if args.reveal {
            Action::Reveal
        } else {
            Action::Read
        },
        Some(&entry.name),
        "ok",
    )?;

    ctx.out.emit(render_entry_human(&view), &view)
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

    audit::record(&ctx.paths, store.identity.name(), Action::Read, None, "ok")?;

    let json_rows = serde_json::to_value(&rows).map_err(json_err)?;
    let data = json!({ "count": rows.len(), "entries": json_rows });
    ctx.out.emit(render_list_human(&rows), &data)
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
pub(super) struct EntryView {
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
pub(super) struct EntrySummary {
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
    pub(super) fn from_entry(entry: &Entry) -> EntrySummary {
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

pub(super) fn entry_view(entry: &Entry, revealed: bool) -> EntryView {
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
        notes: entry.notes.as_ref().map(|n| {
            if revealed {
                n.clone()
            } else {
                REDACTED.to_string()
            }
        }),
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
        let field = entry.field(label).ok_or_else(|| {
            Error::not_found(crate::msg!(
                "entry '{}' has no field '{}'",
                "条目 '{}' 没有字段 '{}'",
                entry.name,
                label
            ))
        })?;
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
    // Labels only. The `--json` keys are the contract and keep their stable names.
    let l = |en: &'static str, zh: &'static str| crate::i18n::m(en, zh);
    let mut lines = vec![
        format!("{}{}", l("name: ", "名称："), view.name),
        format!("{}{}", l("id: ", "ID："), view.id),
        format!("{}{}", l("category: ", "分类："), view.category),
    ];
    if let Some(title) = &view.title {
        lines.push(format!("{}{title}", l("title: ", "标题：")));
    }
    if !view.tags.is_empty() {
        lines.push(format!("{}{}", l("tags: ", "标签："), view.tags.join(", ")));
    }
    lines.push(format!("{}{}", l("favorite: ", "收藏："), view.favorite));
    if let Some(url) = &view.url {
        lines.push(format!("{}{url}", l("url: ", "URL：")));
    }
    if let Some(notes) = &view.notes {
        lines.push(format!("{}{notes}", l("notes: ", "备注：")));
    }
    if let Some(expires) = view.expires_at {
        lines.push(format!("{}{expires}", l("expires_at: ", "过期时间：")));
    }
    if let Some(rotated) = view.rotated_at {
        lines.push(format!("{}{rotated}", l("rotated_at: ", "轮换时间：")));
    }
    if let Some(deleted) = view.deleted_at {
        lines.push(format!("{}{deleted}", l("deleted_at: ", "删除时间：")));
    }
    lines.push(format!(
        "{}{}",
        l("reveal: ", "取明文："),
        view.reveal.as_str()
    ));

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
        return crate::i18n::m("no entries", "没有条目").to_string();
    }
    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let cat_width = rows
        .iter()
        .map(|r| r.category.as_str().len())
        .max()
        .unwrap_or(0);
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
                line.push_str(&format!(
                    "  {}{}",
                    crate::i18n::m("tags:", "标签："),
                    row.tags.join(",")
                ));
            }
            if row.favorite {
                line.push_str(&format!("  {}", crate::i18n::m("favorite", "收藏")));
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
// ─────────────────────────────── Filtering ───────────────────────────────

/// `list` filtering: soft-deleted, tags (AND), category, favorite, expiry window. Results are sorted by name (deterministic).
pub(super) fn select_entries<'a>(
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

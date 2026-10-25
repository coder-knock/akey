//! `import`: build entries from external plaintext (JSON, dotenv, 1Password CSV).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use ulid::Ulid;

use super::{read_stdin, read_text_file};
use crate::audit::{self, Action};
use crate::cli::{ExportFormat, ImportArgs};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::inject::run as inject;
use crate::vault::model::{Category, Entry, Field, FieldType, Vault, is_valid_name, slug};

/// `akey import --format json|dotenv|csv1p`: build entries from external plaintext.
pub fn import(ctx: &Ctx, args: &ImportArgs) -> Result<()> {
    // Tokens are read-only credentials: import (a vault write) is always refused.
    ctx.gate_write()?;

    let store = ctx.store()?;
    let vault = store.load()?;

    let (source, text) = match &args.in_file {
        Some(path) => (
            path.display().to_string(),
            read_text_file(path, &crate::msg!("import file", "导入文件"))?,
        ),
        None => ("stdin".to_string(), read_stdin()?),
    };
    let incoming = match args.encoding {
        ExportFormat::Dotenv => {
            parse_import_dotenv(&import_entry_name(args.in_file.as_deref()), &source, &text)?
        }
        other => parse_import(other, &source, &text)?,
    };
    // Name and ID conflicts are rejected before anything hits disk, so a failure cannot leave a half-written result.
    let plan = plan_import(&vault, incoming, args.merge)?;

    if ctx.dry_run {
        // English pluralises the noun while Chinese does not, so the noun is the localized unit
        // and the counts stay separate arguments in both languages.
        let noun = if plan.creates.len() + plan.merges.len() == 1 {
            crate::msg!("entry", "条目")
        } else {
            crate::msg!("entries", "条目")
        };
        return ctx.out.emit(
            crate::msg!(
                "dry run: would create {} and merge {} {}",
                "试运行：将创建 {} 并合并 {} 个{}",
                plan.creates.len(),
                plan.merges.len(),
                noun
            ),
            &json!({
                "dry_run": true,
                "source": source,
                "creates": plan.creates.iter().map(|e| &e.name).collect::<Vec<_>>(),
                "merges": plan.merges.iter().map(|(_, e)| &e.name).collect::<Vec<_>>(),
            }),
        );
    }

    let report = store.update(|vault| Ok(apply_plan(vault, plan, Utc::now())))?;
    ctx.out.emit(
        crate::msg!(
            "imported {} new and merged {} existing {} ({} field(s) written, {} added)",
            "已导入 {} 条新条目、合并 {} 条已有 {}（写入 {} 个字段，新增 {} 个）",
            report.created,
            report.merged,
            // Chinese has no plural suffix to consume, so the localizable unit is the noun
            // and the placeholder count stays equal in both templates.
            if report.created + report.merged == 1 {
                crate::msg!("entry", "条目")
            } else {
                crate::msg!("entries", "条目")
            },
            report.fields_written,
            report.fields_added
        ),
        &json!({
            "source": source,
            "created": report.created,
            "merged": report.merged,
            "fields_written": report.fields_written,
            "fields_added": report.fields_added,
        }),
    )?;

    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Write,
        Some(&source),
        "ok",
    )?;
    Ok(())
}

/// Parse an import file.
pub(super) fn parse_import(format: ExportFormat, label: &str, text: &str) -> Result<Vec<Entry>> {
    match format {
        ExportFormat::Json => parse_import_json(label, text),
        ExportFormat::Csv1p => parse_import_csv(label, text),
        ExportFormat::Dotenv => Err(Error::usage(crate::msg!(
            "dotenv imports need a name; they are parsed by entry, not here",
            "dotenv 导入需要一个条目名；它们按条目解析，不在这里处理"
        ))),
    }
}

fn parse_import_json(label: &str, text: &str) -> Result<Vec<Entry>> {
    let mut value: Value = serde_json::from_str(text).map_err(|e| {
        Error::usage(crate::msg!(
            "{}: not valid JSON: {}",
            "{}：不是合法的 JSON：{}",
            label,
            e
        ))
    })?;

    if value.is_array() {
        if let Some(items) = value.as_array_mut() {
            for item in items {
                fill_entry_defaults(item);
            }
        }
        return serde_json::from_value(value).map_err(|e| {
            Error::usage(crate::msg!(
                "{}: not a list of entries: {}",
                "{}：不是条目列表：{}",
                label,
                e
            ))
        });
    }

    let has_entries = match value.get_mut("entries").and_then(Value::as_object_mut) {
        Some(entries) => {
            for item in entries.values_mut() {
                fill_entry_defaults(item);
            }
            true
        }
        None => false,
    };
    if has_entries {
        let vault: Vault = serde_json::from_value(value).map_err(|e| {
            Error::usage(crate::msg!(
                "{}: not a vault document: {}",
                "{}：不是金库文档：{}",
                label,
                e
            ))
        })?;
        return Ok(vault.entries.into_values().collect());
    }

    Err(Error::usage(crate::msg!(
        "{}: expected a vault document (`{{\"entries\": …}}`) or a list of entries",
        "{}：应为金库文档（`{{\"entries\": …}}`）或条目列表",
        label
    )))
}

/// Hand-written entry JSON often omits these fields; fill in defaults instead of rejecting it outright.
fn fill_entry_defaults(item: &mut Value) {
    let Some(object) = item.as_object_mut() else {
        return;
    };
    let now = Utc::now().to_rfc3339();
    object
        .entry("id")
        .or_insert_with(|| Value::String(Ulid::generate().to_string()));
    object
        .entry("created_at")
        .or_insert_with(|| Value::String(now.clone()));
    object
        .entry("updated_at")
        .or_insert_with(|| Value::String(now));
    object
        .entry("reveal")
        .or_insert_with(|| Value::String("allow".to_string()));
}

pub(super) fn parse_import_dotenv(name: &str, label: &str, text: &str) -> Result<Vec<Entry>> {
    let pairs = inject::parse_dotenv(label, text)?;
    // A repeated variable takes its last assignment (the usual dotenv semantics), and the keys are sorted for determinism.
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in pairs {
        values.insert(key, value);
    }
    if values.is_empty() {
        return Err(Error::usage(crate::msg!(
            "{}: no variables to import",
            "{}：没有可导入的环境变量",
            label
        )));
    }

    let mut entry = Entry::new(
        Ulid::generate(),
        name.to_string(),
        Category::EnvBundle,
        Utc::now(),
    );
    entry.title = Some(label.to_string());
    for (key, value) in values {
        entry.fields.push(env_field(&key, value));
    }
    Ok(vec![entry])
}

/// Environment variable field: `id` takes the lower-cased variable name so that `env_name(id)`
/// reconstructs the original name (`slug` folds `.` / `-` away, and import-then-inject would no
/// longer line up).
fn env_field(label: &str, value: String) -> Field {
    let mut field = Field::new(label, FieldType::Concealed, value);
    let lower = label.to_ascii_lowercase();
    if lower
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        field.id = lower;
    }
    field
}

/// Derive the name of a dotenv entry from the import file name (`prod.env` → `prod`, `.env` / stdin → `imported-env`).
pub(super) fn import_entry_name(path: Option<&Path>) -> String {
    let stem = path
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let candidate = slug(stem);
    if is_valid_name(&candidate) {
        candidate
    } else {
        "imported-env".to_string()
    }
}

fn parse_import_csv(label: &str, text: &str) -> Result<Vec<Entry>> {
    let rows = parse_csv(text);
    let Some(header) = rows.first() else {
        return Err(Error::usage(crate::msg!(
            "{}: empty CSV",
            "{}：CSV 为空",
            label
        )));
    };
    let column = |want: &str| {
        header
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(want))
    };
    let title_col = column("title").ok_or_else(|| {
        Error::usage(crate::msg!(
            "{}: 1Password CSV needs a Title column",
            "{}：1Password CSV 需要 Title 列",
            label
        ))
    })?;
    let username_col = column("username");
    let password_col = column("password");
    let url_col = column("url");
    let notes_col = column("notes");

    let now = Utc::now();
    let mut entries = Vec::new();
    for (index, row) in rows.iter().enumerate().skip(1) {
        if row.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        let cell = |col: Option<usize>| {
            col.and_then(|col| row.get(col))
                .map(|value| value.trim().to_string())
                .unwrap_or_default()
        };

        let title = cell(Some(title_col));
        let candidate = slug(&title);
        let name = if is_valid_name(&candidate) {
            candidate
        } else {
            format!("imported-{index}")
        };

        let mut entry = Entry::new(Ulid::generate(), name, Category::Login, now);
        if !title.is_empty() {
            entry.title = Some(title);
        }
        let url = cell(url_col);
        if !url.is_empty() {
            entry.url = Some(url);
        }
        let notes = cell(notes_col);
        if !notes.is_empty() {
            entry.notes = Some(notes);
        }
        let username = cell(username_col);
        if !username.is_empty() {
            entry
                .fields
                .push(Field::new("username", FieldType::String, username));
        }
        // The password column creates a field even when empty: downstream references to `password` then have a stable shape.
        entry.fields.push(Field::new(
            "password",
            FieldType::Concealed,
            cell(password_col),
        ));
        entries.push(entry);
    }

    if entries.is_empty() {
        return Err(Error::usage(crate::msg!(
            "{}: no rows to import",
            "{}：没有可导入的行",
            label
        )));
    }
    Ok(entries)
}

/// A minimal RFC 4180 reader: `,`, `\n` and `""` inside a double-quoted field are taken literally.
fn parse_csv(input: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            other => field.push(other),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// The import plan, computed before anything reaches disk: what to create, and what to merge into which entry.
#[derive(Debug, Default)]
pub(super) struct ImportPlan {
    pub(super) creates: Vec<Entry>,
    pub(super) merges: Vec<(Ulid, Entry)>,
}

pub(super) fn plan_import(vault: &Vault, incoming: Vec<Entry>, merge: bool) -> Result<ImportPlan> {
    let mut plan = ImportPlan::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for mut entry in incoming {
        if !is_valid_name(&entry.name) {
            return Err(Error::usage(crate::msg!(
                "imported entry name '{}' is not a valid akey name (lowercase letters, digits, `.`, `_`, `-`)",
                "导入的条目名 '{}' 不是合法的 akey 名称（小写字母、数字以及 `.`、`_`、`-`）",
                entry.name
            )));
        }
        if !seen.insert(entry.name.clone()) {
            return Err(Error::usage(crate::msg!(
                "the import file contains '{}' twice",
                "导入文件中包含 '{}' 两次",
                entry.name
            )));
        }
        match vault.entries.values().find(|e| e.name == entry.name) {
            Some(_) if !merge => {
                return Err(Error::usage(crate::msg!(
                    "entry '{}' already exists; pass --merge to overwrite its fields",
                    "条目 '{}' 已存在；传 --merge 可覆盖其字段",
                    entry.name
                )));
            }
            Some(existing) => {
                entry.id = existing.id;
                plan.merges.push((existing.id, entry));
            }
            None => {
                if vault.entries.contains_key(&entry.id) {
                    // The ID collides with another entry: take a fresh ID, never overwrite someone else's record.
                    entry.id = Ulid::generate();
                }
                plan.creates.push(entry);
            }
        }
    }
    Ok(plan)
}

#[derive(Debug, Default)]
pub(super) struct ImportReport {
    pub(super) created: usize,
    pub(super) merged: usize,
    pub(super) fields_written: usize,
    pub(super) fields_added: usize,
}

pub(super) fn apply_plan(vault: &mut Vault, plan: ImportPlan, now: DateTime<Utc>) -> ImportReport {
    let mut report = ImportReport::default();
    for entry in plan.creates {
        vault.entries.insert(entry.id, entry);
        report.created += 1;
    }
    for (id, incoming) in plan.merges {
        if let Some(target) = vault.entries.get_mut(&id) {
            let (written, added) = merge_fields(target, &incoming, now);
            report.merged += 1;
            report.fields_written += written;
            report.fields_added += added;
        }
    }
    report
}

/// `--merge` semantics: overwrite same-named fields, append new ones; touch only fields and display
/// metadata, not `created_at` / `reveal` / expiry — those are local policy, and an import file
/// should not be able to override them.
fn merge_fields(target: &mut Entry, incoming: &Entry, now: DateTime<Utc>) -> (usize, usize) {
    let (mut written, mut added) = (0, 0);
    for field in &incoming.fields {
        match target.fields.iter_mut().find(|f| f.id == field.id) {
            Some(slot) => {
                *slot = field.clone();
                written += 1;
            }
            None => {
                target.fields.push(field.clone());
                added += 1;
            }
        }
    }
    if incoming.title.is_some() {
        target.title = incoming.title.clone();
    }
    if incoming.url.is_some() {
        target.url = incoming.url.clone();
    }
    if incoming.notes.is_some() {
        target.notes = incoming.notes.clone();
    }
    if !incoming.tags.is_empty() {
        target.tags = incoming.tags.clone();
    }
    target.updated_at = now;
    (written, added)
}

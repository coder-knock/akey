//! `template` and the `--template` input shape.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use ulid::Ulid;

use super::json_err;
use crate::cli::{TemplateArgs, TemplateCommand};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::paths;
use crate::vault::model::{Category, Entry, Field, FieldType, Reveal, slug};

pub(super) const ALL_CATEGORIES: [Category; 8] = [
    Category::Apikey,
    Category::Login,
    Category::Token,
    Category::Database,
    Category::SshKey,
    Category::SecureNote,
    Category::EnvBundle,
    Category::Password,
];

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
                return ctx.out.emit(
                    crate::msg!(
                        "wrote template for {} to {}",
                        "已将 {} 模板写入 {}",
                        category.as_str(),
                        path.display()
                    ),
                    &data,
                );
            }
            let rendered = serde_json::to_string_pretty(&value).map_err(json_err)?;
            ctx.out.emit(rendered, &value)
        }
    }
}
// ─────────────────────────────── Templates ───────────────────────────────

/// The shape of `--template` input: the whole set of **writable** `Entry` fields, every one optional.
/// `value` uses `Value` to accept non-string spellings such as numbers and booleans.
#[derive(Debug, Default, Deserialize)]
pub(super) struct EntryTemplate {
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
    pub(super) fn to_entry(&self, id: Ulid, name: String, now: DateTime<Utc>) -> Entry {
        let mut entry = Entry::new(id, name, self.category.unwrap_or(Category::Apikey), now);
        self.overlay(&mut entry);
        entry
    }

    /// Overlay the template content onto the entry; preserving ID / name / `created_at` is the caller's job.
    /// An empty `fields` array does not overwrite (so an empty template cannot wipe existing fields).
    pub(super) fn overlay(&self, entry: &mut Entry) {
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

pub(super) fn read_template(path: &Path) -> Result<EntryTemplate> {
    // Use std::fs instead of paths::read_file: the latter is for akey's **own** files, and it reads
    // a missing file as "the repo is not initialized, go run akey init" — nonsense for a user-supplied template path.
    let bytes = std::fs::read(path).map_err(|e| {
        Error::usage(crate::msg!(
            "cannot read template {}: {}",
            "无法读取模板 {}：{}",
            path.display(),
            e
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        Error::usage(crate::msg!(
            "template {} is not valid JSON: {}",
            "模板 {} 不是合法的 JSON：{}",
            path.display(),
            e
        ))
    })
}

/// The output of `template get <category>`: a skeleton of the built-in fields with empty values.
pub(super) fn category_template(category: Category) -> Value {
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

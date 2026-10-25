//! `export`: dump the vault as plaintext in one of the portable formats.

use serde_json::json;

use super::write_stdout;
use crate::audit::{self, Action};
use crate::cli::{ExportArgs, ExportFormat};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::inject::run as inject;
use crate::paths::{self, FILE_MODE};
use crate::vault::model::{Entry, Vault};

/// `akey export`: dump the whole vault as plaintext (JSON / dotenv / 1Password CSV).
///
/// A plaintext dump is a destructive operation and requires `--yes`; a scoped token may export
/// only the entries it is authorized for, otherwise `--allow` would be meaningless.
pub fn export(ctx: &Ctx, args: &ExportArgs) -> Result<()> {
    // Block on confirmation before touching the vault: without `--yes` the data should not even be read.
    ctx.confirm(crate::i18n::m("export plaintext", "导出明文"))?;

    let store = ctx.store()?;
    let vault = store.load()?;

    // Export means handing out all the plaintext at once: `AKEY_NO_REVEAL` and `deny_reveal` tokens must not pass either.
    ctx.gate_reveal(&vault, None)?;

    // The reveal=deny of the entry **itself** must apply as well. `gate_reveal(vault, None)` only
    // looks at the global policy; without this block, an entry explicitly marked "never take
    // plaintext" would be written out verbatim by export.
    let denied: Vec<&str> = vault
        .live_entries()
        .filter(|entry| entry.reveal == crate::vault::model::Reveal::Deny)
        .map(|entry| entry.name.as_str())
        .collect();
    if !denied.is_empty() {
        // English pluralises the noun with a suffix, which Chinese cannot carry on the noun it
        // renders; the suffix is therefore the localized unit and the noun moves into each
        // template. The argument order stays (count, noun, names) in both languages.
        let noun = if denied.len() == 1 {
            crate::msg!("y is", "条目")
        } else {
            crate::msg!("ies are", "条目")
        };
        return Err(Error::denied(crate::msg!(
            "{} entr{} marked reveal=deny would be written out in the clear: {}. \
             Flip the policy explicitly with `akey edit <name> --reveal-policy allow` \
             if dumping it is really intended",
            "{} 个{}被标记 reveal=deny，将被明文写出：{}。若确实要导出，请显式用 \
             `akey edit <name> --reveal-policy allow` 翻转策略",
            denied.len(),
            noun,
            denied.join(", ")
        )));
    }

    let scope = ctx.scoped_names(&vault)?;
    let rendered = render_export(&vault, args.encoding, scope.as_deref())?;

    match &args.out_file {
        Some(path) => {
            paths::atomic_write(path, rendered.as_bytes(), FILE_MODE)?;
            ctx.out.emit(
                crate::msg!(
                    "wrote {} byte(s) of plaintext to {}",
                    "已将 {} 字节明文写入 {}",
                    rendered.len(),
                    path.display()
                ),
                &json!({
                    "format": format_name(args.encoding),
                    "out_file": path.display().to_string(),
                    "bytes": rendered.len(),
                }),
            )?;
        }
        None if ctx.out.is_json() => {
            ctx.out.emit(
                "",
                &json!({ "format": format_name(args.encoding), "text": rendered }),
            )?;
        }
        None => write_stdout(rendered.as_bytes())?,
    }

    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Export,
        Some(format_name(args.encoding)),
        "ok",
    )?;
    Ok(())
}

/// Export rendering. `Json` is a whole-vault snapshot (which `import` can read back directly); the other two are flat, per-field forms.
pub(super) fn render_export(
    vault: &Vault,
    format: ExportFormat,
    scope: Option<&[String]>,
) -> Result<String> {
    match format {
        ExportFormat::Json => {
            let restricted = restricted_vault(vault, scope);
            serde_json::to_string_pretty(&restricted)
                .map_err(|e| Error::Io(std::io::Error::other(e)))
        }
        ExportFormat::Dotenv => Ok(export_dotenv(vault, scope)),
        ExportFormat::Csv1p => Ok(export_csv1p(vault, scope)),
    }
}

fn format_name(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Json => "json",
        ExportFormat::Dotenv => "dotenv",
        ExportFormat::Csv1p => "csv1p",
    }
}

/// Only entries inside the scope are exported; everything is visible when no token restricts it.
fn in_scope(entry: &Entry, scope: Option<&[String]>) -> bool {
    scope.is_none_or(|names| names.iter().any(|name| name == &entry.name))
}

fn restricted_vault(vault: &Vault, scope: Option<&[String]>) -> Vault {
    let mut restricted = vault.clone();
    if scope.is_some() {
        restricted.entries.retain(|_, entry| in_scope(entry, scope));
    }
    restricted
}

/// A `NAME=value` line, the name upper-cased and underscored (same origin as the variable names of `run --bundle`).
pub(super) fn export_dotenv(vault: &Vault, scope: Option<&[String]>) -> String {
    let mut rows: Vec<String> = Vec::new();
    for entry in vault.live_entries().filter(|e| in_scope(e, scope)) {
        for field in &entry.fields {
            rows.push(format!(
                "{}_{}={}\n",
                inject::env_name(&entry.name),
                inject::env_name(&field.id),
                dotenv_escape(field.value())
            ));
        }
    }
    // Sorted by variable name: the same vault always exports the same bytes.
    rows.sort();
    rows.concat()
}

const CSV1P_HEADER: &str = "Title,Username,Password,URL,Notes";

/// 1Password CSV: `Title,Username,Password,URL,Notes`, one entry per row.
fn export_csv1p(vault: &Vault, scope: Option<&[String]>) -> String {
    let mut out = String::from(CSV1P_HEADER);
    out.push('\n');
    for entry in vault.live_entries().filter(|e| in_scope(e, scope)) {
        let title = entry.title.clone().unwrap_or_else(|| entry.name.clone());
        let url = entry
            .url
            .clone()
            .or_else(|| entry.field("url").map(|f| f.value().to_string()))
            .unwrap_or_default();
        let notes = entry
            .notes
            .clone()
            .or_else(|| entry.field("notes").map(|f| f.value().to_string()))
            .unwrap_or_default();
        out.push_str(&csv_row(&[
            title,
            field_value(entry, "username"),
            secret_value(entry),
            url,
            notes,
        ]));
    }
    out
}

fn field_value(entry: &Entry, label: &str) -> String {
    entry
        .field(label)
        .map(|f| f.value().to_string())
        .unwrap_or_default()
}

/// The entry's "primary secret" (`env-bundle` has no such concept).
fn secret_value(entry: &Entry) -> String {
    let label = entry.category.default_secret_field();
    if label.is_empty() {
        String::new()
    } else {
        field_value(entry, label)
    }
}

/// dotenv value: double-quoted when it contains whitespace or special characters, escaping `\`, `"`
/// and newlines. The inverse of the way [`inject::parse_dotenv`] reads it.
fn dotenv_escape(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\'));
    if !needs_quotes {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn csv_row(fields: &[String]) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

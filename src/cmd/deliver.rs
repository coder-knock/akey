//! Delivery commands: hand secrets to a child process or a template without going through the caller.
//!
//! This module is where the "plaintext exits" concentrate, so every exit passes the token-scope gate:
//! - `read` / `doc get` take plaintext → `Ctx::gate_reveal` (entry policy + environment switch + token policy)
//! - `run` / `inject` hand plaintext to a child process or a file → `Ctx::authorize_references` / `Ctx::authorize`
//! - `export` dumps the whole vault → `gate_reveal` + only entries inside the scope are exported
//! - `import` / `doc put` write to the vault → `Ctx::gate_write` (tokens are read-only credentials)
//! - `mcp` exposes metadata only, and **never exposes field values**

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, Read, Write};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::audit::{self, Action};
use crate::cli::{
    DocArgs, DocCommand, ExportArgs, ExportFormat, ImportArgs, InjectArgs, ReadArgs, RunArgs,
};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::inject::run as inject;
use crate::paths::{self, FILE_MODE};
use crate::reference::{self, Attribute, Reference};
use crate::vault::model::{
    DEFAULT_VAULT, Category, Entry, Field, FieldType, Vault, is_valid_name, slug,
};

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------

/// `akey read <ref>`: resolve a reference to plaintext and write it to stdout or `--out-file`.
pub fn read(ctx: &Ctx, args: &ReadArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let reference = Reference::parse_in(&args.reference, &env_lookup)?;
    let entry = vault.find(&reference.item).ok();

    if let Err(err) = ctx.gate_reveal(&vault, entry) {
        // A denial must still leave a trace: who tried to take which plaintext, and when.
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Read,
            Some(entry.map_or(reference.item.as_str(), |e| e.name.as_str())),
            "denied",
        )?;
        return Err(err);
    }

    let value = reference::resolve(&vault, &reference, Utc::now())?;
    let payload = if args.no_newline {
        value.to_string()
    } else {
        format!("{}\n", value.as_str())
    };
    let subject = entry.map_or(reference.item.clone(), |e| e.name.clone());

    match &args.out_file {
        // `--dry-run` promises "preview only, nothing on disk", and writing plaintext to a file is
        // exactly what it must stop. This used to write the file anyway, so `akey --dry-run read … -o f`
        // still produced a plaintext file.
        Some(path) if ctx.dry_run => {
            ctx.out.emit(
                crate::msg!(
                    "dry run: would write {} byte(s) of plaintext to {}",
                    "试运行：将把 {} 字节明文写入 {}",
                    payload.len(),
                    path.display()
                ),
                &json!({
                    "action": "read",
                    "reference": reference.to_string(),
                    "out_file": path.display().to_string(),
                    "bytes": payload.len(),
                }),
            )?;
        }
        Some(path) => {
            paths::atomic_write(path, payload.as_bytes(), FILE_MODE)?;
            ctx.out.emit(
                crate::msg!(
                    "wrote {} byte(s) to {}",
                    "已写入 {} 字节到 {}",
                    payload.len(),
                    path.display()
                ),
                &json!({
                    "reference": reference.to_string(),
                    "out_file": path.display().to_string(),
                    "bytes": payload.len(),
                }),
            )?;
        }
        // In JSON mode stdout must be a single JSON document, so the plaintext can only go inside the envelope.
        None if ctx.out.is_json() => {
            ctx.out.emit(
                "",
                &json!({
                    "reference": reference.to_string(),
                    "value": value.as_str(),
                }),
            )?;
        }
        None => write_stdout(payload.as_bytes())?,
    }

    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Read,
        Some(&subject),
        "ok",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// `akey run [--with …] [--bundle …] [--env-file …] -- <cmd>`.
///
/// stdout belongs to the child process: this command emits **no** envelope, or it would pollute the output of the program being run.
pub fn run(ctx: &Ctx, args: &RunArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;

    // Masking is exactly how "run never hands plaintext to the caller" is implemented; turning it off means giving that promise up.
    if args.no_masking && ctx.plaintext_forbidden(&vault)? {
        return Err(Error::denied(crate::msg!(
            "--no-masking would let the child's output reach you in the clear; it is refused \
             while AKEY_NO_REVEAL is set or this token carries --deny-reveal. Keep masking on, \
             or ask an operator to change the policy",
            "--no-masking 会让子进程的输出以明文送达你手中；当 AKEY_NO_REVEAL 已设置或本令牌带有 \
             --deny-reveal 时，这一点会被拒绝。请保持遮蔽，或请运维人员修改策略"
        )));
    }

    // Authorization comes before decryption: a restricted token must not inject entries from outside its scope into a child process.
    let touch = inject::touch(&vault, &args.with, &args.bundle, &args.env_file)?;
    ctx.authorize_references(&vault, &touch.texts)?;
    for item in &touch.items {
        ctx.authorize(&vault, item)?;
    }

    let injection = inject::resolve(&store, &vault, &args.with, &args.bundle, &args.env_file)?;
    let code = inject::execute(&args.command, &injection, !args.no_masking)?;

    let subject = (!touch.subjects.is_empty()).then(|| touch.subjects.join(","));
    let outcome = if code == 0 {
        "ok".to_string()
    } else {
        code.to_string()
    };
    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Inject,
        subject.as_deref(),
        &outcome,
    )?;

    if code != 0 {
        // The child's exit code must become akey's exit code **verbatim**, and `Result` can only
        // express error categories (mapping them to 1/2/3… would pollute the contract). The audit
        // record is already on disk and stdout has nothing left to flush, so exit right here.
        std::process::exit(code);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// inject
// ---------------------------------------------------------------------------

/// `akey inject [-i F] [-o F]`: render the references in a template into plaintext.
pub fn inject(ctx: &Ctx, args: &InjectArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let input = match &args.in_file {
        Some(path) => read_text_file(path, &crate::msg!("template", "模板"))?,
        None => read_stdin()?,
    };

    // The rendered result goes **straight to the caller** (stdout, or a file at `-o` that the caller
    // can then read), so inject is in the same class as `read`: a plaintext channel. Entry policy /
    // AKEY_NO_REVEAL / token --deny-reveal / token scope — all four gates must be passed.
    ctx.gate_references_reveal(&vault, std::slice::from_ref(&input))?;

    let rendered = inject::render_template(&vault, &input)?;
    match &args.out_file {
        // Same as `read`: `--dry-run` must not write plaintext to disk.
        Some(path) if ctx.dry_run => {
            ctx.out.emit(
                crate::msg!(
                    "dry run: would write {} byte(s) of plaintext to {}",
                    "试运行：将把 {} 字节明文写入 {}",
                    rendered.len(),
                    path.display()
                ),
                &json!({
                    "action": "inject",
                    "out_file": path.display().to_string(),
                    "bytes": rendered.len(),
                }),
            )?;
        }
        Some(path) => {
            paths::atomic_write(path, rendered.as_bytes(), FILE_MODE)?;
            ctx.out.emit(
                crate::msg!(
                    "wrote {} byte(s) to {}",
                    "已写入 {} 字节到 {}",
                    rendered.len(),
                    path.display()
                ),
                &json!({
                    "out_file": path.display().to_string(),
                    "bytes": rendered.len(),
                }),
            )?;
        }
        None if ctx.out.is_json() => {
            ctx.out.emit("", &json!({ "text": rendered }))?;
        }
        None => write_stdout(rendered.as_bytes())?,
    }

    let subject = args
        .in_file
        .as_deref()
        .map_or_else(|| "stdin".to_string(), |p| p.display().to_string());
    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Inject,
        Some(&subject),
        "ok",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

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
fn render_export(vault: &Vault, format: ExportFormat, scope: Option<&[String]>) -> Result<String> {
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
fn export_dotenv(vault: &Vault, scope: Option<&[String]>) -> String {
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

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

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
        ExportFormat::Dotenv => parse_import_dotenv(
            &import_entry_name(args.in_file.as_deref()),
            &source,
            &text,
        )?,
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
fn parse_import(format: ExportFormat, label: &str, text: &str) -> Result<Vec<Entry>> {
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
    let mut value: Value = serde_json::from_str(text)
        .map_err(|e| Error::usage(crate::msg!(
            "{}: not valid JSON: {}",
            "{}：不是合法的 JSON：{}",
            label,
            e
        )))?;

    if value.is_array() {
        if let Some(items) = value.as_array_mut() {
            for item in items {
                fill_entry_defaults(item);
            }
        }
        return serde_json::from_value(value)
            .map_err(|e| Error::usage(crate::msg!(
                "{}: not a list of entries: {}",
                "{}：不是条目列表：{}",
                label,
                e
            )));
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
        let vault: Vault = serde_json::from_value(value)
            .map_err(|e| Error::usage(crate::msg!(
                "{}: not a vault document: {}",
                "{}：不是金库文档：{}",
                label,
                e
            )))?;
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

fn parse_import_dotenv(name: &str, label: &str, text: &str) -> Result<Vec<Entry>> {
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
fn import_entry_name(path: Option<&Path>) -> String {
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
    let title_col = column("title")
        .ok_or_else(|| Error::usage(crate::msg!(
            "{}: 1Password CSV needs a Title column",
            "{}：1Password CSV 需要 Title 列",
            label
        )))?;
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
struct ImportPlan {
    creates: Vec<Entry>,
    merges: Vec<(Ulid, Entry)>,
}

fn plan_import(vault: &Vault, incoming: Vec<Entry>, merge: bool) -> Result<ImportPlan> {
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
struct ImportReport {
    created: usize,
    merged: usize,
    fields_written: usize,
    fields_added: usize,
}

fn apply_plan(vault: &mut Vault, plan: ImportPlan, now: DateTime<Utc>) -> ImportReport {
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

// ---------------------------------------------------------------------------
// doc
// ---------------------------------------------------------------------------

/// `akey doc get|put`: arbitrary file attachments (kubeconfig, service-account JSON…).
pub fn doc(ctx: &Ctx, args: &DocArgs) -> Result<()> {
    match &args.command {
        DocCommand::Get {
            reference,
            out_file,
        } => doc_get(ctx, reference, out_file.as_deref()),
        DocCommand::Put { item, file, field } => doc_put(ctx, item, file, field),
    }
}

fn doc_get(ctx: &Ctx, raw: &str, out_file: Option<&Path>) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let reference = Reference::parse_in(raw, &env_lookup)?;
    let entry = vault.find(&reference.item)?;

    // A file field is a secret too: entry policy, environment switch and token policy all still apply.
    ctx.gate_reveal(&vault, Some(entry))?;
    if reference.attribute == Attribute::Value {
        require_attachment_field(entry, &reference)?;
    }

    let encoded = reference::resolve(&vault, &reference, Utc::now())?;
    let bytes = decode_attachment(encoded.as_str())?;

    match out_file {
        Some(path) => {
            paths::atomic_write(path, &bytes, FILE_MODE)?;
            ctx.out.emit(
                crate::msg!(
                    "wrote {} byte(s) to {}",
                    "已写入 {} 字节到 {}",
                    bytes.len(),
                    path.display()
                ),
                &json!({
                    "item": entry.name,
                    "field": reference.field,
                    "out_file": path.display().to_string(),
                    "bytes": bytes.len(),
                }),
            )?;
        }
        // In JSON mode stdout is a single JSON document, so binary can only ride inside the envelope as base64.
        None if ctx.out.is_json() => {
            ctx.out.emit(
                "",
                &json!({
                    "item": entry.name,
                    "field": reference.field,
                    "bytes": bytes.len(),
                    "attachment_base64": encoded.as_str(),
                }),
            )?;
        }
        None => write_stdout(&bytes)?,
    }

    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Read,
        Some(&entry.name),
        "ok",
    )?;
    Ok(())
}

fn doc_put(ctx: &Ctx, item: &str, file: &Path, label: &str) -> Result<()> {
    // Tokens are read-only credentials: write operations are always refused.
    ctx.gate_write()?;
    if label.trim().is_empty() {
        return Err(Error::usage(crate::msg!(
            "--field must not be empty",
            "--field 不能为空"
        )));
    }

    let store = ctx.store()?;
    let vault = store.load()?;
    let entry = vault.find(item)?;

    let bytes = std::fs::read(file).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            crate::msg!("cannot read {}: {}", "无法读取 {}：{}", file.display(), e),
        ))
    })?;
    let encoded = STANDARD.encode(&bytes);
    let id = entry.id;
    let name = entry.name.clone();
    let field_id = slug(label);

    if ctx.dry_run {
        return ctx.out.emit(
            crate::msg!(
                "dry run: would attach {} byte(s) to {}/{}",
                "试运行：将把 {} 字节附加到 {}/{}",
                bytes.len(),
                name,
                field_id
            ),
            &json!({
                "dry_run": true,
                "item": name,
                "field": field_id,
                "bytes": bytes.len(),
            }),
        );
    }

    store.update(|vault| {
        let entry = vault
            .entries
            .get_mut(&id)
            .ok_or_else(|| Error::not_found(crate::msg!(
                "no entry named '{}'",
                "没有名为 '{}' 的条目",
                name
            )))?;
        match entry.field_mut(label) {
            Some(existing) => {
                existing.ty = FieldType::File;
                existing.value = Zeroizing::new(encoded);
            }
            None => entry
                .fields
                .push(Field::new(label, FieldType::File, encoded)),
        }
        Ok(())
    })?;

    ctx.out.emit(
        crate::msg!(
            "attached {} byte(s) to {}/{}",
            "已把 {} 字节附加到 {}/{}",
            bytes.len(),
            name,
            field_id
        ),
        &json!({"item": name, "field": field_id, "bytes": bytes.len()}),
    )?;
    audit::record(
        &ctx.paths,
        store.identity.name(),
        Action::Write,
        Some(&name),
        "ok",
    )?;
    Ok(())
}

/// `doc get` accepts only the `file` field — other fields are secret values and belong to `read`.
fn require_attachment_field<'a>(entry: &'a Entry, reference: &Reference) -> Result<&'a Field> {
    let field = reference::find_field(entry, reference)?;
    if field.ty != FieldType::File {
        return Err(Error::usage(crate::msg!(
            "field '{}' of '{}' is a {}, not a file attachment; use `akey read`",
            "字段 '{}'（条目 '{}'）是 {}，不是文件附件；请改用 `akey read`",
            field.label,
            entry.name,
            field.ty
        )));
    }
    Ok(field)
}

fn decode_attachment(encoded: &str) -> Result<Vec<u8>> {
    let trimmed = encoded.trim();
    STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| {
            Error::corrupt(crate::msg!("attachment is not valid base64", "附件不是合法的 base64"))
        })
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

/// Constants used in MCP messages.
const JSONRPC_VERSION: &str = "2.0";
/// Fallback used when the client does not specify a protocol version.
const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const ERR_PARSE: i64 = -32700;
const ERR_INVALID_REQUEST: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INVALID_PARAMS: i64 = -32602;
const ERR_SERVER: i64 = -32000;

/// `akey mcp`: a JSON-RPC 2.0 service over stdio (**newline-delimited**, not LSP-style Content-Length frames).
///
/// The FR-16 security floor: this channel exposes only entry names, categories, tags and
/// `akey://` references, and **must never return field values** under any circumstances.
pub fn mcp(ctx: &Ctx) -> Result<()> {
    let store = ctx.store()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(e) => {
                // Not even an id is available: per JSON-RPC, reply with a null id.
                write_message(
                    &mut stdout,
                    &error_response(Value::Null, ERR_PARSE, &format!("invalid JSON: {e}")),
                )?;
                continue;
            }
        };

        let response = if message.get("method").and_then(Value::as_str) == Some("tools/call") {
            // Decrypt afresh on every call: MCP is a long-lived process, so do not hold a vault
            // snapshot in hand, and do not let "locked" kill `initialize` along with it.
            match store.load() {
                Ok(vault) => handle_message(Some(&vault), &message),
                Err(err) => message
                    .get("id")
                    .cloned()
                    .map(|id| error_response(id, ERR_SERVER, &err.to_string())),
            }
        } else {
            handle_message(None, &message)
        };

        if let Some(response) = response {
            write_message(&mut stdout, &response)?;
        }
    }
    Ok(())
}

fn write_message(out: &mut impl Write, message: &Value) -> Result<()> {
    serde_json::to_writer(&mut *out, message).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Handle one JSON-RPC message. `None` means this is a notification and must not be answered.
///
/// When `vault` is `None`, only the methods that need a vault fail: `initialize` / `ping` /
/// `tools/list` must still answer on a machine that is uninitialized or locked.
fn handle_message(vault: Option<&Vault>, message: &Value) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(error_response(
            Value::Null,
            ERR_INVALID_REQUEST,
            "request must be a JSON object",
        ));
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return id.map(|id| error_response(id, ERR_INVALID_REQUEST, "request has no method"));
    };
    // A message without an id is a notification: even an unknown method gets no reply (JSON-RPC 2.0 §4.1).
    let respond = |result: Value| id.clone().map(|id| result_response(id, result));

    match method {
        "initialize" => respond(json!({
            "protocolVersion": object
                .get("params")
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL_VERSION),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "akey", "version": env!("CARGO_PKG_VERSION") },
        })),
        "ping" => respond(json!({})),
        "tools/list" => respond(json!({ "tools": tool_definitions() })),
        "tools/call" => handle_tool_call(vault, id, object.get("params")),
        other => id.map(|id| {
            error_response(id, ERR_METHOD_NOT_FOUND, &format!("method '{other}' not found"))
        }),
    }
}

fn handle_tool_call(
    vault: Option<&Vault>,
    id: Option<Value>,
    params: Option<&Value>,
) -> Option<Value> {
    let id = id?;
    let Some(vault) = vault else {
        return Some(error_response(
            id,
            ERR_SERVER,
            "the vault is locked or not initialized; run `akey doctor`",
        ));
    };

    let name = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "akey_list" => Some(result_response(id, tool_text(&list_payload(vault, &arguments)))),
        "akey_get" => {
            let Some(item) = arguments.get("item").and_then(Value::as_str) else {
                return Some(error_response(
                    id,
                    ERR_INVALID_PARAMS,
                    "invalid params: 'item' is required",
                ));
            };
            let payload = match entry_payload(vault, item) {
                Ok(payload) => tool_text(&payload),
                Err(err) => tool_error(&err.to_string()),
            };
            Some(result_response(id, payload))
        }
        other => Some(error_response(
            id,
            ERR_INVALID_PARAMS,
            &format!("unknown tool '{other}'"),
        )),
    }
}

fn result_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": JSONRPC_VERSION, "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// Tool result body: MCP requires `content[].text` to be a string, so the payload is serialized as JSON text.
fn tool_text(payload: &Value) -> Value {
    json!({ "content": [ { "type": "text", "text": payload.to_string() } ] })
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [ { "type": "text", "text": message } ], "isError": true })
}

/// Exposes only the two "name and metadata" tools. Write operations are deliberately absent: see the stance of `Ctx::gate_write`.
fn tool_definitions() -> Value {
    json!([
        {
            "name": "akey_list",
            "description": "List credential entries by name with metadata (category, tags, expiry). \
                            Secret values are never returned; inject them with `akey run`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "category": { "type": "string" },
                },
            },
        },
        {
            "name": "akey_get",
            "description": "Show one entry's fields as labels, types and akey:// references. \
                            Values are never returned; inject them with `akey run`.",
            "inputSchema": {
                "type": "object",
                "properties": { "item": { "type": "string" } },
                "required": ["item"],
            },
        },
    ])
}

fn list_payload(vault: &Vault, arguments: &Value) -> Value {
    let tags: Vec<&str> = arguments
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| tags.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let category = arguments.get("category").and_then(Value::as_str);

    let entries: Vec<Value> = vault
        .live_entries()
        .filter(|entry| {
            tags.iter()
                .all(|want| entry.tags.iter().any(|have| have == want))
        })
        .filter(|entry| {
            category.is_none_or(|want| entry.category.as_str().eq_ignore_ascii_case(want))
        })
        .map(entry_meta)
        .collect();

    json!({ "entries": entries })
}

/// Entry metadata. **No field values**, and no `url` / `notes` either — those can smuggle
/// secrets (a URL query string carrying a token is very common).
fn entry_meta(entry: &Entry) -> Value {
    json!({
        "id": entry.id.to_string(),
        "name": entry.name,
        "category": entry.category.as_str(),
        "title": entry.title,
        "tags": entry.tags,
        "favorite": entry.favorite,
        "expires_at": entry.expires_at.map(|at| at.to_rfc3339()),
        "field_count": entry.fields.len(),
    })
}

/// One entry's metadata plus field references. **Values are never returned**.
fn entry_payload(vault: &Vault, item: &str) -> Result<Value> {
    let entry = vault.find(item)?;
    let fields: Vec<Value> = entry
        .fields
        .iter()
        .map(|field| {
            json!({
                "label": field.label,
                "id": field.id,
                "section": field.section,
                "type": field.ty.as_str(),
                "concealed": field.is_concealed(),
                "reference": field_reference(entry, field),
            })
        })
        .collect();

    Ok(json!({ "entry": entry_meta(entry), "fields": fields }))
}

/// A field's `akey://` reference. When the section contains characters a reference segment
/// forbids (spaces, say), omit it so the reference stays usable at least.
fn field_reference(entry: &Entry, field: &Field) -> String {
    let build = |section: Option<&str>| {
        Reference {
            vault: DEFAULT_VAULT.to_string(),
            item: entry.name.clone(),
            section: section.map(str::to_string),
            field: field.id.clone(),
            attribute: Attribute::Value,
        }
        .to_string()
    };
    if let Some(section) = field.section.as_deref() {
        let candidate = build(Some(section));
        if Reference::parse(&candidate).is_ok() {
            return candidate;
        }
    }
    build(None)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    Ok(raw)
}

fn read_text_file(path: &Path, what: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            crate::msg!(
                "cannot read {} {}: {}",
                "无法读取{} {}：{}",
                what,
                path.display(),
                e
            ),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::config::Config;
    use crate::crypto::token;
    use crate::crypto::DeviceIdentity;
    use crate::paths::Paths;
    use crate::vault::model::Reveal;
    use crate::vault::recipients::{RecipientKind, Recipients};
    use crate::vault::store::Store;
    use clap::Parser as _;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Sentinel values that should only ever exist in the vault and must never show up in any output.
    const SENTINEL: &str = "sk-SENTINEL-DO-NOT-LEAK-9876543210";
    const OTHER_SENTINEL: &str = "pw-OTHER-SENTINEL-1234567890";

    fn ulid(tag: u8) -> Ulid {
        Ulid::from_bytes([tag; 16])
    }

    /// A real, on-disk "device": config + identity + recipients + vault.age. The command layer
    /// reads a real vault, so instead of faking a Store this builds the full fixture.
    struct Fixture {
        dir: TempDir,
        home: PathBuf,
        store: Store,
        vault: Vault,
    }

    fn fixture(tokens: Vec<token::IssuedToken>) -> Fixture {
        let dir = tempfile::tempdir().expect("temporary directory");
        let home = dir.path().join("akey");
        let repo = dir.path().join("repo");
        let paths = Paths::new(home.clone());
        paths.ensure().expect("create home");

        let identity = DeviceIdentity::generate("test-device");
        identity.save(&paths.identity).expect("write the local identity");
        let config = Config {
            repo: repo.clone(),
            remote: None,
            device_name: "test-device".to_string(),
            trusted: std::collections::BTreeMap::from([(identity.pubkey(), Utc::now())]),
            trust_seeded: true,
            created_at: Utc::now(),
        };
        config.save(&paths).expect("write the config");

        let mut recipients = Recipients::default();
        recipients.add(
            &identity.pubkey(),
            "test-device",
            RecipientKind::Device,
            Utc::now(),
        );
        recipients
            .save(&repo.join(crate::vault::store::RECIPIENTS_FILE))
            .expect("write the recipients");

        let now = Utc::now();
        let mut vault = Vault::default();

        let mut openai = Entry::new(ulid(1), "openai".to_string(), Category::Apikey, now);
        openai
            .fields
            .push(Field::new("credential", FieldType::Concealed, SENTINEL.to_string()));
        openai.url = Some("https://platform.openai.com".to_string());
        vault.entries.insert(openai.id, openai);

        let mut other = Entry::new(ulid(2), "other".to_string(), Category::Login, now);
        other.title = Some("Other, Inc.".to_string());
        other.url = Some("https://example.com/login".to_string());
        other
            .fields
            .push(Field::new("username", FieldType::String, "me@example.com".to_string()));
        other.fields.push(Field::new(
            "password",
            FieldType::Concealed,
            OTHER_SENTINEL.to_string(),
        ));
        vault.entries.insert(other.id, other);

        for issued in tokens {
            vault.tokens.insert(issued.meta.id, issued.meta);
        }

        let store = Store {
            paths,
            config,
            identity,
        };
        store.save(&vault).expect("write the vault");
        Fixture {
            dir,
            home,
            store,
            vault,
        }
    }

    /// Build a `Ctx` through the real clap parser (`--home` points at the fixture, never at `$HOME`).
    ///
    /// Only global flags plus a no-argument command are passed: the command function itself is
    /// called directly, and argv exists only to load global state such as `--home` / `--token` /
    /// `--yes` into `Ctx`.
    fn ctx_with(home: &Path, globals: &[&str]) -> Ctx {
        let home = home.to_str().expect("a temporary path should be UTF-8");
        let mut argv: Vec<&str> = vec!["akey", "--home", home];
        argv.extend_from_slice(globals);
        argv.push("whoami");
        let cli = Cli::try_parse_from(argv).expect("cli should parse");
        Ctx::new(&cli).expect("ctx")
    }

    fn issued_token(allow: Option<Vec<String>>) -> token::IssuedToken {
        token::issue("ci", allow, false, None, Utc::now()).expect("issue the token")
    }

    /// Make a child process write an environment variable into a file: proof of whether the child ran at all, and what it received.
    fn sh_write(path: &Path, var: &str) -> Vec<String> {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("/bin/echo -n \"${var}\" > '{}'", path.display()),
        ]
    }

    fn entry_with(name: &str, fields: &[(&str, &str)]) -> Entry {
        let mut entry = Entry::new(Ulid::generate(), name.to_string(), Category::Apikey, Utc::now());
        entry.fields = fields
            .iter()
            .map(|(label, value)| {
                Field::new(label, FieldType::Concealed, (*value).to_string())
            })
            .collect();
        entry
    }

    // ---- read -------------------------------------------------------------

    #[test]
    fn read_writes_the_value_and_audits_without_the_plaintext() {
        let fx = fixture(Vec::new());
        let out = fx.dir.path().join("value.txt");
        let ctx = ctx_with(&fx.home, &[]);

        read(
            &ctx,
            &ReadArgs {
                reference: "akey://openai/credential".to_string(),
                out_file: Some(out.clone()),
                no_newline: false,
            },
        )
        .expect("read should succeed");
        assert_eq!(
            std::fs::read_to_string(&out).expect("read back"),
            format!("{SENTINEL}\n")
        );

        read(
            &ctx,
            &ReadArgs {
                reference: "akey://openai/credential".to_string(),
                out_file: Some(out.clone()),
                no_newline: true,
            },
        )
        .expect("read should succeed");
        assert_eq!(std::fs::read_to_string(&out).expect("read back"), SENTINEL);

        let log = std::fs::read_to_string(&fx.store.paths.audit).expect("audit log");
        assert!(log.contains("\"read\""), "{log}");
        assert!(log.contains("openai"), "{log}");
        assert!(!log.contains(SENTINEL), "the audit log must not contain plaintext: {log}");
    }

    #[test]
    fn read_denies_when_the_entry_forbids_reveal() {
        let fx = fixture(Vec::new());
        let mut vault = fx.vault.clone();
        vault.entries.get_mut(&ulid(1)).expect("openai").reveal = Reveal::Deny;
        fx.store.save(&vault).expect("write the vault");

        let out = fx.dir.path().join("value.txt");
        let ctx = ctx_with(&fx.home, &[]);
        let err = read(
            &ctx,
            &ReadArgs {
                reference: "akey://openai/credential".to_string(),
                out_file: Some(out.clone()),
                no_newline: false,
            },
        )
        .expect_err("reveal=deny must be refused");
        assert_eq!(err.exit_code(), 7);
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!out.exists(), "nothing may be written to disk when denied");

        let log = std::fs::read_to_string(&fx.store.paths.audit).expect("audit log");
        assert!(log.contains("denied"), "{log}");
        assert!(log.contains("openai"), "{log}");
        assert!(!log.contains(SENTINEL), "{log}");
    }

    // ---- export -----------------------------------------------------------

    #[test]
    fn export_requires_yes_before_reading_anything() {
        let fx = fixture(Vec::new());
        let out = fx.dir.path().join("export.env");
        let args = ExportArgs {
            encoding: ExportFormat::Dotenv,
            out_file: Some(out.clone()),
        };

        let err = export(&ctx_with(&fx.home, &[]), &args).expect_err("no --yes");
        assert_eq!(err.exit_code(), 2);
        assert_eq!(err.code(), "usage");
        assert!(err.to_string().contains("--yes"), "{err}");
        assert!(!out.exists(), "nothing may be written to disk without --yes");

        // Only with --yes does it touch the vault: use an uninitialized home to show the gate runs before the read.
        let empty = tempfile::tempdir().expect("temporary directory");
        let err = export(&ctx_with(&empty.path().join("akey"), &["--yes"]), &args)
            .expect_err("not initialized");
        assert_eq!(err.exit_code(), 4, "only after the gate passes does 'not initialized' come up");
    }

    #[test]
    fn export_writes_plaintext_and_honours_the_token_scope() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        // A `--deny-reveal` token: it must not even be able to dump its own entries wholesale.
        let deny = token::issue("deny", None, true, None, Utc::now()).expect("issue the token");
        let deny_plaintext = deny.plaintext.clone();
        let fx = fixture(vec![issued, deny]);

        let all = fx.dir.path().join("all.env");
        export(
            &ctx_with(&fx.home, &["--yes"]),
            &ExportArgs {
                encoding: ExportFormat::Dotenv,
                out_file: Some(all.clone()),
            },
        )
        .expect("export");
        let text = std::fs::read_to_string(&all).expect("read back");
        assert!(
            text.contains(&format!("OPENAI_CREDENTIAL={SENTINEL}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("OTHER_PASSWORD={OTHER_SENTINEL}")),
            "{text}"
        );

        // A scoped token: it only gets the entries it is authorized for.
        let scoped = fx.dir.path().join("scoped.env");
        export(
            &ctx_with(&fx.home, &["--yes", "--token", &plaintext]),
            &ExportArgs {
                encoding: ExportFormat::Dotenv,
                out_file: Some(scoped.clone()),
            },
        )
        .expect("export");
        let text = std::fs::read_to_string(&scoped).expect("read back");
        assert!(text.contains("OTHER_PASSWORD"), "{text}");
        assert!(!text.contains("OPENAI"), "entries outside the scope must not be exported: {text}");
        assert!(!text.contains(SENTINEL), "{text}");

        let export_audit = std::fs::read_to_string(&fx.store.paths.audit).expect("audit");
        assert!(export_audit.contains("\"export\""), "{export_audit}");
        assert!(!export_audit.contains(SENTINEL), "{export_audit}");

        // A `--deny-reveal` token: a whole-vault plaintext dump must be refused, and nothing written to disk.
        let denied = fx.dir.path().join("denied.env");
        let err = export(
            &ctx_with(&fx.home, &["--yes", "--token", &deny_plaintext]),
            &ExportArgs {
                encoding: ExportFormat::Json,
                out_file: Some(denied.clone()),
            },
        )
        .expect_err("a deny_reveal token must not export plaintext");
        assert_eq!(err.exit_code(), 7, "{err}");
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!denied.exists(), "nothing may be written to disk when denied");
    }

    // ---- run: token scope (regression of this fix) --------

    #[test]
    fn a_scoped_token_cannot_inject_an_unauthorized_entry() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        let fx = fixture(vec![issued]);
        let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

        // None of the three forms may bypass it: a reference, `VAR=ITEM`, or a bare `ITEM`.
        for spec in ["X=akey://openai/credential", "X=openai", "openai"] {
            let marker = fx.dir.path().join("leaked.txt");
            let args = RunArgs {
                with: vec![spec.to_string()],
                env_file: Vec::new(),
                bundle: Vec::new(),
                no_masking: false,
                command: sh_write(&marker, "X"),
            };
            let err = run(&ctx, &args).expect_err("a restricted token must not inject entries outside its scope");
            assert_eq!(err.exit_code(), 8, "spec '{spec}': {err}");
            assert!(matches!(err, Error::TokenScope(_)), "spec '{spec}': {err:?}");
            assert!(
                !marker.exists(),
                "spec '{spec}': when authorization fails the child must not run, let alone write out plaintext"
            );
        }
    }

    #[test]
    fn a_scoped_token_cannot_read_scope_through_an_env_file() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        let fx = fixture(vec![issued]);
        let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

        let env_file = fx.dir.path().join("scope.env");
        std::fs::write(&env_file, "X=akey://openai/credential\n").expect("write the env file");
        let marker = fx.dir.path().join("leaked.txt");
        let args = RunArgs {
            with: Vec::new(),
            env_file: vec![env_file],
            bundle: Vec::new(),
            no_masking: false,
            command: sh_write(&marker, "X"),
        };
        let err = run(&ctx, &args).expect_err("a reference in an env file is subject to the scope just the same");
        assert_eq!(err.exit_code(), 8, "{err}");
        assert!(!marker.exists());
    }

    #[test]
    fn a_scoped_token_can_inject_its_own_entries() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        let fx = fixture(vec![issued]);
        let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

        let marker = fx.dir.path().join("ok.txt");
        let args = RunArgs {
            with: vec!["X=akey://other/password".to_string()],
            env_file: Vec::new(),
            bundle: Vec::new(),
            no_masking: false,
            command: sh_write(&marker, "X"),
        };
        run(&ctx, &args).expect("entries inside the scope should be injectable");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("read back the child's output"),
            OTHER_SENTINEL
        );
    }

    // ---- inject -----------------------------------------------------------

    #[test]
    fn a_scoped_token_cannot_render_an_unauthorized_template() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        let fx = fixture(vec![issued]);
        let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

        let template = fx.dir.path().join("tpl.txt");
        let out = fx.dir.path().join("rendered.txt");
        let args = InjectArgs {
            in_file: Some(template.clone()),
            out_file: Some(out.clone()),
        };

        std::fs::write(&template, "key=akey://openai/credential\n").expect("write the template");
        let err = inject(&ctx, &args).expect_err("a restricted token must not render entries outside its scope");
        assert_eq!(err.exit_code(), 8, "{err}");
        assert!(!out.exists(), "nothing may be written to disk when authorization fails");

        std::fs::write(&template, "key=akey://other/password\n").expect("write the template");
        inject(&ctx, &args).expect("references inside the scope should render");
        assert_eq!(
            std::fs::read_to_string(&out).expect("read back"),
            format!("key={OTHER_SENTINEL}\n")
        );
    }

    // ---- doc --------------------------------------------------------------

    #[test]
    fn doc_round_trips_a_file_attachment() {
        let fx = fixture(Vec::new());
        let ctx = ctx_with(&fx.home, &[]);
        let payload: &[u8] = b"\x00kubeconfig\xff binary payload";
        let blob = fx.dir.path().join("kubeconfig");
        std::fs::write(&blob, payload).expect("write the attachment");

        doc(
            &ctx,
            &DocArgs {
                command: DocCommand::Put {
                    item: "openai".to_string(),
                    file: blob,
                    field: "file".to_string(),
                },
            },
        )
        .expect("put");

        let back = fx.dir.path().join("back.bin");
        doc(
            &ctx,
            &DocArgs {
                command: DocCommand::Get {
                    reference: "akey://openai/file".to_string(),
                    out_file: Some(back.clone()),
                },
            },
        )
        .expect("get");
        assert_eq!(std::fs::read(&back).expect("read back"), payload, "must round-trip byte for byte");

        // A non-file field should go through `read`, not doc
        let err = doc(
            &ctx,
            &DocArgs {
                command: DocCommand::Get {
                    reference: "akey://openai/credential".to_string(),
                    out_file: None,
                },
            },
        )
        .expect_err("not a file field");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("akey read"), "{err}");
    }

    #[test]
    fn doc_put_and_import_are_denied_for_capability_tokens() {
        let issued = issued_token(None);
        let plaintext = issued.plaintext.clone();
        let fx = fixture(vec![issued]);
        let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

        let blob = fx.dir.path().join("blob");
        std::fs::write(&blob, b"data").expect("write the file");
        let err = doc(
            &ctx,
            &DocArgs {
                command: DocCommand::Put {
                    item: "openai".to_string(),
                    file: blob,
                    field: "file".to_string(),
                },
            },
        )
        .expect_err("tokens are read-only credentials");
        assert_eq!(err.exit_code(), 7);
        assert!(matches!(err, Error::Denied(_)), "{err:?}");

        let env_file = fx.dir.path().join("in.env");
        std::fs::write(&env_file, "KEY=value\n").expect("write the env file");
        let err = import(
            &ctx,
            &ImportArgs {
                encoding: ExportFormat::Dotenv,
                in_file: Some(env_file),
                merge: false,
            },
        )
        .expect_err("tokens are read-only credentials");
        assert_eq!(err.exit_code(), 7);
    }

    #[test]
    fn attachment_decoding_round_trips_and_rejects_junk() {
        let payload: &[u8] = b"\x00\xff\xfe binary";
        assert_eq!(
            decode_attachment(&STANDARD.encode(payload)).expect("decode"),
            payload
        );

        // The URL-safe variant is accepted too (the two encodings differ on bytes containing `+` / `/`)
        let tricky: &[u8] = &[0xfb, 0xff, 0xfe, 0xfa, 0xff];
        assert_eq!(
            decode_attachment(&URL_SAFE_NO_PAD.encode(tricky)).expect("decode"),
            tricky
        );

        let err = decode_attachment("not base64!!").expect_err("invalid base64");
        assert_eq!(err.exit_code(), 1);
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert!(
            !err.to_string().contains("not base64!!"),
            "the error message must not echo field values: {err}"
        );
    }

    // ---- import -----------------------------------------------------------

    #[test]
    fn import_plan_rejects_duplicates_and_merges_fields() {
        let fx = fixture(Vec::new());

        let err = plan_import(&fx.vault, vec![entry_with("openai", &[("credential", "v")])], false)
            .expect_err("a duplicate name and no --merge");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("--merge"), "{err}");

        let plan = plan_import(
            &fx.vault,
            vec![entry_with(
                "openai",
                &[("credential", "new-value"), ("org", "org-new")],
            )],
            true,
        )
        .expect("the merge plan");
        assert_eq!(plan.merges.len(), 1);
        assert!(plan.creates.is_empty());

        let mut vault = fx.vault.clone();
        let report = apply_plan(&mut vault, plan, Utc::now());
        assert_eq!(
            (
                report.created,
                report.merged,
                report.fields_written,
                report.fields_added
            ),
            (0, 1, 1, 1)
        );
        let openai = vault.find("openai").expect("openai");
        assert_eq!(openai.id, ulid(1), "a merge must keep the original ID");
        assert_eq!(
            openai.field("credential").expect("credential").value(),
            "new-value"
        );
        assert_eq!(openai.field("org").expect("org").value(), "org-new");
        assert_eq!(
            openai.reveal,
            Reveal::Allow,
            "local policy must not be overridden by an import file"
        );

        // A new name → create; the same name twice → usage
        let plan = plan_import(&fx.vault, vec![entry_with("fresh", &[("credential", "v")])], false)
            .expect("the create plan");
        assert_eq!(plan.creates.len(), 1);

        let twice = vec![
            entry_with("dup", &[("a", "1")]),
            entry_with("dup", &[("a", "2")]),
        ];
        let err = plan_import(&fx.vault, twice, true).expect_err("a duplicate name within one file");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("twice"), "{err}");

        let err = plan_import(&fx.vault, vec![entry_with("Bad Name", &[("a", "1")])], false)
            .expect_err("an invalid entry name");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn import_creates_entries_from_a_file_and_is_repeatable_with_merge() {
        let fx = fixture(Vec::new());
        let env_file = fx.dir.path().join("prod.env");
        std::fs::write(&env_file, "AWS_KEY=abc123\n").expect("write the env file");
        let ctx = ctx_with(&fx.home, &[]);

        let args = |merge: bool| ImportArgs {
            encoding: ExportFormat::Dotenv,
            in_file: Some(env_file.clone()),
            merge,
        };
        import(&ctx, &args(false)).expect("import");

        let vault = fx.store.load().expect("reload");
        let entry = vault.find("prod").expect("prod");
        assert_eq!(entry.category, Category::EnvBundle);
        assert_eq!(
            entry.field("aws_key").expect("aws_key").value(),
            "abc123"
        );

        let err = import(&ctx, &args(false)).expect_err("a duplicate name and no --merge");
        assert_eq!(err.exit_code(), 2);

        std::fs::write(&env_file, "AWS_KEY=rotated\n").expect("rewrite the env file");
        import(&ctx, &args(true)).expect("--merge should make the import repeatable");
        let vault = fx.store.load().expect("reload");
        assert_eq!(
            vault.find("prod").expect("prod").field("aws_key").expect("aws_key").value(),
            "rotated"
        );

        let log = std::fs::read_to_string(&fx.store.paths.audit).expect("audit");
        assert!(!log.contains("abc123") && !log.contains("rotated"), "{log}");
    }

    #[test]
    fn import_dotenv_creates_an_env_bundle_that_injects_back() {
        let fx = fixture(Vec::new());
        let imported = parse_import_dotenv(
            "prod",
            ".env",
            "export AWS_KEY=abc123\nDB_URL=\"postgres://u:p@h/db\"\n",
        )
        .expect("parse dotenv");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "prod");
        assert_eq!(imported[0].category, Category::EnvBundle);
        assert_eq!(imported[0].fields.len(), 2, "duplicate and empty variables must both be handled cleanly");

        // import → inject: the variable names must match exactly what the `.env` file said.
        let mut vault = Vault::default();
        vault.entries.insert(imported[0].id, imported[0].clone());
        let injection = inject::resolve(
            &fx.store,
            &vault,
            &[],
            &["prod".to_string()],
            &[],
        )
        .expect("bundle injection");
        let vars: BTreeMap<&str, &str> = injection
            .vars
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(vars["AWS_KEY"], "abc123");
        assert_eq!(vars["DB_URL"], "postgres://u:p@h/db");

        // An empty file → usage, rather than creating an empty entry
        let err = parse_import_dotenv("prod", ".env", "# comment only\n").expect_err("no variables");
        assert_eq!(err.exit_code(), 2);

        assert_eq!(import_entry_name(Some(Path::new("/tmp/prod.env"))), "prod");
        assert_eq!(import_entry_name(Some(Path::new("/tmp/.env"))), "imported-env");
        assert_eq!(import_entry_name(None), "imported-env");
    }

    #[test]
    fn import_json_accepts_our_own_export_and_hand_written_lists() {
        let fx = fixture(Vec::new());
        let text = render_export(&fx.vault, ExportFormat::Json, None).expect("export");
        let entries = parse_import(ExportFormat::Json, "backup.json", &text).expect("parse");
        assert_eq!(entries.len(), 2);
        let openai = entries.iter().find(|e| e.name == "openai").expect("openai");
        assert_eq!(
            openai.field("credential").expect("credential").value(),
            SENTINEL
        );

        // A hand-written list: fill in defaults for an omitted id / timestamps rather than rejecting it
        let bare = r#"[{"name":"solo","category":"apikey","fields":[{"id":"credential","label":"credential","type":"concealed","value":"v"}]}]"#;
        let entries = parse_import(ExportFormat::Json, "bare.json", bare).expect("parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "solo");
        assert_eq!(entries[0].field("credential").expect("credential").value(), "v");

        let err = parse_import(ExportFormat::Json, "x.json", "{\"hello\":1}").expect_err("not recognizable");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("list of entries"), "{err}");
    }

    #[test]
    fn import_csv1p_round_trips_our_own_export() {
        let fx = fixture(Vec::new());
        let text = render_export(&fx.vault, ExportFormat::Csv1p, None).expect("export");
        assert!(text.starts_with("Title,Username,Password,URL,Notes\n"), "{text}");
        assert!(text.contains("\"Other, Inc.\""), "a title containing a comma needs quotes: {text}");

        let entries = parse_import(ExportFormat::Csv1p, "1p.csv", &text).expect("parse");
        let other = entries
            .iter()
            .find(|e| e.title.as_deref() == Some("Other, Inc."))
            .expect("the other entry");
        assert!(is_valid_name(&other.name), "the derived name must be valid: {}", other.name);
        assert_eq!(
            other.field("username").expect("username").value(),
            "me@example.com"
        );
        assert_eq!(
            other.field("password").expect("password").value(),
            OTHER_SENTINEL
        );
        assert_eq!(other.url.as_deref(), Some("https://example.com/login"));

        let err = parse_import(ExportFormat::Csv1p, "x.csv", "Name,Password\nfoo,bar\n")
            .expect_err("a missing Title column");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn export_dotenv_quotes_values_and_round_trips_through_the_env_parser() {
        let now = Utc::now();
        let mut entry = Entry::new(ulid(9), "quoted".to_string(), Category::Apikey, now);
        entry.fields.push(Field::new(
            "credential",
            FieldType::Concealed,
            "has space and \"quotes\"".to_string(),
        ));
        entry
            .fields
            .push(Field::new("plain", FieldType::String, "plain-value".to_string()));
        let mut vault = Vault::default();
        vault.entries.insert(entry.id, entry);

        let text = export_dotenv(&vault, None);
        assert_eq!(
            text,
            "QUOTED_CREDENTIAL=\"has space and \\\"quotes\\\"\"\nQUOTED_PLAIN=plain-value\n"
        );

        // export <-> dotenv parsing must be inverses, or an exported file cannot be fed back to `run --env-file`.
        let values: BTreeMap<String, String> = inject::parse_dotenv("exported", &text)
            .expect("parse the exported dotenv")
            .into_iter()
            .collect();
        assert_eq!(values["QUOTED_CREDENTIAL"], "has space and \"quotes\"");
        assert_eq!(values["QUOTED_PLAIN"], "plain-value");
    }

    // ---- mcp --------------------------------------------------------------

    #[test]
    fn mcp_initialize_ping_and_tools_list() {
        let fx = fixture(Vec::new());
        let vault = &fx.vault;

        let init = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
        )
        .expect("initialize must reply");
        assert_eq!(init["jsonrpc"], "2.0");
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
        assert!(init["result"]["capabilities"]["tools"].is_object());
        assert_eq!(init["result"]["serverInfo"]["name"], "akey");
        assert!(init["result"]["serverInfo"]["version"].is_string());

        // The client gave no version → fall back to the default rather than crashing
        let init = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":2,"method":"initialize"}))
            .expect("initialize must reply");
        assert!(init["result"]["protocolVersion"].is_string());
        assert!(init["result"]["capabilities"]["tools"].is_object());

        // Notifications get no reply
        assert!(
            handle_message(
                Some(vault),
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            )
            .is_none(),
            "a notification must get no reply"
        );

        let pong = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":3,"method":"ping"}))
            .expect("ping must reply");
        assert!(pong["result"].is_object());

        let tools = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}))
            .expect("tools/list must reply");
        let listed = tools["result"]["tools"].as_array().expect("tool array");
        let names: Vec<&str> = listed.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, vec!["akey_list", "akey_get"]);
        for tool in listed {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert!(tool["description"].is_string(), "{tool}");
        }

        // On a locked machine the methods that do not need a vault must answer just the same
        let init = handle_message(None, &json!({"jsonrpc":"2.0","id":5,"method":"initialize"}))
            .expect("initialize does not involve the vault");
        assert!(init["result"]["serverInfo"].is_object());
        let listed = handle_message(None, &json!({"jsonrpc":"2.0","id":6,"method":"tools/list"}))
            .expect("tools/list does not involve the vault");
        assert!(listed["result"]["tools"].is_array());

        // Unknown method → -32601; non-object request → -32600
        let err = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":7,"method":"tools/whatever"}))
            .expect("must reply with an error");
        assert_eq!(err["error"]["code"], -32601);
        let err = handle_message(Some(vault), &json!("nope")).expect("must reply with an error");
        assert_eq!(err["error"]["code"], -32600);
    }

    /// The FR-16 security floor: this channel must not emit field values under any circumstances.
    #[test]
    fn mcp_tools_never_return_field_values() {
        let fx = fixture(Vec::new());
        let vault = &fx.vault;

        let calls = [
            json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"akey_list","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"akey_list","arguments":{"category":"apikey"}}}),
            json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"akey_list","arguments":{"tags":["llm"]}}}),
            json!({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"openai"}}}),
            json!({"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"other"}}}),
            json!({"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"nope"}}}),
        ];
        for call in calls {
            let response = handle_message(Some(vault), &call).expect("must reply");
            let text = response.to_string();
            for leaked in [
                SENTINEL,
                OTHER_SENTINEL,
                "me@example.com",
                // `url` can carry secrets too (a token in a query string), so it is not exposed either
                "platform.openai.com",
                "example.com/login",
            ] {
                assert!(!text.contains(leaked), "MCP leaked {leaked}: {text}");
            }
            assert!(
                response["result"]["content"][0]["text"].is_string(),
                "content[].text must be a string: {response}"
            );
        }

        // But labels, types and references must be there — that is exactly what an agent uses to run `akey run`
        let get = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"openai"}}}),
        )
        .expect("must reply");
        let payload: Value =
            serde_json::from_str(get["result"]["content"][0]["text"].as_str().expect("the text"))
                .expect("the body is JSON");
        assert_eq!(payload["entry"]["name"], "openai");
        assert_eq!(payload["entry"]["category"], "apikey");
        assert_eq!(payload["fields"][0]["label"], "credential");
        assert_eq!(payload["fields"][0]["type"], "concealed");
        assert_eq!(payload["fields"][0]["concealed"], true);
        assert_eq!(
            payload["fields"][0]["reference"],
            "akey://default/openai/credential"
        );
        assert!(
            payload["fields"][0].get("value").is_none(),
            "the field payload must not contain a value: {payload}"
        );

        // A missing entry → a tool-level error (isError), not a JSON-RPC error
        let missing = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"nope"}}}),
        )
        .expect("must reply");
        assert_eq!(missing["result"]["isError"], true);

        // Missing params / unknown tool → -32602; vault unavailable → -32000
        let err = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"akey_get","arguments":{}}}),
        )
        .expect("must reply");
        assert_eq!(err["error"]["code"], -32602);
        let err = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"akey_delete"}}),
        )
        .expect("must reply");
        assert_eq!(err["error"]["code"], -32602);
        let err = handle_message(
            None,
            &json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"akey_list"}}),
        )
        .expect("must reply");
        assert_eq!(err["error"]["code"], -32000);

        // A tool call in notification form gets no reply
        assert!(
            handle_message(
                Some(vault),
                &json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"akey_list"}})
            )
            .is_none()
        );
    }
}

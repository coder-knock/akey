//! 交付类命令：把秘密送进子进程或模板，而不经过调用者。
//!
//! 本模块是"明文出口"的集中地，因此每个出口都要过令牌作用域闸门：
//! - `read` / `doc get` 取明文 → `Ctx::gate_reveal`（条目策略 + 环境开关 + 令牌策略）
//! - `run` / `inject` 把明文交给子进程或文件 → `Ctx::authorize_references` / `Ctx::authorize`
//! - `export` 整批出库 → `gate_reveal` + 只导出作用域内的条目
//! - `import` / `doc put` 写库 → `Ctx::gate_write`（令牌是只读凭据）
//! - `mcp` 只暴露元数据，**永不暴露字段值**

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

/// `akey read <ref>`：把引用解成明文，写到 stdout 或 `--out-file`。
pub fn read(ctx: &Ctx, args: &ReadArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let reference = Reference::parse_in(&args.reference, &env_lookup)?;
    let entry = vault.find(&reference.item).ok();

    if let Err(err) = ctx.gate_reveal(&vault, entry) {
        // 被拒也要留痕：谁在什么时候试过取哪条明文。
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
        // `--dry-run` 承诺"只预览不落盘"，而把明文写成文件正是它该拦下的事。
        // 曾经这里直接写盘，于是 `akey --dry-run read … -o f` 照样产出明文文件。
        Some(path) if ctx.dry_run => {
            ctx.out.emit(
                format!(
                    "dry run: would write {} byte(s) of plaintext to {}",
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
                format!("wrote {} byte(s) to {}", payload.len(), path.display()),
                &json!({
                    "reference": reference.to_string(),
                    "out_file": path.display().to_string(),
                    "bytes": payload.len(),
                }),
            )?;
        }
        // JSON 模式下 stdout 必须是单个 JSON 文档，明文只能进信封。
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

/// `akey run [--with …] [--bundle …] [--env-file …] -- <cmd>`。
///
/// stdout 属于子进程：本命令**不**输出任何信封，否则会污染被运行程序的输出。
pub fn run(ctx: &Ctx, args: &RunArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;

    // 掩蔽正是"run 不把明文交给调用者"这条承诺的实现方式；关掉它等于放弃承诺。
    if args.no_masking && ctx.plaintext_forbidden(&vault)? {
        return Err(Error::denied(
            "--no-masking would let the child's output reach you in the clear; it is refused \
             while AKEY_NO_REVEAL is set or this token carries --deny-reveal. Keep masking on, \
             or ask an operator to change the policy",
        ));
    }

    // 授权先于解密：受限令牌不得把作用域外的条目注入子进程。
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
        // 子进程的退出码必须**原样**成为 akey 的退出码，而 `Result` 只能表达错误类别
        // （映射到 1/2/3… 会污染契约）。审计已落盘、stdout 上没有待刷新的数据，
        // 所以在这里直接退。
        std::process::exit(code);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// inject
// ---------------------------------------------------------------------------

/// `akey inject [-i F] [-o F]`：把模板里的引用渲染成明文。
pub fn inject(ctx: &Ctx, args: &InjectArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let input = match &args.in_file {
        Some(path) => read_text_file(path, "template")?,
        None => read_stdin()?,
    };

    // 渲染结果会**直接交给调用者**（stdout，或 `-o` 指向一个调用者随后能读的文件），
    // 所以 inject 与 `read` 同类，是明文通道。条目策略 / AKEY_NO_REVEAL / 令牌
    // --deny-reveal / 令牌作用域——四道闸门全都要过。
    ctx.gate_references_reveal(&vault, std::slice::from_ref(&input))?;

    let rendered = inject::render_template(&vault, &input)?;
    match &args.out_file {
        // 同 `read`：`--dry-run` 不得把明文写到磁盘。
        Some(path) if ctx.dry_run => {
            ctx.out.emit(
                format!(
                    "dry run: would write {} byte(s) of plaintext to {}",
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
                format!("wrote {} byte(s) to {}", rendered.len(), path.display()),
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

/// `akey export`：整库明文出库（JSON / dotenv / 1Password CSV）。
///
/// 明文出库是破坏性操作，必须 `--yes`；作用域令牌只能导出它被授权的条目，
/// 否则 `--allow` 形同虚设。
pub fn export(ctx: &Ctx, args: &ExportArgs) -> Result<()> {
    // 先挡确认再碰金库：没有 `--yes` 时连数据都不该读。
    ctx.confirm("export plaintext")?;

    let store = ctx.store()?;
    let vault = store.load()?;

    // 导出等于把明文整批交出去：`AKEY_NO_REVEAL` 与 `deny_reveal` 令牌同样不得放行。
    ctx.gate_reveal(&vault, None)?;

    // 条目**自身**的 reveal=deny 也必须生效。`gate_reveal(vault, None)` 只看全局策略，
    // 少了这段，一条被明确标记"永不取明文"的条目会被 export 原样写出去。
    let denied: Vec<&str> = vault
        .live_entries()
        .filter(|entry| entry.reveal == crate::vault::model::Reveal::Deny)
        .map(|entry| entry.name.as_str())
        .collect();
    if !denied.is_empty() {
        return Err(Error::denied(format!(
            "{} entr{} marked reveal=deny would be written out in the clear: {}. \
             Flip the policy explicitly with `akey edit <name> --reveal-policy allow` \
             if dumping it is really intended",
            denied.len(),
            if denied.len() == 1 { "y is" } else { "ies are" },
            denied.join(", ")
        )));
    }

    let scope = ctx.scoped_names(&vault)?;
    let rendered = render_export(&vault, args.encoding, scope.as_deref())?;

    match &args.out_file {
        Some(path) => {
            paths::atomic_write(path, rendered.as_bytes(), FILE_MODE)?;
            ctx.out.emit(
                format!(
                    "wrote {} byte(s) of plaintext to {}",
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

/// 导出渲染。`Json` 是整库快照（可直接再 `import` 回来），另外两种是逐字段的扁平形式。
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

/// 作用域内的条目才导出；没有令牌限制时全部可见。
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

/// `NAME=value` 行，名字用大写下划线（与 `run --bundle` 的变量名同源）。
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
    // 按变量名排序：同一份金库永远导出同样的字节。
    rows.sort();
    rows.concat()
}

const CSV1P_HEADER: &str = "Title,Username,Password,URL,Notes";

/// 1Password CSV：`Title,Username,Password,URL,Notes`，每行一个条目。
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

/// 条目的"主秘密"（`env-bundle` 没有这一概念）。
fn secret_value(entry: &Entry) -> String {
    let label = entry.category.default_secret_field();
    if label.is_empty() {
        String::new()
    } else {
        field_value(entry, label)
    }
}

/// dotenv 值：含空白或特殊字符时双引号包裹，并转义 `\` `"` 与换行。
/// 与 [`inject::parse_dotenv`] 的读法互逆。
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

/// `akey import --format json|dotenv|csv1p`：把外部明文建成条目。
pub fn import(ctx: &Ctx, args: &ImportArgs) -> Result<()> {
    // 令牌是只读凭据：导入（写库）一律拒绝。
    ctx.gate_write()?;

    let store = ctx.store()?;
    let vault = store.load()?;

    let (source, text) = match &args.in_file {
        Some(path) => (path.display().to_string(), read_text_file(path, "import file")?),
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
    // 重名与 ID 冲突在落盘之前就判掉，避免写一半失败。
    let plan = plan_import(&vault, incoming, args.merge)?;

    if ctx.dry_run {
        return ctx.out.emit(
            format!(
                "dry run: would create {} and merge {} entr{}",
                plan.creates.len(),
                plan.merges.len(),
                if plan.creates.len() + plan.merges.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
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
        format!(
            "imported {} new and merged {} existing entr{} ({} field(s) written, {} added)",
            report.created, report.merged, if report.created + report.merged == 1 { "y" } else { "ies" },
            report.fields_written, report.fields_added
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

/// 解析导入文件。
fn parse_import(format: ExportFormat, label: &str, text: &str) -> Result<Vec<Entry>> {
    match format {
        ExportFormat::Json => parse_import_json(label, text),
        ExportFormat::Csv1p => parse_import_csv(label, text),
        ExportFormat::Dotenv => Err(Error::usage(
            "dotenv imports need a name; they are parsed by entry, not here",
        )),
    }
}

fn parse_import_json(label: &str, text: &str) -> Result<Vec<Entry>> {
    let mut value: Value = serde_json::from_str(text)
        .map_err(|e| Error::usage(format!("{label}: not valid JSON: {e}")))?;

    if value.is_array() {
        if let Some(items) = value.as_array_mut() {
            for item in items {
                fill_entry_defaults(item);
            }
        }
        return serde_json::from_value(value)
            .map_err(|e| Error::usage(format!("{label}: not a list of entries: {e}")));
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
            .map_err(|e| Error::usage(format!("{label}: not a vault document: {e}")))?;
        return Ok(vault.entries.into_values().collect());
    }

    Err(Error::usage(format!(
        "{label}: expected a vault document (`{{\"entries\": …}}`) or a list of entries"
    )))
}

/// 手写的条目 JSON 常常省掉这些字段，补上默认值而不是直接拒绝。
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
    // 同名变量取最后一次赋值（dotenv 的常见语义），并按键排序保证确定性。
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in pairs {
        values.insert(key, value);
    }
    if values.is_empty() {
        return Err(Error::usage(format!("{label}: no variables to import")));
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

/// 环境变量字段：`id` 取变量名的小写形式，这样 `env_name(id)` 能还原出原变量名
/// （`slug` 会把 `.` / `-` 折叠掉，导入再注入就对不上了）。
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

/// 从导入文件名派生 dotenv 条目的名字（`prod.env` → `prod`，`.env` / stdin → `imported-env`）。
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
        return Err(Error::usage(format!("{label}: empty CSV")));
    };
    let column = |want: &str| {
        header
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(want))
    };
    let title_col = column("title")
        .ok_or_else(|| Error::usage(format!("{label}: 1Password CSV needs a Title column")))?;
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
        // 密码列即使为空也建字段：下游引用 `password` 时结构稳定。
        entry.fields.push(Field::new(
            "password",
            FieldType::Concealed,
            cell(password_col),
        ));
        entries.push(entry);
    }

    if entries.is_empty() {
        return Err(Error::usage(format!("{label}: no rows to import")));
    }
    Ok(entries)
}

/// 极简 RFC 4180 读法：双引号字段内的 `,` `\n` `""` 都按字面处理。
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

/// 落盘前的导入计划：创建哪些、合并到哪条。
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
            return Err(Error::usage(format!(
                "imported entry name '{}' is not a valid akey name (lowercase letters, digits, `.`, `_`, `-`)",
                entry.name
            )));
        }
        if !seen.insert(entry.name.clone()) {
            return Err(Error::usage(format!(
                "the import file contains '{}' twice",
                entry.name
            )));
        }
        match vault.entries.values().find(|e| e.name == entry.name) {
            Some(_) if !merge => {
                return Err(Error::usage(format!(
                    "entry '{}' already exists; pass --merge to overwrite its fields",
                    entry.name
                )));
            }
            Some(existing) => {
                entry.id = existing.id;
                plan.merges.push((existing.id, entry));
            }
            None => {
                if vault.entries.contains_key(&entry.id) {
                    // ID 撞上另一条条目：换一个新 ID，绝不覆盖别人的记录。
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

/// `--merge` 的语义：覆盖同名字段、追加新字段；只动字段与展示性元数据，
/// 不动 `created_at` / `reveal` / 过期时间——那些是本地策略，不该被导入文件覆盖。
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

/// `akey doc get|put`：任意文件附件（kubeconfig、service-account JSON…）。
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

    // 文件字段也是秘密：条目策略、环境开关、令牌策略一样要过。
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
                format!("wrote {} byte(s) to {}", bytes.len(), path.display()),
                &json!({
                    "item": entry.name,
                    "field": reference.field,
                    "out_file": path.display().to_string(),
                    "bytes": bytes.len(),
                }),
            )?;
        }
        // JSON 模式下 stdout 是单个 JSON 文档，二进制只能 base64 进信封。
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
    // 令牌是只读凭据：写操作一律拒绝。
    ctx.gate_write()?;
    if label.trim().is_empty() {
        return Err(Error::usage("--field must not be empty"));
    }

    let store = ctx.store()?;
    let vault = store.load()?;
    let entry = vault.find(item)?;

    let bytes = std::fs::read(file).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read {}: {e}", file.display()),
        ))
    })?;
    let encoded = STANDARD.encode(&bytes);
    let id = entry.id;
    let name = entry.name.clone();
    let field_id = slug(label);

    if ctx.dry_run {
        return ctx.out.emit(
            format!("dry run: would attach {} byte(s) to {name}/{field_id}", bytes.len()),
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
            .ok_or_else(|| Error::not_found(format!("no entry named '{name}'")))?;
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
        format!("attached {} byte(s) to {name}/{field_id}", bytes.len()),
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

/// `doc get` 只认 `file` 字段——别的字段是秘密值，应该走 `read`。
fn require_attachment_field<'a>(entry: &'a Entry, reference: &Reference) -> Result<&'a Field> {
    let field = reference::find_field(entry, reference)?;
    if field.ty != FieldType::File {
        return Err(Error::usage(format!(
            "field '{}' of '{}' is a {}, not a file attachment; use `akey read`",
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
        .map_err(|_| Error::corrupt("attachment is not valid base64"))
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

/// MCP 消息里用到的常量。
const JSONRPC_VERSION: &str = "2.0";
/// 客户端没指定协议版本时的回落值。
const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const ERR_PARSE: i64 = -32700;
const ERR_INVALID_REQUEST: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INVALID_PARAMS: i64 = -32602;
const ERR_SERVER: i64 = -32000;

/// `akey mcp`：stdio 上的 JSON-RPC 2.0 服务（**换行分隔**，不是 LSP 的 Content-Length 帧）。
///
/// FR-16 的安全底线：这条通路只暴露条目名、分类、标签与 `akey://` 引用，
/// **任何情况下都不得返回字段值**。
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
                // 连 id 都拿不到：按 JSON-RPC 规定用 null id 回错。
                write_message(
                    &mut stdout,
                    &error_response(Value::Null, ERR_PARSE, &format!("invalid JSON: {e}")),
                )?;
                continue;
            }
        };

        let response = if message.get("method").and_then(Value::as_str) == Some("tools/call") {
            // 每次调用现解密：MCP 是长驻进程，别把金库快照攥在手里，
            // 也别让"未解锁"把 `initialize` 一起打死。
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

/// 处理一条 JSON-RPC 消息。返回 `None` 表示这是通知，不应回复。
///
/// `vault` 为 `None` 时只有需要金库的方法失败：`initialize` / `ping` /
/// `tools/list` 在未初始化或未解锁的机器上同样要能应答。
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
    // 没有 id 的消息是通知：即便方法未知也不回复（JSON-RPC 2.0 §4.1）。
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

/// 工具结果正文：MCP 要求 `content[].text` 是字符串，所以载荷序列化成 JSON 文本。
fn tool_text(payload: &Value) -> Value {
    json!({ "content": [ { "type": "text", "text": payload.to_string() } ] })
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [ { "type": "text", "text": message } ], "isError": true })
}

/// 只暴露"名字与元数据"的两个工具。写操作刻意不提供：见 `Ctx::gate_write` 的取向。
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

/// 条目元数据。**不含字段值**，也不含 `url` / `notes`——它们可能夹带秘密
/// （URL 里带 token 的查询串很常见）。
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

/// 单条条目的元数据 + 字段引用。**值一律不返回**。
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

/// 字段的 `akey://` 引用。section 含引用段不允许的字符（空格等）时省略它，
/// 让引用至少是可用的。
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
// 小工具
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
            format!("cannot read {what} {}: {e}", path.display()),
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

    /// 只应出现在金库里、绝不该出现在任何输出里的哨兵值。
    const SENTINEL: &str = "sk-SENTINEL-DO-NOT-LEAK-9876543210";
    const OTHER_SENTINEL: &str = "pw-OTHER-SENTINEL-1234567890";

    fn ulid(tag: u8) -> Ulid {
        Ulid::from_bytes([tag; 16])
    }

    /// 一台真正落盘的"设备"：config + identity + recipients + vault.age。
    /// 命令层要读真金库，所以这里不造假 Store，而是把夹具建全。
    struct Fixture {
        dir: TempDir,
        home: PathBuf,
        store: Store,
        vault: Vault,
    }

    fn fixture(tokens: Vec<token::IssuedToken>) -> Fixture {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path().join("akey");
        let repo = dir.path().join("repo");
        let paths = Paths::new(home.clone());
        paths.ensure().expect("创建 home");

        let identity = DeviceIdentity::generate("test-device");
        identity.save(&paths.identity).expect("写本机身份");
        let config = Config {
            repo: repo.clone(),
            remote: None,
            device_name: "test-device".to_string(),
            created_at: Utc::now(),
        };
        config.save(&paths).expect("写配置");

        let mut recipients = Recipients::default();
        recipients.add(
            &identity.pubkey(),
            "test-device",
            RecipientKind::Device,
            Utc::now(),
        );
        recipients
            .save(&repo.join(crate::vault::store::RECIPIENTS_FILE))
            .expect("写收件人");

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
        store.save(&vault).expect("写金库");
        Fixture {
            dir,
            home,
            store,
            vault,
        }
    }

    /// 用真实的 clap 解析构造 `Ctx`（`--home` 指向夹具，绝不碰 `$HOME`）。
    ///
    /// 只传全局标志 + 一个无参命令：命令函数本身直接调用，argv 只是用来把
    /// `--home` / `--token` / `--yes` 这些全局状态装进 `Ctx`。
    fn ctx_with(home: &Path, globals: &[&str]) -> Ctx {
        let home = home.to_str().expect("临时路径应为 UTF-8");
        let mut argv: Vec<&str> = vec!["akey", "--home", home];
        argv.extend_from_slice(globals);
        argv.push("whoami");
        let cli = Cli::try_parse_from(argv).expect("cli 应能解析");
        Ctx::new(&cli).expect("ctx")
    }

    fn issued_token(allow: Option<Vec<String>>) -> token::IssuedToken {
        token::issue("ci", allow, false, None, Utc::now()).expect("签发令牌")
    }

    /// 让子进程把某个环境变量写进文件：用来证明"子进程到底跑没跑、拿到了什么"。
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
        .expect("read 应成功");
        assert_eq!(
            std::fs::read_to_string(&out).expect("读回"),
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
        .expect("read 应成功");
        assert_eq!(std::fs::read_to_string(&out).expect("读回"), SENTINEL);

        let log = std::fs::read_to_string(&fx.store.paths.audit).expect("审计日志");
        assert!(log.contains("\"read\""), "{log}");
        assert!(log.contains("openai"), "{log}");
        assert!(!log.contains(SENTINEL), "审计不得含明文：{log}");
    }

    #[test]
    fn read_denies_when_the_entry_forbids_reveal() {
        let fx = fixture(Vec::new());
        let mut vault = fx.vault.clone();
        vault.entries.get_mut(&ulid(1)).expect("openai").reveal = Reveal::Deny;
        fx.store.save(&vault).expect("写金库");

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
        .expect_err("reveal=deny 必须拒绝");
        assert_eq!(err.exit_code(), 7);
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!out.exists(), "被拒时不得落盘");

        let log = std::fs::read_to_string(&fx.store.paths.audit).expect("审计日志");
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

        let err = export(&ctx_with(&fx.home, &[]), &args).expect_err("无 --yes");
        assert_eq!(err.exit_code(), 2);
        assert_eq!(err.code(), "usage");
        assert!(err.to_string().contains("--yes"), "{err}");
        assert!(!out.exists(), "没有 --yes 时不得落盘");

        // 加了 --yes 才会去碰金库：用一个没初始化过的 home 证明闸门在读取之前。
        let empty = tempfile::tempdir().expect("临时目录");
        let err = export(&ctx_with(&empty.path().join("akey"), &["--yes"]), &args)
            .expect_err("未初始化");
        assert_eq!(err.exit_code(), 4, "闸门通过后才轮到'没初始化'");
    }

    #[test]
    fn export_writes_plaintext_and_honours_the_token_scope() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        // 一个 `--deny-reveal` 的令牌：它连自己的条目都不该能整批导出。
        let deny = token::issue("deny", None, true, None, Utc::now()).expect("签发令牌");
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
        .expect("导出");
        let text = std::fs::read_to_string(&all).expect("读回");
        assert!(
            text.contains(&format!("OPENAI_CREDENTIAL={SENTINEL}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("OTHER_PASSWORD={OTHER_SENTINEL}")),
            "{text}"
        );

        // 作用域令牌：只能拿到被授权的条目。
        let scoped = fx.dir.path().join("scoped.env");
        export(
            &ctx_with(&fx.home, &["--yes", "--token", &plaintext]),
            &ExportArgs {
                encoding: ExportFormat::Dotenv,
                out_file: Some(scoped.clone()),
            },
        )
        .expect("导出");
        let text = std::fs::read_to_string(&scoped).expect("读回");
        assert!(text.contains("OTHER_PASSWORD"), "{text}");
        assert!(!text.contains("OPENAI"), "作用域外的条目不得导出：{text}");
        assert!(!text.contains(SENTINEL), "{text}");

        let export_audit = std::fs::read_to_string(&fx.store.paths.audit).expect("审计");
        assert!(export_audit.contains("\"export\""), "{export_audit}");
        assert!(!export_audit.contains(SENTINEL), "{export_audit}");

        // `--deny-reveal` 令牌：整库明文出库必须被拒，且不落盘。
        let denied = fx.dir.path().join("denied.env");
        let err = export(
            &ctx_with(&fx.home, &["--yes", "--token", &deny_plaintext]),
            &ExportArgs {
                encoding: ExportFormat::Json,
                out_file: Some(denied.clone()),
            },
        )
        .expect_err("deny_reveal 令牌不得导出明文");
        assert_eq!(err.exit_code(), 7, "{err}");
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!denied.exists(), "被拒时不得落盘");
    }

    // ---- run：令牌作用域（本次修补的回归点） ------------------------------

    #[test]
    fn a_scoped_token_cannot_inject_an_unauthorized_entry() {
        let issued = issued_token(Some(vec!["other".to_string()]));
        let plaintext = issued.plaintext.clone();
        let fx = fixture(vec![issued]);
        let ctx = ctx_with(&fx.home, &["--token", &plaintext]);

        // 三种写法都不能绕过：引用、`VAR=ITEM`、裸 `ITEM`。
        for spec in ["X=akey://openai/credential", "X=openai", "openai"] {
            let marker = fx.dir.path().join("leaked.txt");
            let args = RunArgs {
                with: vec![spec.to_string()],
                env_file: Vec::new(),
                bundle: Vec::new(),
                no_masking: false,
                command: sh_write(&marker, "X"),
            };
            let err = run(&ctx, &args).expect_err("受限令牌不得注入作用域外的条目");
            assert_eq!(err.exit_code(), 8, "spec '{spec}': {err}");
            assert!(matches!(err, Error::TokenScope(_)), "spec '{spec}': {err:?}");
            assert!(
                !marker.exists(),
                "spec '{spec}': 授权失败时子进程不得运行，更不得写出明文"
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
        std::fs::write(&env_file, "X=akey://openai/credential\n").expect("写 env 文件");
        let marker = fx.dir.path().join("leaked.txt");
        let args = RunArgs {
            with: Vec::new(),
            env_file: vec![env_file],
            bundle: Vec::new(),
            no_masking: false,
            command: sh_write(&marker, "X"),
        };
        let err = run(&ctx, &args).expect_err("env-file 里的引用同样受作用域限制");
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
        run(&ctx, &args).expect("作用域内的条目应可注入");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("读回子进程输出"),
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

        std::fs::write(&template, "key=akey://openai/credential\n").expect("写模板");
        let err = inject(&ctx, &args).expect_err("受限令牌不得渲染作用域外的条目");
        assert_eq!(err.exit_code(), 8, "{err}");
        assert!(!out.exists(), "授权失败时不得落盘");

        std::fs::write(&template, "key=akey://other/password\n").expect("写模板");
        inject(&ctx, &args).expect("作用域内的引用应可渲染");
        assert_eq!(
            std::fs::read_to_string(&out).expect("读回"),
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
        std::fs::write(&blob, payload).expect("写附件");

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
        assert_eq!(std::fs::read(&back).expect("读回"), payload, "必须逐字节还原");

        // 非 file 字段该走 `read`，而不是 doc
        let err = doc(
            &ctx,
            &DocArgs {
                command: DocCommand::Get {
                    reference: "akey://openai/credential".to_string(),
                    out_file: None,
                },
            },
        )
        .expect_err("非 file 字段");
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
        std::fs::write(&blob, b"data").expect("写文件");
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
        .expect_err("令牌是只读凭据");
        assert_eq!(err.exit_code(), 7);
        assert!(matches!(err, Error::Denied(_)), "{err:?}");

        let env_file = fx.dir.path().join("in.env");
        std::fs::write(&env_file, "KEY=value\n").expect("写 env 文件");
        let err = import(
            &ctx,
            &ImportArgs {
                encoding: ExportFormat::Dotenv,
                in_file: Some(env_file),
                merge: false,
            },
        )
        .expect_err("令牌是只读凭据");
        assert_eq!(err.exit_code(), 7);
    }

    #[test]
    fn attachment_decoding_round_trips_and_rejects_junk() {
        let payload: &[u8] = b"\x00\xff\xfe binary";
        assert_eq!(
            decode_attachment(&STANDARD.encode(payload)).expect("解码"),
            payload
        );

        // URL-safe 变体也认（两种编码在含 `+` / `/` 的字节上不同）
        let tricky: &[u8] = &[0xfb, 0xff, 0xfe, 0xfa, 0xff];
        assert_eq!(
            decode_attachment(&URL_SAFE_NO_PAD.encode(tricky)).expect("解码"),
            tricky
        );

        let err = decode_attachment("not base64!!").expect_err("非法 base64");
        assert_eq!(err.exit_code(), 1);
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert!(
            !err.to_string().contains("not base64!!"),
            "错误信息不得回显字段值：{err}"
        );
    }

    // ---- import -----------------------------------------------------------

    #[test]
    fn import_plan_rejects_duplicates_and_merges_fields() {
        let fx = fixture(Vec::new());

        let err = plan_import(&fx.vault, vec![entry_with("openai", &[("credential", "v")])], false)
            .expect_err("重名且没有 --merge");
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
        .expect("合并计划");
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
        assert_eq!(openai.id, ulid(1), "合并必须保留原 ID");
        assert_eq!(
            openai.field("credential").expect("credential").value(),
            "new-value"
        );
        assert_eq!(openai.field("org").expect("org").value(), "org-new");
        assert_eq!(
            openai.reveal,
            Reveal::Allow,
            "本地策略不该被导入文件覆盖"
        );

        // 新名字 → 创建；同名两次 → usage
        let plan = plan_import(&fx.vault, vec![entry_with("fresh", &[("credential", "v")])], false)
            .expect("创建计划");
        assert_eq!(plan.creates.len(), 1);

        let twice = vec![
            entry_with("dup", &[("a", "1")]),
            entry_with("dup", &[("a", "2")]),
        ];
        let err = plan_import(&fx.vault, twice, true).expect_err("同一文件里重复名字");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("twice"), "{err}");

        let err = plan_import(&fx.vault, vec![entry_with("Bad Name", &[("a", "1")])], false)
            .expect_err("非法条目名");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn import_creates_entries_from_a_file_and_is_repeatable_with_merge() {
        let fx = fixture(Vec::new());
        let env_file = fx.dir.path().join("prod.env");
        std::fs::write(&env_file, "AWS_KEY=abc123\n").expect("写 env 文件");
        let ctx = ctx_with(&fx.home, &[]);

        let args = |merge: bool| ImportArgs {
            encoding: ExportFormat::Dotenv,
            in_file: Some(env_file.clone()),
            merge,
        };
        import(&ctx, &args(false)).expect("导入");

        let vault = fx.store.load().expect("重新载入");
        let entry = vault.find("prod").expect("prod");
        assert_eq!(entry.category, Category::EnvBundle);
        assert_eq!(
            entry.field("aws_key").expect("aws_key").value(),
            "abc123"
        );

        let err = import(&ctx, &args(false)).expect_err("重名且没有 --merge");
        assert_eq!(err.exit_code(), 2);

        std::fs::write(&env_file, "AWS_KEY=rotated\n").expect("改 env 文件");
        import(&ctx, &args(true)).expect("--merge 应可重复导入");
        let vault = fx.store.load().expect("重新载入");
        assert_eq!(
            vault.find("prod").expect("prod").field("aws_key").expect("aws_key").value(),
            "rotated"
        );

        let log = std::fs::read_to_string(&fx.store.paths.audit).expect("审计");
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
        .expect("解析 dotenv");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "prod");
        assert_eq!(imported[0].category, Category::EnvBundle);
        assert_eq!(imported[0].fields.len(), 2, "重复/空变量都要处理干净");

        // 导入 → 注入：变量名必须与 `.env` 里写的一模一样。
        let mut vault = Vault::default();
        vault.entries.insert(imported[0].id, imported[0].clone());
        let injection = inject::resolve(
            &fx.store,
            &vault,
            &[],
            &["prod".to_string()],
            &[],
        )
        .expect("bundle 注入");
        let vars: BTreeMap<&str, &str> = injection
            .vars
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(vars["AWS_KEY"], "abc123");
        assert_eq!(vars["DB_URL"], "postgres://u:p@h/db");

        // 空文件 → usage，而不是建一条空条目
        let err = parse_import_dotenv("prod", ".env", "# 只有注释\n").expect_err("没有变量");
        assert_eq!(err.exit_code(), 2);

        assert_eq!(import_entry_name(Some(Path::new("/tmp/prod.env"))), "prod");
        assert_eq!(import_entry_name(Some(Path::new("/tmp/.env"))), "imported-env");
        assert_eq!(import_entry_name(None), "imported-env");
    }

    #[test]
    fn import_json_accepts_our_own_export_and_hand_written_lists() {
        let fx = fixture(Vec::new());
        let text = render_export(&fx.vault, ExportFormat::Json, None).expect("导出");
        let entries = parse_import(ExportFormat::Json, "backup.json", &text).expect("解析");
        assert_eq!(entries.len(), 2);
        let openai = entries.iter().find(|e| e.name == "openai").expect("openai");
        assert_eq!(
            openai.field("credential").expect("credential").value(),
            SENTINEL
        );

        // 手写列表：省略 id / 时间戳时补默认值，而不是拒绝
        let bare = r#"[{"name":"solo","category":"apikey","fields":[{"id":"credential","label":"credential","type":"concealed","value":"v"}]}]"#;
        let entries = parse_import(ExportFormat::Json, "bare.json", bare).expect("解析");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "solo");
        assert_eq!(entries[0].field("credential").expect("credential").value(), "v");

        let err = parse_import(ExportFormat::Json, "x.json", "{\"hello\":1}").expect_err("认不出来");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("list of entries"), "{err}");
    }

    #[test]
    fn import_csv1p_round_trips_our_own_export() {
        let fx = fixture(Vec::new());
        let text = render_export(&fx.vault, ExportFormat::Csv1p, None).expect("导出");
        assert!(text.starts_with("Title,Username,Password,URL,Notes\n"), "{text}");
        assert!(text.contains("\"Other, Inc.\""), "含逗号的标题要加引号：{text}");

        let entries = parse_import(ExportFormat::Csv1p, "1p.csv", &text).expect("解析");
        let other = entries
            .iter()
            .find(|e| e.title.as_deref() == Some("Other, Inc."))
            .expect("other 条目");
        assert!(is_valid_name(&other.name), "派生名必须合法：{}", other.name);
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
            .expect_err("缺 Title 列");
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

        // 导出 ↔ dotenv 解析必须互逆，否则导出文件喂不回 `run --env-file`。
        let values: BTreeMap<String, String> = inject::parse_dotenv("exported", &text)
            .expect("解析导出的 dotenv")
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
        .expect("initialize 必须回复");
        assert_eq!(init["jsonrpc"], "2.0");
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
        assert!(init["result"]["capabilities"]["tools"].is_object());
        assert_eq!(init["result"]["serverInfo"]["name"], "akey");
        assert!(init["result"]["serverInfo"]["version"].is_string());

        // 客户端没给版本 → 回默认值，而不是崩
        let init = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":2,"method":"initialize"}))
            .expect("initialize 必须回复");
        assert!(init["result"]["protocolVersion"].is_string());
        assert!(init["result"]["capabilities"]["tools"].is_object());

        // 通知不回复
        assert!(
            handle_message(
                Some(vault),
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            )
            .is_none(),
            "通知不得回复"
        );

        let pong = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":3,"method":"ping"}))
            .expect("ping 必须回复");
        assert!(pong["result"].is_object());

        let tools = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}))
            .expect("tools/list 必须回复");
        let listed = tools["result"]["tools"].as_array().expect("工具数组");
        let names: Vec<&str> = listed.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, vec!["akey_list", "akey_get"]);
        for tool in listed {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert!(tool["description"].is_string(), "{tool}");
        }

        // 未解锁的机器上，不需要金库的方法同样要能应答
        let init = handle_message(None, &json!({"jsonrpc":"2.0","id":5,"method":"initialize"}))
            .expect("initialize 与金库无关");
        assert!(init["result"]["serverInfo"].is_object());
        let listed = handle_message(None, &json!({"jsonrpc":"2.0","id":6,"method":"tools/list"}))
            .expect("tools/list 与金库无关");
        assert!(listed["result"]["tools"].is_array());

        // 未知方法 → -32601；非对象请求 → -32600
        let err = handle_message(Some(vault), &json!({"jsonrpc":"2.0","id":7,"method":"tools/whatever"}))
            .expect("必须回复错误");
        assert_eq!(err["error"]["code"], -32601);
        let err = handle_message(Some(vault), &json!("nope")).expect("必须回复错误");
        assert_eq!(err["error"]["code"], -32600);
    }

    /// FR-16 的安全底线：这条通路在任何情况下都不得吐出字段值。
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
            let response = handle_message(Some(vault), &call).expect("必须回复");
            let text = response.to_string();
            for leaked in [
                SENTINEL,
                OTHER_SENTINEL,
                "me@example.com",
                // `url` 也可能夹带秘密（查询串里的 token），同样不暴露
                "platform.openai.com",
                "example.com/login",
            ] {
                assert!(!text.contains(leaked), "MCP 泄漏了 {leaked}：{text}");
            }
            assert!(
                response["result"]["content"][0]["text"].is_string(),
                "content[].text 必须是字符串：{response}"
            );
        }

        // 但标签、类型与引用必须在——agent 正是靠它去 `akey run`
        let get = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"openai"}}}),
        )
        .expect("必须回复");
        let payload: Value =
            serde_json::from_str(get["result"]["content"][0]["text"].as_str().expect("文本"))
                .expect("正文是 JSON");
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
            "字段载荷里不该有 value：{payload}"
        );

        // 条目不存在 → 工具级错误（isError），不是 JSON-RPC 错误
        let missing = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"akey_get","arguments":{"item":"nope"}}}),
        )
        .expect("必须回复");
        assert_eq!(missing["result"]["isError"], true);

        // 缺参数 / 未知工具 → -32602；金库不可用 → -32000
        let err = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"akey_get","arguments":{}}}),
        )
        .expect("必须回复");
        assert_eq!(err["error"]["code"], -32602);
        let err = handle_message(
            Some(vault),
            &json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"akey_delete"}}),
        )
        .expect("必须回复");
        assert_eq!(err["error"]["code"], -32602);
        let err = handle_message(
            None,
            &json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"akey_list"}}),
        )
        .expect("必须回复");
        assert_eq!(err["error"]["code"], -32000);

        // 通知形式的工具调用不回复
        assert!(
            handle_message(
                Some(vault),
                &json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"akey_list"}})
            )
            .is_none()
        );
    }
}

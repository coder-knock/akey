//! Config-file adapters: inspect and apply the `akey` MCP entry for one harness.
//!
//! Each adapter edits the harness's real serialization format instead of re-emitting the
//! whole file, so comments, key order, and unrelated settings survive an install. The
//! [`McpStyle`] decides how an entry is *shaped*; the [`ConfigFormat`] decides which parser
//! edits it. That split is why adding a harness is usually a registry row rather than a new
//! module.
//!
//! Inspection and planning are deliberately separate:
//!
//! * [`inspect`] is tolerant — a broken file becomes [`EntryStatus::Unreadable`] so
//!   `akey agent status` can report on every harness and still exit 0.
//! * [`plan`] is strict — a broken file aborts the install *before* anything is written, so
//!   a multi-harness install can never be half-applied.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstRootNode};
use serde_json::{Value as JsonValue, json};
use toml_edit::{Array as TomlArray, DocumentMut, Item, Table};
use yaml_edit::path::YamlPath;
use yaml_edit::{Document, YamlNode};

use super::registry::{ConfigFormat, Harness, McpStyle, Scope};
use crate::error::{Error, Result};
use crate::paths::{FILE_MODE, atomic_write};

/// Project files are checked into a repository, so they stay group/world readable.
const PROJECT_FILE_MODE: u32 = 0o644;

/// The MCP server name akey registers.
const SERVER_NAME: &str = "akey";
/// The command line every harness must end up running.
const ARGV: [&str; 2] = [SERVER_NAME, "mcp"];

/// What an existing MCP entry says, normalized across formats.
///
/// Only the fields akey owns are read. `env`, headers, and anything else a user added are
/// ignored when deciding whether the entry is already ours; `--force` replaces the entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EntryView {
    kind: Option<String>,
    argv: Vec<String>,
    enabled: Option<bool>,
    disabled: Option<bool>,
}

impl EntryView {
    fn is_akey(&self) -> bool {
        self.argv.len() == ARGV.len() && self.argv.iter().zip(ARGV).all(|(a, b)| a == b)
    }

    /// Why this entry is not the one akey would install; empty means it matches.
    fn problems(&self, style: McpStyle) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.is_akey() {
            problems.push(if self.argv.is_empty() {
                "has no command".to_string()
            } else {
                format!("runs `{}` instead of `akey mcp`", self.argv.join(" "))
            });
        }

        let expected_kind = match style {
            McpStyle::Claude | McpStyle::Plain => Some("stdio"),
            McpStyle::OpenCode => Some("local"),
            McpStyle::Codex | McpStyle::Hermes => None,
        };
        if let Some(expected) = expected_kind
            && let Some(actual) = self.kind.as_deref()
            && actual != expected
        {
            problems.push(format!("has `type` `{actual}` instead of `{expected}`"));
        }

        if matches!(style, McpStyle::Hermes | McpStyle::OpenCode) && self.enabled == Some(false) {
            problems.push("is disabled (`enabled: false`)".to_string());
        }
        if style == McpStyle::Plain && self.disabled == Some(true) {
            problems.push("is disabled (`disabled: true`)".to_string());
        }

        problems
    }
}

/// The state of the `akey` entry in one harness config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    /// No entry yet (or the file does not exist).
    Missing,
    /// An entry exists and points at `akey mcp`.
    Installed,
    /// An entry exists but is not the one akey owns.
    Conflict { detail: String },
    /// The file exists but cannot be read, parsed, or navigated safely.
    Unreadable { detail: String },
}

/// A read-only look at one harness config.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// The config file that would be read or written.
    pub path: PathBuf,
    /// Whether that file existed when inspected.
    pub exists: bool,
    pub status: EntryStatus,
}

/// What an install would do to one config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Added,
    Replaced,
    Unchanged,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Added => "added",
            Change::Replaced => "replaced",
            Change::Unchanged => "unchanged",
        }
    }
}

/// A planned config edit. Nothing is written until [`apply`] is called.
#[derive(Debug, Clone)]
pub struct Plan {
    pub path: PathBuf,
    pub change: Change,
    /// Bytes to write. Empty when `change` is [`Change::Unchanged`].
    pub contents: Vec<u8>,
    pub mode: u32,
    /// Whether the target file does not exist yet.
    pub creates: bool,
    /// What the conflicting entry said, when this plan replaces one.
    pub replaced_detail: Option<String>,
}

/// A rendered edit, before it is attributed to a path.
type Draft = (Change, Vec<u8>, Option<String>);

/// Inspect one harness config without failing on malformed user data.
pub fn inspect(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<Inspection> {
    let path = config_path(harness, scope, home, cwd)?;
    let exists = path.is_file();
    let status = match std::fs::read_to_string(&path) {
        Ok(text) => inspect_text(harness, &text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => EntryStatus::Missing,
        Err(err) => EntryStatus::Unreadable {
            detail: err.to_string(),
        },
    };
    Ok(Inspection {
        path,
        exists,
        status,
    })
}

/// Plan the edit that installs `akey mcp` into one harness config.
///
/// Returns [`Error::AgentConflict`] when a different entry already owns the `akey` name
/// and `force` is false, and [`Error::Corrupt`] when the existing file cannot be edited
/// safely. Nothing is written until the returned plan is applied.
pub fn plan(harness: &Harness, scope: Scope, home: &Path, cwd: &Path, force: bool) -> Result<Plan> {
    let path = config_path(harness, scope, home, cwd)?;
    let text = read_for_edit(&path)?;

    let draft = match harness.format {
        ConfigFormat::Json => draft_json(harness, &path, text.as_deref(), force)?,
        ConfigFormat::Toml => draft_toml(harness, &path, text.as_deref(), force)?,
        ConfigFormat::Yaml => draft_yaml(harness, &path, text.as_deref(), force)?,
    };

    Ok(Plan {
        path,
        change: draft.0,
        contents: draft.1,
        mode: file_mode(scope),
        creates: text.is_none(),
        replaced_detail: draft.2,
    })
}

/// Write a planned edit atomically. An unchanged plan is a no-op.
pub fn apply(plan: &Plan) -> Result<()> {
    if plan.change == Change::Unchanged {
        return Ok(());
    }
    atomic_write(&plan.path, &plan.contents, plan.mode)
}

// ---------------------------------------------------------------------------
// Removal
// ---------------------------------------------------------------------------

/// What an uninstall would do to one config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveChange {
    /// The `akey` entry is present and would be deleted.
    Removed,
    /// There is nothing to delete (missing file, or no `akey` entry).
    Missing,
}

impl RemoveChange {
    pub fn as_str(self) -> &'static str {
        match self {
            RemoveChange::Removed => "removed",
            RemoveChange::Missing => "missing",
        }
    }
}

/// A planned config removal. Nothing is written until [`apply_remove`] is called.
///
/// A config file is never deleted, even when the removal leaves it empty: it may hold
/// comments, a schema declaration, or settings this adapter does not understand.
#[derive(Debug, Clone)]
pub struct RemovePlan {
    pub path: PathBuf,
    pub change: RemoveChange,
    /// Bytes to write. Empty when `change` is [`RemoveChange::Missing`].
    pub contents: Vec<u8>,
    pub mode: u32,
    /// What the removed entry said, when it was not the one akey installs.
    pub removed_detail: Option<String>,
}

/// A rendered removal, before it is attributed to a path.
type RemoveDraft = (RemoveChange, Vec<u8>, Option<String>);

/// Plan the deletion of the `akey` entry from one harness config.
///
/// Absence is a no-op, not an error: uninstall is idempotent, and a harness may never have
/// been configured. A *different* entry named `akey` requires `force`, exactly like install,
/// so an unrelated server that happens to use the name is not deleted by accident. An
/// unreadable file aborts: deleting from a document akey cannot parse would be guesswork.
pub fn plan_remove(
    harness: &Harness,
    scope: Scope,
    home: &Path,
    cwd: &Path,
    force: bool,
) -> Result<RemovePlan> {
    let path = config_path(harness, scope, home, cwd)?;
    let mode = file_mode(scope);
    let Some(text) = read_for_edit(&path)? else {
        return Ok(RemovePlan::missing(path, mode));
    };
    if text.trim().is_empty() {
        return Ok(RemovePlan::missing(path, mode));
    }

    let draft = match harness.format {
        ConfigFormat::Json => remove_json(harness, &path, &text, force)?,
        ConfigFormat::Toml => remove_toml(harness, &path, &text, force)?,
        ConfigFormat::Yaml => remove_yaml(harness, &path, &text, force)?,
    };

    Ok(RemovePlan {
        path,
        change: draft.0,
        contents: draft.1,
        mode,
        removed_detail: draft.2,
    })
}

/// Write a planned removal atomically. A missing entry is a no-op.
pub fn apply_remove(plan: &RemovePlan) -> Result<()> {
    if plan.change == RemoveChange::Missing {
        return Ok(());
    }
    atomic_write(&plan.path, &plan.contents, plan.mode)
}

/// File mode for a planned write. User configs are private; project configs are committed.
fn file_mode(scope: Scope) -> u32 {
    match scope {
        Scope::User => FILE_MODE,
        Scope::Project => PROJECT_FILE_MODE,
    }
}

/// Read a file for a deliberate edit. A missing file is a new document, not an error.
fn read_for_edit(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::corrupt(format!(
            "cannot read {}: {err}",
            path.display()
        ))),
    }
}

impl RemovePlan {
    fn missing(path: PathBuf, mode: u32) -> Self {
        Self {
            path,
            change: RemoveChange::Missing,
            contents: Vec::new(),
            mode,
            removed_detail: None,
        }
    }
}

fn remove_json(harness: &Harness, path: &Path, text: &str, force: bool) -> Result<RemoveDraft> {
    let root = CstRootNode::parse(text, &ParseOptions::default())
        .map_err(|err| corrupt(path, err.to_string()))?;
    let Some(object) = root.object_value() else {
        return Err(corrupt(path, "the top-level value is not an object"));
    };
    let Some(servers) = object.object_value(harness.key) else {
        if object.get(harness.key).is_some() {
            return Err(corrupt(path, format!("`{}` is not an object", harness.key)));
        }
        return Ok((RemoveChange::Missing, Vec::new(), None));
    };
    let Some(prop) = servers.get(SERVER_NAME) else {
        return Ok((RemoveChange::Missing, Vec::new(), None));
    };
    let view = prop
        .value()
        .and_then(|value| value.to_serde_value())
        .map(|value| json_entry_view(&value))
        .unwrap_or_default();
    let removed_detail = removal_guard(harness, path, classify(harness, view), force)?;

    prop.remove();
    Ok((
        RemoveChange::Removed,
        finish(root.to_string()),
        removed_detail,
    ))
}

fn remove_toml(harness: &Harness, path: &Path, text: &str, force: bool) -> Result<RemoveDraft> {
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|err: toml_edit::TomlError| corrupt(path, err.to_string()))?;
    let Some(item) = doc.as_table().get(harness.key) else {
        return Ok((RemoveChange::Missing, Vec::new(), None));
    };
    let Some(servers) = item.as_table_like() else {
        return Err(corrupt(path, format!("`{}` is not a table", harness.key)));
    };
    let Some(entry) = servers.get(SERVER_NAME) else {
        return Ok((RemoveChange::Missing, Vec::new(), None));
    };
    let removed_detail = removal_guard(
        harness,
        path,
        classify(harness, toml_entry_view(entry)),
        force,
    )?;

    let Some(servers) = doc
        .as_table_mut()
        .get_mut(harness.key)
        .and_then(Item::as_table_like_mut)
    else {
        return Err(corrupt(path, format!("`{}` is not a table", harness.key)));
    };
    servers.remove(SERVER_NAME);
    Ok((
        RemoveChange::Removed,
        finish(doc.to_string()),
        removed_detail,
    ))
}

fn remove_yaml(harness: &Harness, path: &Path, text: &str, force: bool) -> Result<RemoveDraft> {
    let doc = Document::from_str(text).map_err(|err| corrupt(path, err.to_string()))?;
    let Some(servers) = doc.get(harness.key) else {
        return Ok((RemoveChange::Missing, Vec::new(), None));
    };
    let Some(servers) = servers.as_mapping() else {
        return Err(corrupt(path, format!("`{}` is not a mapping", harness.key)));
    };
    let Some(entry) = servers.get(SERVER_NAME) else {
        return Ok((RemoveChange::Missing, Vec::new(), None));
    };
    let removed_detail = removal_guard(
        harness,
        path,
        classify(harness, yaml_entry_view(&entry)),
        force,
    )?;

    doc.try_remove_path(&format!("{}.{SERVER_NAME}", harness.key))
        .map_err(|err| corrupt(path, err.to_string()))?;
    Ok((
        RemoveChange::Removed,
        finish(doc.to_string()),
        removed_detail,
    ))
}

/// Allow a removal, or refuse one that would delete an entry akey does not own.
fn removal_guard(
    harness: &Harness,
    path: &Path,
    status: EntryStatus,
    force: bool,
) -> Result<Option<String>> {
    match status {
        EntryStatus::Installed => Ok(None),
        EntryStatus::Conflict { detail } => {
            if !force {
                return Err(Error::AgentConflict(format!(
                    "{} has a different `akey` MCP entry in {}: {}; \
                     rerun with `--force` to remove it",
                    harness.display,
                    path.display(),
                    detail
                )));
            }
            Ok(Some(detail))
        }
        // `classify` never returns these; a missing entry is handled by the caller and an
        // unreadable one by the parser before this point.
        EntryStatus::Missing => Ok(None),
        EntryStatus::Unreadable { detail } => Err(corrupt(path, detail)),
    }
}

/// A paste-ready fragment showing exactly what a fresh config would receive.
///
/// This is rendered through the same planner used for real installs, so the snippet cannot
/// drift from the bytes akey actually writes.
pub fn snippet(harness: &Harness) -> Result<String> {
    let path = Path::new("<config>");
    let draft = match harness.format {
        ConfigFormat::Json => draft_json(harness, path, None, false)?,
        ConfigFormat::Toml => draft_toml(harness, path, None, false)?,
        ConfigFormat::Yaml => draft_yaml(harness, path, None, false)?,
    };
    Ok(String::from_utf8_lossy(&draft.1).into_owned())
}

fn config_path(harness: &Harness, scope: Scope, home: &Path, cwd: &Path) -> Result<PathBuf> {
    harness.config_path(scope, home, cwd).ok_or_else(|| {
        Error::usage(format!(
            "{} does not support the {} scope",
            harness.display,
            scope.as_str()
        ))
    })
}

fn inspect_text(harness: &Harness, text: &str) -> EntryStatus {
    if text.trim().is_empty() {
        return EntryStatus::Missing;
    }
    match harness.format {
        ConfigFormat::Json => inspect_json(harness, text),
        ConfigFormat::Toml => inspect_toml(harness, text),
        ConfigFormat::Yaml => inspect_yaml(harness, text),
    }
}

// ---------------------------------------------------------------------------
// JSON / JSONC
// ---------------------------------------------------------------------------

fn inspect_json(harness: &Harness, text: &str) -> EntryStatus {
    let root = match CstRootNode::parse(text, &ParseOptions::default()) {
        Ok(root) => root,
        Err(err) => return unreadable(err.to_string()),
    };
    let Some(object) = root.object_value() else {
        return unreadable("the top-level value is not an object");
    };
    let Some(servers) = object.object_value(harness.key) else {
        return if object.get(harness.key).is_some() {
            unreadable(format!("`{}` is not an object", harness.key))
        } else {
            EntryStatus::Missing
        };
    };
    let Some(prop) = servers.get(SERVER_NAME) else {
        return EntryStatus::Missing;
    };
    let Some(value) = prop.value().and_then(|value| value.to_serde_value()) else {
        return unreadable("the `akey` entry has no readable value");
    };
    classify(harness, json_entry_view(&value))
}

fn draft_json(harness: &Harness, path: &Path, text: Option<&str>, force: bool) -> Result<Draft> {
    let existed = text.is_some();
    let source = text.unwrap_or("{}");
    let root = CstRootNode::parse(source, &ParseOptions::default())
        .map_err(|err| corrupt(path, err.to_string()))?;
    let object = root
        .object_value_or_create()
        .ok_or_else(|| corrupt(path, "the top-level value is not an object"))?;

    // A brand-new OpenCode config should declare its schema, exactly like the docs show.
    if !existed && let Some(schema) = harness.schema_url {
        object.append("$schema", CstInputValue::String(schema.to_string()));
    }

    let servers = object
        .object_value_or_create(harness.key)
        .ok_or_else(|| corrupt(path, format!("`{}` is not an object", harness.key)))?;

    // A mid-file parse failure can leave a property with no readable value; treating that
    // as missing would silently overwrite broken user data, so fail instead.
    let status = match servers.get(SERVER_NAME) {
        None => EntryStatus::Missing,
        Some(prop) => {
            let Some(value) = prop.value().and_then(|value| value.to_serde_value()) else {
                return Err(corrupt(path, "the `akey` entry has no readable value"));
            };
            classify_strict(harness, path, json_entry_view(&value))?
        }
    };

    let (change, replaced_detail) = decide(harness, path, status, force)?;
    if change == Change::Unchanged {
        return Ok((change, Vec::new(), replaced_detail));
    }

    let desired = desired_json(harness)?;
    let value = to_cst_input(&desired).expect("desired JSON is always representable in CST");
    match servers.get(SERVER_NAME) {
        Some(prop) => prop.set_value(value),
        None => {
            servers.append(SERVER_NAME, value);
        }
    }

    Ok((change, finish(root.to_string()), replaced_detail))
}

fn json_entry_view(value: &JsonValue) -> EntryView {
    let Some(object) = value.as_object() else {
        return EntryView::default();
    };

    // OpenCode's local servers use `command: ["akey", "mcp"]`; the string-plus-args form is
    // accepted too, because older configs and hand-written entries use it.
    let mut argv = Vec::new();
    match object.get("command") {
        Some(JsonValue::String(command)) => {
            argv.push(command.clone());
            if let Some(args) = object.get("args").and_then(JsonValue::as_array) {
                argv.extend(
                    args.iter()
                        .filter_map(|arg| arg.as_str().map(str::to_string)),
                );
            }
        }
        Some(JsonValue::Array(command)) => {
            argv.extend(
                command
                    .iter()
                    .filter_map(|arg| arg.as_str().map(str::to_string)),
            );
        }
        _ => {}
    }

    EntryView {
        kind: object
            .get("type")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        argv,
        enabled: object.get("enabled").and_then(JsonValue::as_bool),
        disabled: object.get("disabled").and_then(JsonValue::as_bool),
    }
}

fn desired_json(harness: &Harness) -> Result<JsonValue> {
    match harness.style {
        McpStyle::Claude => Ok(json!({
            "type": "stdio",
            "command": "akey",
            "args": ["mcp"],
        })),
        McpStyle::OpenCode => Ok(json!({
            "type": "local",
            "command": ["akey", "mcp"],
            "enabled": true,
        })),
        McpStyle::Plain => Ok(json!({
            "command": "akey",
            "args": ["mcp"],
        })),
        style => Err(adapter_mismatch(harness, style)),
    }
}

fn to_cst_input(value: &JsonValue) -> Option<CstInputValue> {
    match value {
        JsonValue::Null => Some(CstInputValue::Null),
        JsonValue::Bool(flag) => Some(CstInputValue::Bool(*flag)),
        JsonValue::Number(number) => Some(CstInputValue::Number(number.to_string())),
        JsonValue::String(text) => Some(CstInputValue::String(text.clone())),
        JsonValue::Array(items) => items
            .iter()
            .map(to_cst_input)
            .collect::<Option<Vec<_>>>()
            .map(CstInputValue::Array),
        JsonValue::Object(map) => map
            .iter()
            .map(|(key, value)| Some((key.clone(), to_cst_input(value)?)))
            .collect::<Option<Vec<_>>>()
            .map(CstInputValue::Object),
    }
}

// ---------------------------------------------------------------------------
// TOML
// ---------------------------------------------------------------------------

fn inspect_toml(harness: &Harness, text: &str) -> EntryStatus {
    let doc: DocumentMut = match text.parse() {
        Ok(doc) => doc,
        Err(err) => return unreadable(err.to_string()),
    };
    let Some(item) = doc.as_table().get(harness.key) else {
        return EntryStatus::Missing;
    };
    let Some(servers) = item.as_table_like() else {
        return unreadable(format!("`{}` is not a table", harness.key));
    };
    let Some(entry) = servers.get(SERVER_NAME) else {
        return EntryStatus::Missing;
    };
    classify(harness, toml_entry_view(entry))
}

fn draft_toml(harness: &Harness, path: &Path, text: Option<&str>, force: bool) -> Result<Draft> {
    let source = text.unwrap_or("");
    let mut doc: DocumentMut = source
        .parse()
        .map_err(|err: toml_edit::TomlError| corrupt(path, err.to_string()))?;

    let status = match doc.as_table().get(harness.key) {
        None => EntryStatus::Missing,
        Some(item) => {
            let Some(servers) = item.as_table_like() else {
                return Err(corrupt(path, format!("`{}` is not a table", harness.key)));
            };
            match servers.get(SERVER_NAME) {
                None => EntryStatus::Missing,
                Some(entry) => classify_strict(harness, path, toml_entry_view(entry))?,
            }
        }
    };

    let (change, replaced_detail) = decide(harness, path, status, force)?;
    if change == Change::Unchanged {
        return Ok((change, Vec::new(), replaced_detail));
    }

    let servers_item = doc.as_table_mut().entry(harness.key).or_insert_with(|| {
        // The parent exists only to hold `akey`, so let TOML imply it instead of writing an
        // empty `[mcp_servers]` header above the real table.
        let mut servers = Table::new();
        servers.set_implicit(true);
        Item::Table(servers)
    });
    let Some(servers) = servers_item.as_table_like_mut() else {
        return Err(corrupt(path, format!("`{}` is not a table", harness.key)));
    };
    servers.insert(SERVER_NAME, toml_entry());

    Ok((change, finish(doc.to_string()), replaced_detail))
}

fn toml_entry_view(item: &Item) -> EntryView {
    let Some(table) = item.as_table_like() else {
        return EntryView::default();
    };

    let mut argv = table
        .get("command")
        .and_then(Item::as_str)
        .map(|command| vec![command.to_string()])
        .unwrap_or_default();
    if let Some(args) = table.get("args").and_then(Item::as_array) {
        argv.extend(
            args.iter()
                .filter_map(|arg| arg.as_str().map(str::to_string)),
        );
    }

    EntryView {
        kind: table.get("type").and_then(Item::as_str).map(str::to_string),
        argv,
        enabled: table.get("enabled").and_then(Item::as_bool),
        disabled: table.get("disabled").and_then(Item::as_bool),
    }
}

fn toml_entry() -> Item {
    let mut table = Table::new();
    table.insert("command", toml_edit::value(SERVER_NAME));
    let mut args = TomlArray::new();
    args.push(ARGV[1]);
    table.insert("args", toml_edit::value(args));
    Item::Table(table)
}

// ---------------------------------------------------------------------------
// YAML
// ---------------------------------------------------------------------------

fn inspect_yaml(harness: &Harness, text: &str) -> EntryStatus {
    let doc = match Document::from_str(text) {
        Ok(doc) => doc,
        Err(err) => return unreadable(err.to_string()),
    };
    let Some(servers) = doc.get(harness.key) else {
        return EntryStatus::Missing;
    };
    let Some(servers) = servers.as_mapping() else {
        return unreadable(format!("`{}` is not a mapping", harness.key));
    };
    let Some(entry) = servers.get(SERVER_NAME) else {
        return EntryStatus::Missing;
    };
    classify(harness, yaml_entry_view(&entry))
}

fn draft_yaml(harness: &Harness, path: &Path, text: Option<&str>, force: bool) -> Result<Draft> {
    let source = text.unwrap_or("");
    let doc = if source.trim().is_empty() {
        Document::new_mapping()
    } else {
        Document::from_str(source).map_err(|err| corrupt(path, err.to_string()))?
    };

    let status = match doc.get(harness.key) {
        None => EntryStatus::Missing,
        Some(servers) => {
            let Some(servers) = servers.as_mapping() else {
                return Err(corrupt(path, format!("`{}` is not a mapping", harness.key)));
            };
            match servers.get(SERVER_NAME) {
                None => EntryStatus::Missing,
                Some(entry) => classify_strict(harness, path, yaml_entry_view(&entry))?,
            }
        }
    };

    let (change, replaced_detail) = decide(harness, path, status, force)?;
    if change == Change::Unchanged {
        return Ok((change, Vec::new(), replaced_detail));
    }

    let entry_path = format!("{}.{SERVER_NAME}", harness.key);
    if change == Change::Replaced {
        // The entry is known to exist here; a removal failure means the document changed
        // underneath us, so surface it rather than writing a half-merged entry.
        doc.try_remove_path(&entry_path)
            .map_err(|err| corrupt(path, err.to_string()))?;
    }
    let command_path = format!("{entry_path}.command");
    let args_path = format!("{entry_path}.args[0]");
    let enabled_path = format!("{entry_path}.enabled");
    doc.try_set_path(&command_path, ARGV[0])
        .map_err(|err| corrupt(path, err.to_string()))?;
    doc.try_set_path(&args_path, ARGV[1])
        .map_err(|err| corrupt(path, err.to_string()))?;
    doc.try_set_path(&enabled_path, true)
        .map_err(|err| corrupt(path, err.to_string()))?;

    Ok((change, finish(doc.to_string()), replaced_detail))
}

fn yaml_entry_view(node: &YamlNode) -> EntryView {
    let Some(table) = node.as_mapping() else {
        return EntryView::default();
    };

    let command = table.get("command");
    let mut argv = command
        .as_ref()
        .and_then(|node| node.as_scalar().map(|scalar| vec![scalar.as_string()]))
        .unwrap_or_default();
    let args = table.get("args");
    if let Some(args) = args.as_ref().and_then(|node| node.as_sequence()) {
        let mut index = 0;
        while let Some(arg) = args.get(index) {
            if let Some(scalar) = arg.as_scalar() {
                argv.push(scalar.as_string());
            }
            index += 1;
        }
    }

    let kind = table.get("type");
    let enabled = table.get("enabled");
    let disabled = table.get("disabled");
    EntryView {
        kind: kind
            .as_ref()
            .and_then(|node| node.as_scalar())
            .map(|scalar| scalar.as_string()),
        argv,
        enabled: enabled
            .as_ref()
            .and_then(|node| node.as_scalar())
            .and_then(|scalar| scalar.as_bool()),
        disabled: disabled
            .as_ref()
            .and_then(|node| node.as_scalar())
            .and_then(|scalar| scalar.as_bool()),
    }
}

// ---------------------------------------------------------------------------
// Shared decisions and helpers
// ---------------------------------------------------------------------------

fn classify(harness: &Harness, view: EntryView) -> EntryStatus {
    let problems = view.problems(harness.style);
    if problems.is_empty() {
        EntryStatus::Installed
    } else {
        EntryStatus::Conflict {
            detail: format!("`{}` {}", entry_pointer(harness), problems.join("; ")),
        }
    }
}

/// Same classification, but a file whose entry cannot be read safely aborts the plan.
fn classify_strict(harness: &Harness, path: &Path, view: EntryView) -> Result<EntryStatus> {
    if view.argv.is_empty() && view.kind.is_none() {
        return Err(corrupt(
            path,
            format!(
                "the `{}` entry is not a readable server object",
                entry_pointer(harness)
            ),
        ));
    }
    Ok(classify(harness, view))
}

fn entry_pointer(harness: &Harness) -> String {
    format!("{}.{SERVER_NAME}", harness.key)
}

fn decide(
    harness: &Harness,
    path: &Path,
    status: EntryStatus,
    force: bool,
) -> Result<(Change, Option<String>)> {
    match status {
        EntryStatus::Missing => Ok((Change::Added, None)),
        EntryStatus::Installed => Ok((Change::Unchanged, None)),
        EntryStatus::Conflict { detail } => {
            if !force {
                return Err(Error::AgentConflict(format!(
                    "{} already has a different `akey` MCP entry in {}: {}; \
                     rerun with `--force` to replace it",
                    harness.display,
                    path.display(),
                    detail
                )));
            }
            Ok((Change::Replaced, Some(detail)))
        }
        EntryStatus::Unreadable { detail } => Err(corrupt(path, detail)),
    }
}

fn unreadable(detail: impl Into<String>) -> EntryStatus {
    EntryStatus::Unreadable {
        detail: detail.into(),
    }
}

fn corrupt(path: &Path, detail: impl Into<String>) -> Error {
    Error::corrupt(format!("{}: {}", path.display(), detail.into()))
}

fn adapter_mismatch(harness: &Harness, style: McpStyle) -> Error {
    Error::corrupt(format!(
        "internal adapter mismatch: {} uses {:?} entries with a {:?} config",
        harness.id, style, harness.format
    ))
}

/// Normalize a rendered document to exactly one trailing newline.
fn finish(mut rendered: String) -> Vec<u8> {
    while rendered.ends_with('\n') {
        rendered.pop();
    }
    rendered.push('\n');
    rendered.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::registry;

    fn harness(id: &str) -> &'static Harness {
        registry::resolve(id).unwrap()
    }

    fn plan_for(harness: &Harness, home: &Path, cwd: &Path, force: bool) -> Result<Plan> {
        plan(harness, Scope::User, home, cwd, force)
    }

    fn install(harness: &Harness, home: &Path, cwd: &Path) -> Plan {
        let plan = plan_for(harness, home, cwd, false).unwrap();
        apply(&plan).unwrap();
        plan
    }

    /// Write a fixture config, creating its parent directory first.
    fn write_config(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn first_install_is_idempotent_for_every_harness() {
        for harness in registry::harnesses() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();
            let cwd = temp.path();

            let first = install(harness, home, cwd);
            assert_ne!(
                first.change,
                Change::Unchanged,
                "{} must plan a write",
                harness.id
            );
            assert!(first.creates, "{} must create a file", harness.id);

            let inspection = inspect(harness, Scope::User, home, cwd).unwrap();
            assert_eq!(
                inspection.status,
                EntryStatus::Installed,
                "{} must inspect as installed\n{}",
                harness.id,
                String::from_utf8_lossy(&std::fs::read(&inspection.path).unwrap())
            );

            let second = plan_for(harness, home, cwd, false).unwrap();
            assert_eq!(
                second.change,
                Change::Unchanged,
                "{} must be idempotent",
                harness.id
            );
            assert!(second.contents.is_empty());
        }
    }

    #[test]
    fn install_preserves_unrelated_keys_and_comments() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();

        // Claude: unrelated server plus an unrelated root key.
        std::fs::write(
            home.join(".claude.json"),
            "{
  // keep this comment
  \"theme\": \"dark\",
  \"mcpServers\": {
    \"other\": { \"command\": \"other\" }
  }
}
",
        )
        .unwrap();
        install(harness("claude"), home, temp.path());
        let text = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(text.contains("keep this comment"), "{text}");
        assert!(text.contains("\"theme\""), "{text}");
        assert!(text.contains("\"other\""), "{text}");
        assert!(text.contains("\"akey\""), "{text}");

        // Codex: another server table stays intact.
        write_config(
            &home.join(".codex/config.toml"),
            "[mcp_servers.other]\ncommand = \"other\"\n",
        );
        install(harness("codex"), home, temp.path());
        let text = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(text.contains("[mcp_servers.other]"), "{text}");
        assert!(text.contains("[mcp_servers.akey]"), "{text}");

        // Hermes: unrelated root keys and servers survive.
        write_config(
            &home.join(".hermes/config.yaml"),
            "model: hermes-3\nmcp_servers:\n  other:\n    command: other\n",
        );
        install(harness("hermes"), home, temp.path());
        let text = std::fs::read_to_string(home.join(".hermes/config.yaml")).unwrap();
        assert!(text.contains("model: hermes-3"), "{text}");
        assert!(text.contains("other:"), "{text}");
        assert!(text.contains("akey:"), "{text}");
    }

    #[test]
    fn conflicting_entry_requires_force() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let claude = harness("claude");
        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"akey":{"type":"stdio","command":"other","args":["mcp"]}}}"#,
        )
        .unwrap();

        let err = plan_for(claude, home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");
        assert!(
            err.to_string().contains("--force"),
            "conflict must point at the fix: {err}"
        );

        let forced = plan_for(claude, home, temp.path(), true).unwrap();
        assert_eq!(forced.change, Change::Replaced);
        assert!(forced.replaced_detail.is_some());
        apply(&forced).unwrap();
        assert_eq!(
            inspect(claude, Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Installed
        );
    }

    #[test]
    fn disabled_or_wrong_type_entries_are_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();

        write_config(
            &home.join(".hermes/config.yaml"),
            "mcp_servers:\n  akey:\n    command: akey\n    args: [mcp]\n    enabled: false\n",
        );
        assert!(matches!(
            inspect(harness("hermes"), Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Conflict { .. }
        ));

        write_config(
            &home.join(".config/opencode/opencode.json"),
            r#"{"mcp":{"akey":{"type":"remote","command":["akey","mcp"]}}}"#,
        );
        assert!(matches!(
            inspect(harness("opencode"), Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Conflict { .. }
        ));

        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"akey":{"type":"sse","command":"akey","args":["mcp"]}}}"#,
        )
        .unwrap();
        assert!(matches!(
            inspect(harness("claude"), Scope::User, home, temp.path())
                .unwrap()
                .status,
            EntryStatus::Conflict { .. }
        ));
    }

    #[test]
    fn opencode_accepts_string_command_but_writes_the_array_form() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let oc = harness("opencode");
        write_config(
            &home.join(".config/opencode/opencode.json"),
            r#"{"mcp":{"akey":{"type":"local","command":"akey","args":["mcp"],"enabled":true}}}"#,
        );
        assert_eq!(
            inspect(oc, Scope::User, home, temp.path()).unwrap().status,
            EntryStatus::Installed
        );

        let other = temp.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        let plan = plan(oc, Scope::User, &other, temp.path(), false).unwrap();
        let text = String::from_utf8_lossy(&plan.contents);
        assert!(text.contains("\"command\": ["), "{text}");
        assert!(text.contains("$schema"), "{text}");
    }

    #[test]
    fn plain_entries_have_no_type_and_reject_disabled() {
        let configs = [
            ("cursor", ".cursor/mcp.json"),
            ("kiro", ".kiro/settings/mcp.json"),
            ("devin", ".config/devin/mcp_config.json"),
        ];

        for (id, relative) in configs {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();
            let harness = harness(id);

            let plan = install(harness, home, temp.path());
            let text = String::from_utf8_lossy(&plan.contents);
            assert!(text.contains("\"command\": \"akey\""), "{id}: {text}");
            assert!(text.contains("\"args\""), "{id}: {text}");
            assert!(!text.contains("\"type\""), "{id}: {text}");
            assert!(
                !text.contains("\"enabled\"") && !text.contains("\"disabled\""),
                "{id}: {text}"
            );

            // The canonical plain shape is accepted with an explicit `stdio` type as well.
            write_config(
                &home.join(relative),
                r#"{"mcpServers":{"akey":{"type":"stdio","command":"akey","args":["mcp"]}}}"#,
            );
            assert_eq!(
                inspect(harness, Scope::User, home, temp.path())
                    .unwrap()
                    .status,
                EntryStatus::Installed,
                "{id}"
            );

            // A remote transport must not be mistaken for the stdio entry akey installs.
            write_config(
                &home.join(relative),
                r#"{"mcpServers":{"akey":{"type":"sse","command":"akey","args":["mcp"]}}}"#,
            );
            assert!(matches!(
                inspect(harness, Scope::User, home, temp.path())
                    .unwrap()
                    .status,
                EntryStatus::Conflict { .. }
            ));

            // `disabled: true` means the entry exists but never runs.
            write_config(
                &home.join(relative),
                r#"{"mcpServers":{"akey":{"command":"akey","args":["mcp"],"disabled":true}}}"#,
            );
            let err = plan_for(harness, home, temp.path(), false).unwrap_err();
            assert!(matches!(err, Error::AgentConflict(_)), "{id}: {err:?}");
            assert!(err.to_string().contains("disabled"), "{id}: {err}");

            let forced = plan_for(harness, home, temp.path(), true).unwrap();
            assert_eq!(forced.change, Change::Replaced, "{id}");
            apply(&forced).unwrap();
            let text = std::fs::read_to_string(home.join(relative)).unwrap();
            assert!(!text.contains("disabled"), "{id}: {text}");
            assert_eq!(
                inspect(harness, Scope::User, home, temp.path())
                    .unwrap()
                    .status,
                EntryStatus::Installed,
                "{id}"
            );
        }
    }

    #[test]
    fn malformed_config_is_reported_and_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        std::fs::write(home.join(".claude.json"), "{ not json").unwrap();

        let status = inspect(harness("claude"), Scope::User, home, temp.path())
            .unwrap()
            .status;
        assert!(
            matches!(status, EntryStatus::Unreadable { .. }),
            "{status:?}"
        );

        let err = plan_for(harness("claude"), home, temp.path(), true).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(
            std::fs::read_to_string(home.join(".claude.json")).unwrap(),
            "{ not json"
        );
    }

    #[test]
    fn wrong_container_shape_is_not_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        std::fs::write(home.join(".claude.json"), r#"{"mcpServers":[]}"#).unwrap();
        let err = plan_for(harness("claude"), home, temp.path(), true).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(
            std::fs::read_to_string(home.join(".claude.json")).unwrap(),
            r#"{"mcpServers":[]}"#
        );
    }

    #[test]
    fn snippets_reinspect_as_installed() {
        // The fragment printed by `akey agent print` must be exactly the fragment a fresh
        // install writes; otherwise copy-paste and `install` would disagree.
        for harness in registry::harnesses() {
            let snippet = snippet(harness).unwrap();
            assert!(!snippet.trim().is_empty(), "{}", harness.id);

            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();
            let plan = plan_for(harness, home, temp.path(), false).unwrap();
            assert_eq!(
                snippet,
                String::from_utf8_lossy(&plan.contents),
                "{} snippet drifted from its install",
                harness.id
            );
        }
    }

    fn remove_for(harness: &Harness, home: &Path, cwd: &Path, force: bool) -> Result<RemovePlan> {
        plan_remove(harness, Scope::User, home, cwd, force)
    }

    #[test]
    fn uninstall_removes_only_the_akey_entry_for_every_harness() {
        for harness in registry::harnesses() {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();
            install(harness, home, temp.path());

            let plan = remove_for(harness, home, temp.path(), false).unwrap();
            assert_eq!(
                plan.change,
                RemoveChange::Removed,
                "{} must plan a removal",
                harness.id
            );
            apply_remove(&plan).unwrap();

            assert!(
                plan.path.is_file(),
                "{} uninstall must keep the config file",
                harness.id
            );
            assert_eq!(
                inspect(harness, Scope::User, home, temp.path())
                    .unwrap()
                    .status,
                EntryStatus::Missing,
                "{} must inspect as missing\n{}",
                harness.id,
                std::fs::read_to_string(&plan.path).unwrap()
            );

            // Uninstall is idempotent: a second pass is a no-op and drops no bytes.
            let again = remove_for(harness, home, temp.path(), false).unwrap();
            assert_eq!(again.change, RemoveChange::Missing, "{}", harness.id);
            assert!(again.contents.is_empty(), "{}", harness.id);
        }
    }

    #[test]
    fn uninstall_preserves_unrelated_settings() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();

        std::fs::write(
            home.join(".claude.json"),
            "{\n  // keep this comment\n  \"theme\": \"dark\",\n  \"mcpServers\": {\n    \"other\": { \"command\": \"other\" }\n  }\n}\n",
        )
        .unwrap();
        install(harness("claude"), home, temp.path());
        let plan = remove_for(harness("claude"), home, temp.path(), false).unwrap();
        apply_remove(&plan).unwrap();
        let text = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(text.contains("keep this comment"), "{text}");
        assert!(text.contains("\"theme\""), "{text}");
        assert!(text.contains("\"other\""), "{text}");
        assert!(!text.contains("\"akey\""), "{text}");

        write_config(
            &home.join(".codex/config.toml"),
            "# keep this comment\n[mcp_servers.other]\ncommand = \"other\"\n",
        );
        install(harness("codex"), home, temp.path());
        let plan = remove_for(harness("codex"), home, temp.path(), false).unwrap();
        apply_remove(&plan).unwrap();
        let text = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(text.contains("keep this comment"), "{text}");
        assert!(text.contains("[mcp_servers.other]"), "{text}");
        assert!(!text.contains("[mcp_servers.akey]"), "{text}");

        write_config(
            &home.join(".hermes/config.yaml"),
            "model: hermes-3\nmcp_servers:\n  other:\n    command: other\n",
        );
        install(harness("hermes"), home, temp.path());
        let plan = remove_for(harness("hermes"), home, temp.path(), false).unwrap();
        apply_remove(&plan).unwrap();
        let text = std::fs::read_to_string(home.join(".hermes/config.yaml")).unwrap();
        assert!(text.contains("model: hermes-3"), "{text}");
        assert!(text.contains("other:"), "{text}");
        assert!(!text.contains("akey:"), "{text}");

        write_config(
            &home.join(".config/opencode/opencode.json"),
            r#"{"$schema":"https://opencode.ai/config.json","mcp":{"other":{"type":"local","command":["other"]}}}"#,
        );
        install(harness("opencode"), home, temp.path());
        let plan = remove_for(harness("opencode"), home, temp.path(), false).unwrap();
        apply_remove(&plan).unwrap();
        let text = std::fs::read_to_string(home.join(".config/opencode/opencode.json")).unwrap();
        assert!(text.contains("$schema"), "{text}");
        assert!(text.contains("\"other\""), "{text}");
        assert!(!text.contains("\"akey\""), "{text}");

        write_config(
            &home.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"other":{"command":"other","args":[]}}}"#,
        );
        install(harness("cursor"), home, temp.path());
        let plan = remove_for(harness("cursor"), home, temp.path(), false).unwrap();
        apply_remove(&plan).unwrap();
        let text = std::fs::read_to_string(home.join(".cursor/mcp.json")).unwrap();
        assert!(text.contains("\"other\""), "{text}");
        assert!(!text.contains("\"akey\""), "{text}");
    }

    #[test]
    fn uninstall_tolerates_a_missing_file() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let plan = remove_for(harness("claude"), home, temp.path(), false).unwrap();
        assert_eq!(plan.change, RemoveChange::Missing);
        apply_remove(&plan).unwrap();
        assert!(!home.join(".claude.json").exists());
    }

    #[test]
    fn uninstall_requires_force_for_a_different_entry_and_force_removes_it() {
        let fixtures = [
            (
                "claude",
                ".claude.json",
                r#"{"mcpServers":{"akey":{"type":"stdio","command":"other","args":["mcp"]}}}"#,
            ),
            (
                "codex",
                ".codex/config.toml",
                "[mcp_servers.akey]\ncommand = \"other\"\n",
            ),
            (
                "hermes",
                ".hermes/config.yaml",
                "mcp_servers:\n  akey:\n    command: other\n    args: [mcp]\n",
            ),
            (
                "opencode",
                ".config/opencode/opencode.json",
                r#"{"mcp":{"akey":{"type":"local","command":["other","mcp"]}}}"#,
            ),
            (
                "cursor",
                ".cursor/mcp.json",
                r#"{"mcpServers":{"akey":{"command":"other","args":["mcp"]}}}"#,
            ),
            (
                "kiro",
                ".kiro/settings/mcp.json",
                r#"{"mcpServers":{"akey":{"command":"other","args":["mcp"]}}}"#,
            ),
            (
                "devin",
                ".config/devin/mcp_config.json",
                r#"{"mcpServers":{"akey":{"command":"other","args":["mcp"]}}}"#,
            ),
        ];

        for (id, relative, text) in fixtures {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path();
            write_config(&home.join(relative), text);
            let harness = harness(id);

            let err = remove_for(harness, home, temp.path(), false).unwrap_err();
            assert!(matches!(err, Error::AgentConflict(_)), "{id}: {err:?}");
            assert!(err.to_string().contains("--force"), "{id}: {err}");
            assert_eq!(
                std::fs::read_to_string(home.join(relative)).unwrap(),
                text,
                "{id} must be untouched without --force"
            );

            let forced = remove_for(harness, home, temp.path(), true).unwrap();
            assert_eq!(forced.change, RemoveChange::Removed, "{id}");
            assert!(forced.removed_detail.is_some(), "{id}");
            apply_remove(&forced).unwrap();
            assert_eq!(
                inspect(harness, Scope::User, home, temp.path())
                    .unwrap()
                    .status,
                EntryStatus::Missing,
                "{id}"
            );
        }
    }

    #[test]
    fn uninstall_force_removes_a_non_server_value() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();

        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"akey":7},"theme":"dark"}"#,
        )
        .unwrap();
        let err = remove_for(harness("claude"), home, temp.path(), false).unwrap_err();
        assert!(matches!(err, Error::AgentConflict(_)), "{err:?}");
        let forced = remove_for(harness("claude"), home, temp.path(), true).unwrap();
        apply_remove(&forced).unwrap();
        let text = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(!text.contains("\"akey\""), "{text}");
        assert!(text.contains("theme"), "{text}");

        write_config(
            &home.join(".codex/config.toml"),
            "[mcp_servers]\nakey = 7\n",
        );
        assert!(matches!(
            remove_for(harness("codex"), home, temp.path(), false).unwrap_err(),
            Error::AgentConflict(_)
        ));
        let forced = remove_for(harness("codex"), home, temp.path(), true).unwrap();
        apply_remove(&forced).unwrap();
        let text = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(!text.contains("akey"), "{text}");

        write_config(
            &home.join(".hermes/config.yaml"),
            "mcp_servers:\n  akey: 7\n",
        );
        assert!(matches!(
            remove_for(harness("hermes"), home, temp.path(), false).unwrap_err(),
            Error::AgentConflict(_)
        ));
        let forced = remove_for(harness("hermes"), home, temp.path(), true).unwrap();
        apply_remove(&forced).unwrap();
        let text = std::fs::read_to_string(home.join(".hermes/config.yaml")).unwrap();
        assert!(!text.contains("akey"), "{text}");
    }

    #[test]
    fn uninstall_never_rewrites_a_malformed_file() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        std::fs::write(home.join(".claude.json"), "{ not json").unwrap();

        let err = remove_for(harness("claude"), home, temp.path(), true).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
        assert_eq!(
            std::fs::read_to_string(home.join(".claude.json")).unwrap(),
            "{ not json"
        );
    }

    #[test]
    fn project_scope_uses_the_project_config() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let cwd = temp.path().join("project");
        std::fs::create_dir_all(&cwd).unwrap();

        let claude = harness("claude");
        let plan = plan(claude, Scope::Project, &home, &cwd, false).unwrap();
        assert_eq!(plan.path, cwd.join(".mcp.json"));
        assert_eq!(plan.mode, PROJECT_FILE_MODE);
        apply(&plan).unwrap();
        assert!(cwd.join(".mcp.json").is_file());
        assert!(!home.join(".claude.json").exists());
    }
}

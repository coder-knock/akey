//! JSON and JSONC adapter.
//!
//! Editing goes through `jsonc-parser`'s CST rather than a value round-trip, so comments,
//! key order, and unrelated settings survive. A brand-new document starts as `{}`; when the
//! harness declares a schema URL, that schema is added only on creation.

use std::path::Path;

use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstRootNode};
use serde_json::{Value as JsonValue, json};

use super::{
    Change, Draft, EntryStatus, EntryView, RemoveChange, RemoveDraft, SERVER_NAME, classify,
    classify_strict, corrupt, decide, finish, removal_guard, unreadable,
};
use crate::agent::registry::{Harness, McpStyle};
use crate::error::Result;

pub(super) fn inspect(harness: &Harness, text: &str) -> EntryStatus {
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
    classify(harness, entry_view(&value))
}

pub(super) fn draft(
    harness: &Harness,
    path: &Path,
    text: Option<&str>,
    force: bool,
) -> Result<Draft> {
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
            classify_strict(harness, path, entry_view(&value))?
        }
    };

    let (change, replaced_detail) = decide(harness, path, status, force)?;
    if change == Change::Unchanged {
        return Ok((change, Vec::new(), replaced_detail));
    }

    let desired = desired(harness)?;
    let value = to_cst_input(&desired).expect("desired JSON is always representable in CST");
    match servers.get(SERVER_NAME) {
        Some(prop) => prop.set_value(value),
        None => {
            servers.append(SERVER_NAME, value);
        }
    }

    Ok((change, finish(root.to_string()), replaced_detail))
}

fn entry_view(value: &JsonValue) -> EntryView {
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

fn desired(harness: &Harness) -> Result<JsonValue> {
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
        style => Err(super::adapter_mismatch(harness, style)),
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

pub(super) fn remove(
    harness: &Harness,
    path: &Path,
    text: &str,
    force: bool,
) -> Result<RemoveDraft> {
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
        .map(|value| entry_view(&value))
        .unwrap_or_default();
    let removed_detail = removal_guard(harness, path, classify(harness, view), force)?;

    prop.remove();
    Ok((
        RemoveChange::Removed,
        finish(root.to_string()),
        removed_detail,
    ))
}

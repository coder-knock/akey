//! TOML adapter, edited through `toml_edit` so comments and formatting survive.

use std::path::Path;

use toml_edit::{Array as TomlArray, DocumentMut, Item, Table};

use super::{
    ARGV, Change, Draft, EntryStatus, EntryView, RemoveChange, RemoveDraft, SERVER_NAME, classify,
    classify_strict, corrupt, decide, finish, removal_guard, unreadable,
};
use crate::agent::registry::Harness;
use crate::error::Result;

pub(super) fn inspect(harness: &Harness, text: &str) -> EntryStatus {
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
    classify(harness, entry_view(entry))
}

pub(super) fn draft(
    harness: &Harness,
    path: &Path,
    text: Option<&str>,
    force: bool,
) -> Result<Draft> {
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
                Some(entry) => classify_strict(harness, path, entry_view(entry))?,
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
    servers.insert(SERVER_NAME, entry());

    Ok((change, finish(doc.to_string()), replaced_detail))
}

fn entry_view(item: &Item) -> EntryView {
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

fn entry() -> Item {
    let mut table = Table::new();
    table.insert("command", toml_edit::value(SERVER_NAME));
    let mut args = TomlArray::new();
    args.push(ARGV[1]);
    table.insert("args", toml_edit::value(args));
    Item::Table(table)
}

pub(super) fn remove(
    harness: &Harness,
    path: &Path,
    text: &str,
    force: bool,
) -> Result<RemoveDraft> {
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
    let removed_detail = removal_guard(harness, path, classify(harness, entry_view(entry)), force)?;

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

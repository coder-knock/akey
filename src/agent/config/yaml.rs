//! YAML adapter, edited through `yaml_edit` paths so unrelated keys survive.

use std::path::Path;
use std::str::FromStr;

use yaml_edit::path::YamlPath;
use yaml_edit::{Document, YamlNode};

use super::{
    ARGV, Change, Draft, EntryStatus, EntryView, RemoveChange, RemoveDraft, SERVER_NAME, classify,
    classify_strict, corrupt, decide, finish, removal_guard, unreadable,
};
use crate::agent::registry::Harness;
use crate::error::Result;

pub(super) fn inspect(harness: &Harness, text: &str) -> EntryStatus {
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
    classify(harness, entry_view(&entry))
}

pub(super) fn draft(
    harness: &Harness,
    path: &Path,
    text: Option<&str>,
    force: bool,
) -> Result<Draft> {
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
                Some(entry) => classify_strict(harness, path, entry_view(&entry))?,
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

fn entry_view(node: &YamlNode) -> EntryView {
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

pub(super) fn remove(
    harness: &Harness,
    path: &Path,
    text: &str,
    force: bool,
) -> Result<RemoveDraft> {
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
    let removed_detail =
        removal_guard(harness, path, classify(harness, entry_view(&entry)), force)?;

    doc.try_remove_path(&format!("{}.{SERVER_NAME}", harness.key))
        .map_err(|err| corrupt(path, err.to_string()))?;
    Ok((
        RemoveChange::Removed,
        finish(doc.to_string()),
        removed_detail,
    ))
}

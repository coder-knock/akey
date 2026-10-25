//! `mcp`: a metadata-only JSON-RPC 2.0 service over stdio.

use std::io::{BufRead as _, Write};

use serde_json::{Value, json};

use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::reference::{Attribute, Reference};
use crate::vault::model::{DEFAULT_VAULT, Entry, Field, Vault};

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
pub(super) fn handle_message(vault: Option<&Vault>, message: &Value) -> Option<Value> {
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
            error_response(
                id,
                ERR_METHOD_NOT_FOUND,
                &format!("method '{other}' not found"),
            )
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
        "akey_list" => Some(result_response(
            id,
            tool_text(&list_payload(vault, &arguments)),
        )),
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

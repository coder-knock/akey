//! `doc`: read and write arbitrary file attachments.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::json;
use zeroize::Zeroizing;

use super::{env_lookup, write_stdout};
use crate::audit::{self, Action};
use crate::cli::{DocArgs, DocCommand};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::paths::{self, FILE_MODE};
use crate::reference::{self, Attribute, Reference};
use crate::vault::model::{Entry, Field, FieldType, slug};

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
            if !ctx.dry_run {
                paths::atomic_write(path, &bytes, FILE_MODE)?;
            }
            ctx.out.emit(
                if ctx.dry_run {
                    crate::msg!(
                        "dry run: would write {} byte(s) to {}",
                        "试运行：将写入 {} 字节到 {}",
                        bytes.len(),
                        path.display()
                    )
                } else {
                    crate::msg!(
                        "wrote {} byte(s) to {}",
                        "已写入 {} 字节到 {}",
                        bytes.len(),
                        path.display()
                    )
                },
                &json!({
                    "item": entry.name,
                    "field": reference.field,
                    "out_file": path.display().to_string(),
                    "bytes": bytes.len(),
                    "dry_run": ctx.dry_run,
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
        let entry = vault.entries.get_mut(&id).ok_or_else(|| {
            Error::not_found(crate::msg!(
                "no entry named '{}'",
                "没有名为 '{}' 的条目",
                name
            ))
        })?;
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

pub(super) fn decode_attachment(encoded: &str) -> Result<Vec<u8>> {
    let trimmed = encoded.trim();
    STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| {
            Error::corrupt(crate::msg!(
                "attachment is not valid base64",
                "附件不是合法的 base64"
            ))
        })
}

//! `read`, `run`, and `inject`: plaintext handed to the caller or a child process.

use chrono::Utc;
use serde_json::json;

use super::{env_lookup, read_stdin, read_text_file, write_stdout};
use crate::audit::{self, Action};
use crate::cli::{InjectArgs, ReadArgs, RunArgs};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::inject::run as inject;
use crate::paths::{self, FILE_MODE};
use crate::reference::{self, Reference};

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

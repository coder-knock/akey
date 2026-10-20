//! `akey agent` — install akey into AI agent harnesses.
//!
//! This layer is deliberately thin: it turns clap arguments into one [`agent`] request,
//! lets the orchestration module plan and apply everything, and renders the resulting
//! report. All knowledge about *which* harnesses exist lives in the registry, so this file
//! never grows a per-agent branch.

use std::path::PathBuf;

use crate::agent::{self, InstallRequest, NativeMode, PrintRequest, StatusRequest};
use crate::cli::{AgentArgs, AgentCommand, AgentInstallArgs, AgentStatusArgs};
use crate::error::{Error, Result};

use super::Ctx;

pub fn run(ctx: &Ctx, args: &AgentArgs) -> Result<()> {
    match &args.command {
        AgentCommand::List => {
            let report = agent::list();
            let human = report.render();
            ctx.out.emit(human, &report)
        }
        AgentCommand::Status(args) => status(ctx, args),
        AgentCommand::Install(args) => install(ctx, args),
        AgentCommand::Print(args) => print(ctx, args),
    }
}

fn status(ctx: &Ctx, args: &AgentStatusArgs) -> Result<()> {
    let selection = agent::select(&args.agents)?;
    let home = home()?;
    let cwd = cwd()?;
    let report = agent::status(&StatusRequest {
        selection: &selection,
        scope: args.scope,
        only: args.only,
        native: native(false),
        home: &home,
        cwd: &cwd,
    })?;
    let human = report.render(&home);
    ctx.out.emit(human, &report)
}

fn install(ctx: &Ctx, args: &AgentInstallArgs) -> Result<()> {
    let selection = install_selection(args)?;
    // A capability token is read-only, and installing writes outside the vault. Dry runs
    // never touch the filesystem, so they remain usable for inspection.
    if !ctx.dry_run {
        ctx.gate_write()?;
    }
    let home = home()?;
    let cwd = cwd()?;
    let report = agent::install(&InstallRequest {
        selection: &selection,
        scope: args.scope,
        only: args.only,
        force: args.force,
        dry_run: ctx.dry_run,
        native: native(args.no_native),
        home: &home,
        cwd: &cwd,
    })?;
    let human = report.render(&home);
    ctx.out.emit(human, &report)
}

fn print(ctx: &Ctx, args: &AgentStatusArgs) -> Result<()> {
    let selection = agent::select(&args.agents)?;
    let home = home()?;
    let cwd = cwd()?;
    let report = agent::print(&PrintRequest {
        selection: &selection,
        scope: args.scope,
        only: args.only,
        home: &home,
        cwd: &cwd,
    })?;
    let human = report.render(&home);
    ctx.out.emit(human, &report)
}

/// `install` is the one verb that writes, so it is also the one verb that refuses to
/// guess: naming no harness is almost always a typo, and silently installing into every
/// harness on the machine would be a surprising side effect. `--all` makes it explicit.
fn install_selection(args: &AgentInstallArgs) -> Result<agent::Selection> {
    if args.all && !args.agents.is_empty() {
        return Err(Error::usage(crate::msg!(
            "pass either harness names or `--all`, not both",
            "请只传 harness 名称或 `--all`，不要同时传"
        )));
    }
    if !args.all && args.agents.is_empty() {
        return Err(Error::usage(crate::msg!(
            "name at least one harness or pass `--all` (supported: {})",
            "请指定至少一个 harness 或加 `--all`（支持：{}）",
            agent::supported_ids()
        )));
    }
    agent::select(&args.agents)
}

fn native(no_native: bool) -> NativeMode<'static> {
    if no_native {
        NativeMode::Disabled
    } else {
        NativeMode::Auto
    }
}

fn home() -> Result<PathBuf> {
    agent::registry::user_home()
}

fn cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(Error::Io)
}

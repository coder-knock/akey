//! `token`: create, list, and revoke capability tokens.

use chrono::Utc;

use super::git_for;
use crate::audit::{self, Action};
use crate::cli::{TokenArgs, TokenCommand};
use crate::cmd::{Ctx, parse_duration};
use crate::crypto::token as tokenmod;
use crate::error::{Error, Result};
use crate::vault::model::is_valid_name;
use crate::vault::store::SYNCED_FILES;

pub fn token(ctx: &Ctx, args: &TokenArgs) -> Result<()> {
    let store = ctx.store()?;
    match &args.command {
        TokenCommand::Create {
            name,
            allow,
            deny_reveal,
            ttl,
        } => {
            // Key: without this gate, a token restricted to a single entry could mint an
            // **unrestricted** token and read the whole vault with it — scoping drops to zero
            // on the spot. Reproduced in practice.
            ctx.gate_write()?;
            if !is_valid_name(name) {
                return Err(Error::usage(crate::msg!(
                    "invalid token name '{}'",
                    "非法令牌名 '{}'",
                    name
                )));
            }
            let now = Utc::now();
            let expires_at = match ttl {
                Some(raw) => Some(now + parse_duration(raw)?),
                None => None,
            };
            let allow = if allow.is_empty() {
                None
            } else {
                Some(allow.clone())
            };

            if ctx.dry_run {
                return ctx.out.emit(
                    crate::msg!(
                        "dry run: would issue token '{}'",
                        "试运行：会签发令牌 '{}'",
                        name
                    ),
                    &serde_json::json!({ "action": "token create", "name": name, "allow": allow }),
                );
            }

            let issued = tokenmod::issue(name, allow.clone(), *deny_reveal, expires_at, now)?;
            let meta = issued.meta.clone();
            let id = meta.id;
            store.update(|vault| {
                vault.tokens.insert(id, meta);
                Ok(())
            })?;

            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: issue token {name}"))?;
            audit::record(
                &ctx.paths,
                store.identity.name(),
                Action::TokenIssue,
                Some(name),
                "ok",
            )?;

            ctx.out.emit(
                crate::msg!(
                    "token '{}' issued — copy it now, it will never be shown again\n{}",
                    "令牌 '{}' 已签发——请立即复制，之后不会再显示\n{}",
                    name,
                    issued.plaintext
                ),
                &serde_json::json!({
                    "name": name,
                    "token": issued.plaintext,
                    "allow": allow,
                    "deny_reveal": deny_reveal,
                    "expires_at": expires_at,
                }),
            )
        }

        TokenCommand::List => {
            let vault = store.load()?;
            let now = Utc::now();
            let rows: Vec<_> = vault
                .tokens
                .values()
                .map(|meta| {
                    serde_json::json!({
                        "name": meta.name,
                        "id": meta.id.to_string(),
                        "active": meta.is_active(now),
                        "allow": meta.allow,
                        "deny_reveal": meta.deny_reveal,
                        "expires_at": meta.expires_at,
                        "created_at": meta.created_at,
                        "last_used_at": meta.last_used_at,
                        "revoked_at": meta.revoked_at,
                    })
                })
                .collect();
            let human = if rows.is_empty() {
                crate::msg!("no tokens", "没有令牌")
            } else {
                rows.iter()
                    .map(|r| {
                        format!(
                            "{:<20} {:<8} {} {}",
                            r["name"].as_str().unwrap_or("?"),
                            if r["active"].as_bool() == Some(true) {
                                crate::msg!("active", "有效")
                            } else {
                                crate::msg!("inactive", "无效")
                            },
                            crate::i18n::m("expires", "有效期"),
                            r["expires_at"]
                                .as_str()
                                .unwrap_or(crate::i18n::m("never", "永不过期")),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            ctx.out.emit(human, &serde_json::json!({ "tokens": rows }))
        }

        TokenCommand::Rm { name } => {
            ctx.gate_write()?;
            let now = Utc::now();
            let id = store.update(|vault| {
                let meta = vault
                    .tokens
                    .values()
                    .find(|t| &t.name == name)
                    .ok_or_else(|| {
                        Error::not_found(crate::msg!(
                            "no token named '{}'",
                            "没有名为 '{}' 的令牌",
                            name
                        ))
                    })?;
                let id = meta.id;
                let meta = vault.tokens.get_mut(&id).expect("just found");
                if meta.revoked_at.is_none() {
                    meta.revoked_at = Some(now);
                }
                Ok(id)
            })?;
            let git = git_for(&store);
            git.add_paths(SYNCED_FILES)?;
            git.commit(&format!("akey: revoke token {name}"))?;
            audit::record(
                &ctx.paths,
                store.identity.name(),
                Action::TokenRevoke,
                Some(name),
                "ok",
            )?;
            ctx.out.emit(
                crate::msg!("token '{}' revoked", "令牌 '{}' 已吊销", name),
                &serde_json::json!({ "name": name, "id": id.to_string(), "revoked": true }),
            )
        }
    }
}

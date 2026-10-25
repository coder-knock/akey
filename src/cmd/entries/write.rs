//! `set` / `edit`: create or update an entry through the pure `apply_*` functions.

use chrono::{DateTime, Utc};
use serde_json::json;
use ulid::Ulid;

use super::input::{
    AssignAction, Assignment, apply_assignment, apply_assignments, apply_stdin, generate_password,
    parse_assignment, parse_recipe, read_stdin, warn_argv_secrets_edit,
};
use super::json_err;
use super::read::entry_view;
use super::template::{EntryTemplate, read_template};
use crate::audit::{self, Action};
use crate::cli::{EditArgs, RevealPolicy, SetArgs};
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::vault::model::{
    Category, Entry, Field, FieldType, MAX_NAME_LEN, Reveal, Vault, is_valid_name,
};

/// Create or update an entry. With the name unchanged, a second `set` is an **update** (ID and `created_at` stay put).
pub fn set(ctx: &Ctx, args: &SetArgs) -> Result<()> {
    ctx.gate_write()?;
    if args.item.is_empty() {
        return Err(Error::usage(crate::msg!(
            "set needs an item name",
            "`set` 需要一个条目名"
        )));
    }
    let plan = SetPlan::from_args(args)?;
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_set(&mut vault, &plan, now)?
    } else {
        store.update(|vault| apply_set(vault, &plan, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.entry.name),
            "ok",
        )?;
    }
    warn_argv_secrets_edit(ctx, &plan.assignments, &outcome.entry);

    let verb = if outcome.created { "create" } else { "update" };
    let human = format!(
        "{} entry '{}' ({}, {} field(s))",
        if dry {
            format!("dry run: would {verb}")
        } else if outcome.created {
            "created".to_string()
        } else {
            "updated".to_string()
        },
        outcome.entry.name,
        outcome.entry.id,
        outcome.entry.fields.len(),
    );
    let mut data = json!({
        "action": if outcome.created { "created" } else { "updated" },
        "name": outcome.entry.name,
        "id": outcome.entry.id.to_string(),
        "category": outcome.entry.category,
        "field_count": outcome.entry.fields.len(),
        "dry_run": dry,
    });
    if dry {
        // In the preview, concealed fields show only the placeholder — plaintext never enters JSON (NFR-9).
        let preview = serde_json::to_value(entry_view(&outcome.entry, false)).map_err(json_err)?;
        ctx.out
            .note(&serde_json::to_string_pretty(&preview).map_err(json_err)?);
        data["entry"] = preview;
    }
    ctx.out.emit(human, &data)
}

/// Edit an existing entry; never creates one. Any flag left out means "leave it alone".
pub fn edit(ctx: &Ctx, args: &EditArgs) -> Result<()> {
    ctx.gate_write()?;
    let plan = EditPlan::from_args(args)?;
    let store = ctx.store()?;
    let now = Utc::now();
    let dry = ctx.dry_run;

    let outcome = if dry {
        let mut vault = store.load()?;
        apply_edit(&mut vault, &plan, now)?
    } else {
        store.update(|vault| apply_edit(vault, &plan, now))?
    };

    if !dry {
        audit::record(
            &ctx.paths,
            store.identity.name(),
            Action::Write,
            Some(&outcome.entry.name),
            "ok",
        )?;
    }
    warn_argv_secrets_edit(ctx, &plan.assignments, &outcome.entry);

    let human = format!(
        "{} entry '{}' ({}, {} field(s))",
        if dry {
            "dry run: would update".to_string()
        } else {
            "updated".to_string()
        },
        outcome.entry.name,
        outcome.entry.id,
        outcome.entry.fields.len(),
    );
    let mut data = json!({
        "action": "updated",
        "name": outcome.entry.name,
        "id": outcome.entry.id.to_string(),
        "category": outcome.entry.category,
        "field_count": outcome.entry.fields.len(),
        "changed": outcome.changed,
        "dry_run": dry,
    });
    if dry {
        let preview = serde_json::to_value(entry_view(&outcome.entry, false)).map_err(json_err)?;
        ctx.out
            .note(&serde_json::to_string_pretty(&preview).map_err(json_err)?);
        data["entry"] = preview;
    }
    ctx.out.emit(human, &data)
}
// ─────────────────────────────── Pure write-path functions ───────────────────────────────

fn skeleton(id: Ulid, name: String, category: Category, now: DateTime<Utc>) -> Entry {
    let mut entry = Entry::new(id, name, category, now);
    entry.fields = category
        .builtin_fields()
        .iter()
        .map(|(label, ty)| Field::new(label, *ty, String::new()))
        .collect();
    entry
}

/// A write command cannot revive a soft-deleted entry in place; `restore` first, then edit.
fn writable_entry(vault: &Vault, key: &str) -> Result<Option<Entry>> {
    match vault.find(key) {
        Ok(entry) if entry.is_deleted() => Err(Error::usage(crate::msg!(
            "entry '{}' is deleted; run `akey restore {}` first",
            "条目 '{}' 已删除；请先运行 `akey restore {}`",
            entry.name,
            entry.name
        ))),
        Ok(entry) => Ok(Some(entry.clone())),
        Err(Error::NotFound(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

pub(super) struct SetPlan {
    pub(super) name: String,
    pub(super) category: Option<Category>,
    pub(super) title: Option<String>,
    pub(super) tags: Option<Vec<String>>,
    pub(super) template: Option<EntryTemplate>,
    pub(super) stdin_text: Option<String>,
    pub(super) secret_field: Option<String>,
    pub(super) generate_password: Option<String>,
    pub(super) assignments: Vec<Assignment>,
}

impl SetPlan {
    fn from_args(args: &SetArgs) -> Result<SetPlan> {
        if args.stdin && args.generate_password.is_some() {
            return Err(Error::usage(crate::msg!(
                "--stdin and --generate-password cannot be combined",
                "`--stdin` 与 `--generate-password` 不能同时使用"
            )));
        }
        let assignments = args
            .assignments
            .iter()
            .map(|spec| parse_assignment(spec))
            .collect::<Result<Vec<_>>>()?;
        let template = match &args.template {
            Some(path) => Some(read_template(path)?),
            None => None,
        };
        let stdin_text = if args.stdin {
            Some(read_stdin()?)
        } else {
            None
        };
        Ok(SetPlan {
            name: args.item.clone(),
            category: args.category,
            title: args.title.clone(),
            tags: (!args.tags.is_empty()).then(|| args.tags.clone()),
            template,
            stdin_text,
            secret_field: args.secret_field.clone(),
            generate_password: args.generate_password.clone(),
            assignments,
        })
    }
}

#[derive(Debug)]
pub(super) struct SetOutcome {
    pub(super) entry: Entry,
    pub(super) created: bool,
}

pub(super) fn apply_set(
    vault: &mut Vault,
    plan: &SetPlan,
    now: DateTime<Utc>,
) -> Result<SetOutcome> {
    if !is_valid_name(&plan.name) {
        return Err(Error::usage(crate::msg!(
            "invalid entry name '{}': expected ^[a-z0-9][a-z0-9._-]*$ with at most {} chars",
            "非法条目名 '{}'：应为 ^[a-z0-9][a-z0-9._-]*$，最多 {} 个字符",
            plan.name,
            MAX_NAME_LEN
        )));
    }
    let existing = writable_entry(vault, &plan.name)?;
    let created = existing.is_none();
    // Snapshot for the change check at the bottom. Taken before the template overlay, so a
    // `set` that only re-states what is already there counts as no change either.
    let before = existing.clone();

    let mut entry = match (existing, &plan.template) {
        (Some(entry), Some(template)) => {
            let mut entry = entry;
            template.overlay(&mut entry);
            entry
        }
        (Some(entry), None) => entry,
        (None, Some(template)) => template.to_entry(Ulid::generate(), plan.name.clone(), now),
        (None, None) => skeleton(
            Ulid::generate(),
            plan.name.clone(),
            plan.category.unwrap_or(Category::Apikey),
            now,
        ),
    };
    if let Some(category) = plan.category {
        entry.category = category;
    }
    if let Some(title) = &plan.title {
        entry.title = Some(title.clone());
    }
    if let Some(tags) = &plan.tags {
        entry.tags = tags.clone();
    }
    apply_assignments(&mut entry, &plan.assignments);
    if let Some(text) = &plan.stdin_text {
        apply_stdin(&mut entry, text, plan.secret_field.as_deref())?;
    }
    if let Some(raw) = &plan.generate_password {
        let recipe = parse_recipe(raw)?;
        let label = plan
            .secret_field
            .clone()
            .unwrap_or_else(|| entry.category.default_secret_field().to_string());
        if label.is_empty() {
            return Err(Error::usage(crate::msg!(
                "category '{}' has no default secret field; pass --secret-field",
                "分类 '{}' 没有默认秘密字段；请传 --secret-field",
                entry.category
            )));
        }
        apply_assignment(
            &mut entry,
            &Assignment {
                section: None,
                label,
                ty: Some(FieldType::Concealed),
                action: AssignAction::Set(generate_password(&recipe)),
            },
        );
    }
    // Only a real change advances the timestamp. `sync` uses `updated_at` to pick a merge
    // winner and to derive a conflict copy's ID, so stamping a no-op would let a retried `set`
    // outrank another device's genuine edit — and make the two devices derive different
    // conflict IDs for the same divergence.
    if before.as_ref() != Some(&entry) {
        entry.updated_at = now;
    }

    vault.entries.insert(entry.id, entry.clone());
    Ok(SetOutcome { entry, created })
}

struct EditPlan {
    item: String,
    title: Option<String>,
    tags: Option<Vec<String>>,
    template: Option<EntryTemplate>,
    favorite: bool,
    unfavorite: bool,
    rotate: bool,
    reveal_policy: Option<Reveal>,
    assignments: Vec<Assignment>,
}

impl EditPlan {
    fn from_args(args: &EditArgs) -> Result<EditPlan> {
        if args.favorite && args.unfavorite {
            return Err(Error::usage(crate::msg!(
                "--favorite and --unfavorite cannot be combined",
                "`--favorite` 与 `--unfavorite` 不能同时使用"
            )));
        }
        let assignments = args
            .assignments
            .iter()
            .map(|spec| parse_assignment(spec))
            .collect::<Result<Vec<_>>>()?;
        let template = match &args.template {
            Some(path) => Some(read_template(path)?),
            None => None,
        };
        let plan = EditPlan {
            item: args.item.clone(),
            title: args.title.clone(),
            tags: (!args.tags.is_empty()).then(|| args.tags.clone()),
            template,
            favorite: args.favorite,
            unfavorite: args.unfavorite,
            rotate: args.rotate,
            reveal_policy: args.reveal_policy.map(|p| match p {
                RevealPolicy::Allow => Reveal::Allow,
                RevealPolicy::Deny => Reveal::Deny,
            }),
            assignments,
        };
        if !plan.changes_anything() {
            return Err(Error::usage(crate::msg!(
                "nothing to change; pass assignments or one of --title/--tags/--favorite/--unfavorite/--rotate/--reveal-policy/--template",
                "没有可改的内容；请传赋值，或 --title/--tags/--favorite/--unfavorite/--rotate/--reveal-policy/--template 之一"
            )));
        }
        Ok(plan)
    }

    fn changes_anything(&self) -> bool {
        !self.assignments.is_empty()
            || self.title.is_some()
            || self.tags.is_some()
            || self.template.is_some()
            || self.favorite
            || self.unfavorite
            || self.rotate
            || self.reveal_policy.is_some()
    }
}

#[derive(Debug)]
struct EditOutcome {
    entry: Entry,
    changed: bool,
}

fn apply_edit(vault: &mut Vault, plan: &EditPlan, now: DateTime<Utc>) -> Result<EditOutcome> {
    let mut entry = writable_entry(vault, &plan.item)?.ok_or_else(|| {
        Error::not_found(crate::msg!(
            "no entry named '{}'",
            "没有名为 '{}' 的条目",
            plan.item
        ))
    })?;
    // Same rule as `apply_set`: only a real change may move `updated_at`, because that field
    // decides merge winners and names conflict copies.
    let before = entry.clone();

    if let Some(template) = &plan.template {
        template.overlay(&mut entry);
    }
    if let Some(title) = &plan.title {
        entry.title = Some(title.clone());
    }
    if let Some(tags) = &plan.tags {
        entry.tags = tags.clone();
    }
    if plan.favorite {
        entry.favorite = true;
    }
    if plan.unfavorite {
        entry.favorite = false;
    }
    if plan.rotate {
        entry.rotated_at = Some(now);
    }
    if let Some(reveal) = plan.reveal_policy {
        entry.reveal = reveal;
    }
    apply_assignments(&mut entry, &plan.assignments);
    if before != entry {
        entry.updated_at = now;
    }

    vault.entries.insert(entry.id, entry.clone());
    Ok(EditOutcome {
        entry,
        changed: true,
    })
}

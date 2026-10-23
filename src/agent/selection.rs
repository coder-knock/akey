//! Harness selection: which registered harnesses one command applies to.
//!
//! Selection is shared by `status`, `print`, `install`, and `uninstall`, so it lives
//! apart from any one lifecycle. The only policy here is the explicit/default split: a
//! default selection skips harnesses that cannot serve the requested scope, while an
//! explicit one turns that mismatch into an error.

use std::path::Path;

use super::registry::{Harness, Only, Scope, harnesses, resolve};

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// The harnesses one command applies to.
///
/// `explicit` records whether the user named them. A default selection quietly skips
/// harnesses that cannot serve the requested scope; an explicit one turns that into an
/// error, because a user who typed `akey agent install codex --scope project` needs to
/// learn that Codex has no project scope, not silently get nothing.
pub struct Selection {
    harnesses: Vec<&'static Harness>,
    explicit: bool,
}

impl Selection {
    pub fn harnesses(&self) -> &[&'static Harness] {
        &self.harnesses
    }

    pub fn explicit(&self) -> bool {
        self.explicit
    }
}

/// Resolve agent names (empty = every harness, in registry order).
pub fn select(names: &[String]) -> crate::error::Result<Selection> {
    if names.is_empty() {
        return Ok(Selection {
            harnesses: harnesses().iter().collect(),
            explicit: false,
        });
    }

    let mut wanted = Vec::with_capacity(names.len());
    for name in names {
        let harness =
            resolve(name).ok_or_else(|| crate::error::Error::usage(unknown_agent(name)))?;
        if !wanted.iter().any(|h: &&'static Harness| h.id == harness.id) {
            wanted.push(harness);
        }
    }
    // Report in registry order so a multi-harness install reads the same way every time.
    let ordered = harnesses()
        .iter()
        .filter(|harness| wanted.iter().any(|w| w.id == harness.id))
        .collect();
    Ok(Selection {
        harnesses: ordered,
        explicit: true,
    })
}

fn unknown_agent(name: &str) -> String {
    crate::msg!(
        "unknown agent `{}`; supported agents: {}",
        "未知 agent `{}`；支持的 agent：{}",
        name,
        supported_ids()
    )
}

/// Comma-separated list of registered harness ids, for error messages.
pub fn supported_ids() -> String {
    harnesses()
        .iter()
        .map(|harness| harness.id)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Narrow a selection to the harnesses that can serve a scope, applying the explicit/default
/// rule described on [`Selection`].
pub(super) fn scoped(
    selection: &Selection,
    scope: Scope,
    only: Only,
    home: &Path,
    cwd: &Path,
) -> crate::error::Result<Vec<&'static Harness>> {
    let mut targets = Vec::new();
    for &harness in &selection.harnesses {
        let has_scope = harness.supports(scope);
        let has_skill = !only.includes_skill() || harness.skill_dir(scope, home, cwd).is_some();
        if has_scope && has_skill {
            targets.push(harness);
            continue;
        }
        if selection.explicit {
            let reason = if !has_scope {
                crate::msg!(
                    "{} supports only the {} scope",
                    "{} 只支持 {} 范围",
                    harness.display,
                    harness.scopes_label()
                )
            } else {
                crate::msg!(
                    "{} has no skill directory for the {} scope",
                    "{} 在 {} 范围没有技能目录",
                    harness.display,
                    scope.as_str()
                )
            };
            return Err(crate::error::Error::usage(reason));
        }
    }
    if targets.is_empty() {
        return Err(crate::error::Error::usage(crate::msg!(
            "no selected harness supports the {} scope",
            "所选的 harness 都不支持 {} 范围",
            scope.as_str()
        )));
    }
    Ok(targets)
}

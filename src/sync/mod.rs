//! Cross-device sync: push the decrypted three-way merge result as a new commit on git.
//!
//! The algorithm is in `DESIGN.md` §8. Two essentials:
//! 1. **Settle the working tree first**, after which `ours` always equals `HEAD`, so the
//!    comparison is meaningful.
//! 2. On divergence, **`reset --soft` onto the remote first** and then commit the merge
//!    result — otherwise our commit does not have the remote as an ancestor, the push is
//!    rejected again, and it loops forever. This also yields linear history that the next
//!    device merges more easily.

use chrono::Utc;

use crate::error::{Error, Result};
use crate::vault::merge::{Conflict, MergeStats, merge3};
use crate::vault::model::Vault;
use crate::vault::recipients::Recipients;
use crate::vault::store::{RECIPIENTS_FILE, SYNCED_FILES, Store, VAULT_FILE};

pub mod git;

pub use git::{Git, PushOutcome};

/// Maximum retries after a rejected push. Exceeding it means another device is writing
/// concurrently, so it is handed back to the user.
pub const MAX_PUSH_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum SyncMode {
    /// Both ways: pull first, then push, merging when needed.
    #[default]
    Auto,
    /// Push local commits only.
    Push,
    /// Pull only, and only fast-forward.
    Pull,
    /// Report status only; change nothing.
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// No remote configured — not an error; the local vault keeps working.
    NoRemote,
    UpToDate,
    Pulled {
        commits: usize,
    },
    Pushed {
        commits: usize,
    },
    /// The histories diverged; merged (possibly producing conflict copies) and pushed.
    Merged {
        conflicts: Vec<Conflict>,
        stats: MergeStats,
    },
    /// The `--status` result.
    Status {
        ahead: usize,
        behind: usize,
    },
}

impl SyncOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncOutcome::NoRemote => "no_remote",
            SyncOutcome::UpToDate => "up_to_date",
            SyncOutcome::Pulled { .. } => "pulled",
            SyncOutcome::Pushed { .. } => "pushed",
            SyncOutcome::Merged { .. } => "merged",
            SyncOutcome::Status { .. } => "status",
        }
    }
}

pub fn sync(store: &Store, mode: SyncMode) -> Result<SyncOutcome> {
    let device = store.config.device_name.clone();
    let git = Git::new(
        store.repo(),
        &device,
        format!("akey+{}@akey.invalid", sanitise(&device)),
    );

    if !git.is_repo() {
        return Err(Error::SyncFailed(crate::msg!(
            "{} is not a git repository; run `akey init` first",
            "{} 不是 git 仓库；请先运行 `akey init`",
            store.repo().display()
        )));
    }
    if git.remote_url()?.is_none() {
        return Ok(SyncOutcome::NoRemote);
    }

    // Settle the working tree first, so `ours` is the content of HEAD.
    git.add_paths(SYNCED_FILES)?;
    git.commit(&format!("akey: local changes from {device}"))?;

    if mode == SyncMode::Status {
        git.fetch()?;
        return status(&git);
    }

    let mut last_rejection = None;
    for _ in 0..MAX_PUSH_ATTEMPTS {
        git.fetch()?;
        let local = git.try_rev_parse("HEAD")?;
        let remote = git.try_rev_parse("FETCH_HEAD")?;

        let (Some(local_rev), Some(remote_rev)) = (local, remote) else {
            // Neither side has a commit yet: just push the local side up.
            return match push(&git, mode)? {
                PushOutcome::Pushed => Ok(SyncOutcome::Pushed { commits: 1 }),
                PushOutcome::UpToDate => Ok(SyncOutcome::UpToDate),
                PushOutcome::Rejected => {
                    last_rejection = Some(crate::msg!(
                        "remote branch appeared while pushing",
                        "推送过程中远端分支出现"
                    ));
                    continue;
                }
            };
        };

        if local_rev == remote_rev {
            return Ok(SyncOutcome::UpToDate);
        }

        if git.is_ancestor(&remote_rev, &local_rev)? {
            // Local is ahead → push directly.
            let ahead = git.commit_count(&format!("{remote_rev}..{local_rev}"))?;
            return match push(&git, mode)? {
                PushOutcome::Pushed => Ok(SyncOutcome::Pushed { commits: ahead }),
                PushOutcome::UpToDate => Ok(SyncOutcome::UpToDate),
                PushOutcome::Rejected => {
                    last_rejection = Some(crate::msg!(
                        "remote advanced concurrently",
                        "远端已并发更新"
                    ));
                    continue;
                }
            };
        }

        if git.is_ancestor(&local_rev, &remote_rev)? {
            // Remote is ahead → fast-forward.
            if mode == SyncMode::Push {
                return Err(Error::SyncFailed(crate::msg!(
                    "remote is ahead; run `akey sync` (without --push) to pull and merge",
                    "远端领先；请运行 `akey sync`（不带 --push）拉取并合并"
                )));
            }
            let behind = git.commit_count(&format!("{local_rev}..{remote_rev}"))?;

            // Preserve the local revocation markers before the remote revision lands
            // wholesale.
            //
            // `reset --hard` replaces the working tree (including recipients.json) with the
            // remote revision. But `merge_recipients`' "revocation wins" only runs on the
            // **diverged** path — a device removed with `devices rm` that still has git
            // write access can push an ordinary commit adding itself back, and the
            // fast-forward path would overwrite the revoking list entirely, nullifying the
            // revocation on the spot. Reproduced in practice.
            let ours = store.load_recipients()?;
            let theirs = recipients_at(&git, &remote_rev)?;
            let merged = merge_recipients(&Recipients::default(), &ours, &theirs);

            git.reset_hard(&remote_rev)?;

            if merged != theirs {
                merged.save(&store.recipients_path())?;
                git.add_paths(SYNCED_FILES)?;
                git.commit("akey: keep local recipient revocations")?;
            }

            // After a fast-forward, confirm this device can still decrypt: otherwise it
            // silently enters a "the vault is there but cannot be opened" state, and the
            // user only learns of their own revocation on the next command.
            store.load().map_err(|e| {
                Error::Locked(crate::msg!(
                    "pulled {} commit(s) but this device can no longer decrypt the vault: {}",
                    "已拉取 {} 个提交，但本设备已无法解密金库：{}",
                    behind,
                    e
                ))
            })?;
            return Ok(SyncOutcome::Pulled { commits: behind });
        }

        // Diverged → three-way merge.
        if mode == SyncMode::Pull {
            return Err(Error::SyncFailed(crate::msg!(
                "local and remote have diverged; run `akey sync` to merge",
                "本地与远端已分叉；请运行 `akey sync` 进行合并"
            )));
        }
        let base_rev = git.merge_base(&local_rev, &remote_rev)?.ok_or_else(|| {
            Error::SyncFailed(crate::msg!(
                "local and remote share no common ancestor; refusing to merge",
                "本地与远端没有共同祖先；拒绝合并"
            ))
        })?;
        let merged = merge(store, &git, &base_rev, &remote_rev)?;

        match push(&git, SyncMode::Auto)? {
            PushOutcome::Pushed | PushOutcome::UpToDate => {
                return Ok(SyncOutcome::Merged {
                    conflicts: merged.conflicts,
                    stats: merged.stats,
                });
            }
            PushOutcome::Rejected => {
                last_rejection = Some(crate::msg!(
                    "another device pushed while merging",
                    "合并期间另一台设备完成了推送"
                ));
                continue;
            }
        }
    }

    Err(Error::SyncFailed(crate::msg!(
        "push rejected {} times; another device is writing concurrently ({})",
        "推送被拒绝 {} 次；另一台设备正在并发写入（{}）",
        MAX_PUSH_ATTEMPTS,
        last_rejection.unwrap_or_else(|| crate::msg!("unknown reason", "原因未知"))
    )))
}

fn push(git: &Git, mode: SyncMode) -> Result<PushOutcome> {
    if mode == SyncMode::Pull {
        // `--pull` never pushes.
        return Ok(PushOutcome::UpToDate);
    }
    git.push()
}

fn status(git: &Git) -> Result<SyncOutcome> {
    let Some(local) = git.try_rev_parse("HEAD")? else {
        return Ok(SyncOutcome::UpToDate);
    };
    let Some(remote) = git.try_rev_parse("FETCH_HEAD")? else {
        return Ok(SyncOutcome::UpToDate);
    };
    if local == remote {
        return Ok(SyncOutcome::UpToDate);
    }
    let ahead = git.commit_count(&format!("{remote}..{local}"))?;
    let behind = git.commit_count(&format!("{local}..{remote}"))?;
    Ok(SyncOutcome::Status { ahead, behind })
}

/// Decrypt three ciphertexts, merge, and land the result as a new commit on top of the
/// remote.
fn merge(store: &Store, git: &Git, base_rev: &str, remote_rev: &str) -> Result<MergeOutcome> {
    let base = match git.show_bytes(base_rev, VAULT_FILE)? {
        Some(bytes) => store.open_ciphertext(&bytes)?,
        None => Vault::default(),
    };
    let theirs_ciphertext = git.show_bytes(remote_rev, VAULT_FILE)?.ok_or_else(|| {
        Error::SyncFailed(crate::msg!(
            "remote revision has no vault.age; refusing to overwrite",
            "远端版本没有 vault.age；拒绝覆盖"
        ))
    })?;
    let theirs = store.open_ciphertext(&theirs_ciphertext)?;
    let ours = store.load()?;

    let result = merge3(&base, &ours, &theirs);

    let base_recipients = recipients_at(git, base_rev)?;
    let theirs_recipients = recipients_at(git, remote_rev)?;
    let ours_recipients = store.load_recipients()?;
    let merged_recipients = merge_recipients(&base_recipients, &ours_recipients, &theirs_recipients);

    // Key: move HEAD onto the remote, then commit our merge result — that way the commit
    // has the remote as an ancestor and the push can fast-forward.
    git.reset_soft(remote_rev)?;

    merged_recipients.save(&store.recipients_path())?;
    store.save_with(&result.vault, &merged_recipients)?;

    git.add_paths(SYNCED_FILES)?;
    let message = format!(
        "akey: merge {} entries, {} conflicts",
        result.vault.entries.len(),
        result.conflicts.len()
    );
    git.commit(&message)?;

    Ok(MergeOutcome {
        conflicts: result.conflicts,
        stats: result.stats,
    })
}

struct MergeOutcome {
    conflicts: Vec<Conflict>,
    stats: MergeStats,
}

fn recipients_at(git: &Git, rev: &str) -> Result<Recipients> {
    match git.show_bytes(rev, RECIPIENTS_FILE)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            Error::Corrupt(crate::msg!(
                "{}@{} is not valid JSON: {}",
                "{}@{} 不是合法的 JSON：{}",
                RECIPIENTS_FILE,
                rev,
                e
            ))
        }),
        None => Ok(Recipients::default()),
    }
}

/// Three-way merge of recipient lists.
///
/// Unlike the entry merge rules, **revocation wins** here: if either side revoked, it stays
/// revoked. Otherwise two devices could sync once each and resurrect a revoked device —
/// that is a security incident, not a merge conflict.
pub fn merge_recipients(base: &Recipients, ours: &Recipients, theirs: &Recipients) -> Recipients {
    let mut merged = Recipients::default();
    let mut keys: Vec<&String> = base
        .recipients
        .keys()
        .chain(ours.recipients.keys())
        .chain(theirs.recipients.keys())
        .collect();
    keys.sort_unstable();
    keys.dedup();

    for key in keys {
        let b = base.recipients.get(key);
        let o = ours.recipients.get(key);
        let t = theirs.recipients.get(key);

        let record = match (b, o, t) {
            (_, None, None) => continue, // both sides deleted it
            (_, Some(o), None) => o.clone(),
            (_, None, Some(t)) => t.clone(),
            (_, Some(o), Some(t)) => {
                let mut rec = o.clone();
                // Name/kind: ours wins; if ours is new but theirs is earlier, take
                // theirs' added_at.
                rec.added_at = o.added_at.min(t.added_at);
                rec.last_seen_at = match (o.last_seen_at, t.last_seen_at) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                // Revocation wins, and the earlier revocation is kept.
                rec.revoked_at = match (o.revoked_at, t.revoked_at) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                rec
            }
        };
        merged.recipients.insert(key.clone(), record);
    }

    merged
}

fn sanitise(device: &str) -> String {
    device
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// For `doctor`: whether any unresolved conflict entries currently exist.
pub fn pending_conflicts(vault: &Vault) -> Vec<String> {
    vault
        .live_entries()
        .filter(|e| e.tags.iter().any(|t| t == "conflict"))
        .map(|e| e.name.clone())
        .collect()
}

/// Record the sync time, for human-readable output.
pub fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

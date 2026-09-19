//! 跨设备同步：把解密后的三方合并结果推成 git 上的新提交。
//!
//! 算法见 `DESIGN.md` §8。两条要点：
//! 1. **先落定工作区**，之后 `ours` 恒等于 `HEAD`，比较才有意义。
//! 2. 分叉时**先 `reset --soft` 到远端**再提交合并结果——否则我们的提交不以远端为祖先，
//!    push 仍会被拒，陷入死循环。这样得到的是线性历史，下一台设备也更好合。

use chrono::Utc;

use crate::error::{Error, Result};
use crate::vault::merge::{Conflict, MergeStats, merge3};
use crate::vault::model::Vault;
use crate::vault::recipients::Recipients;
use crate::vault::store::{RECIPIENTS_FILE, SYNCED_FILES, Store, VAULT_FILE};

pub mod git;

pub use git::{Git, PushOutcome};

/// push 被拒后的最大重试次数。超过说明有其他设备在并发写，交给用户。
pub const MAX_PUSH_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum SyncMode {
    /// 双向：先拉后推，必要时合并。
    #[default]
    Auto,
    /// 只推本地提交。
    Push,
    /// 只拉远端，且仅允许快进。
    Pull,
    /// 只看状态，不改动任何东西。
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// 未配置远端——不是错误，本地库照常可用。
    NoRemote,
    UpToDate,
    Pulled {
        commits: usize,
    },
    Pushed {
        commits: usize,
    },
    /// 发生分叉并已合并（可能带冲突副本）并推送。
    Merged {
        conflicts: Vec<Conflict>,
        stats: MergeStats,
    },
    /// `--status` 结果。
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
        return Err(Error::SyncFailed(format!(
            "{} is not a git repository; run `akey init` first",
            store.repo().display()
        )));
    }
    if git.remote_url()?.is_none() {
        return Ok(SyncOutcome::NoRemote);
    }

    // 先把工作区落定，这样 `ours` 就是 HEAD 的内容。
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
            // 任一侧还没有提交：直接把本地推上去即可。
            return match push(&git, mode)? {
                PushOutcome::Pushed => Ok(SyncOutcome::Pushed { commits: 1 }),
                PushOutcome::UpToDate => Ok(SyncOutcome::UpToDate),
                PushOutcome::Rejected => {
                    last_rejection = Some("remote branch appeared while pushing".to_string());
                    continue;
                }
            };
        };

        if local_rev == remote_rev {
            return Ok(SyncOutcome::UpToDate);
        }

        if git.is_ancestor(&remote_rev, &local_rev)? {
            // 本地领先 → 直接推。
            let ahead = git.commit_count(&format!("{remote_rev}..{local_rev}"))?;
            return match push(&git, mode)? {
                PushOutcome::Pushed => Ok(SyncOutcome::Pushed { commits: ahead }),
                PushOutcome::UpToDate => Ok(SyncOutcome::UpToDate),
                PushOutcome::Rejected => {
                    last_rejection = Some("remote advanced concurrently".to_string());
                    continue;
                }
            };
        }

        if git.is_ancestor(&local_rev, &remote_rev)? {
            // 远端领先 → 快进。
            if mode == SyncMode::Push {
                return Err(Error::SyncFailed(
                    "remote is ahead; run `akey sync` (without --push) to pull and merge".into(),
                ));
            }
            let behind = git.commit_count(&format!("{local_rev}..{remote_rev}"))?;

            // 远端版本整体落地之前先保住本地的吊销标记。
            //
            // `reset --hard` 会把工作区（含 recipients.json）换成远端版本。而
            // `merge_recipients` 的"吊销优先"只在**分叉**路径上跑得到——一个被
            // `devices rm` 掉的设备只要还有 git 写权限，推一个把自己加回去的普通提交，
            // 快进路径就会把那本带吊销的清单整个覆盖掉，吊销当场失效。实测可复现。
            let ours = store.load_recipients()?;
            let theirs = recipients_at(&git, &remote_rev)?;
            let merged = merge_recipients(&Recipients::default(), &ours, &theirs);

            git.reset_hard(&remote_rev)?;

            if merged != theirs {
                merged.save(&store.recipients_path())?;
                git.add_paths(SYNCED_FILES)?;
                git.commit("akey: keep local recipient revocations")?;
            }

            // 快进后必须确认本机仍能解密：否则会静默进入"库在、但打不开"的状态，
            // 而用户直到下一条命令才知道自己被吊销了。
            store.load().map_err(|e| {
                Error::Locked(format!(
                    "pulled {behind} commit(s) but this device can no longer decrypt the vault: {e}"
                ))
            })?;
            return Ok(SyncOutcome::Pulled { commits: behind });
        }

        // 分叉 → 三方合并。
        if mode == SyncMode::Pull {
            return Err(Error::SyncFailed(
                "local and remote have diverged; run `akey sync` to merge".into(),
            ));
        }
        let base_rev = git.merge_base(&local_rev, &remote_rev)?.ok_or_else(|| {
            Error::SyncFailed(
                "local and remote share no common ancestor; refusing to merge".to_string(),
            )
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
                last_rejection = Some("another device pushed while merging".to_string());
                continue;
            }
        }
    }

    Err(Error::SyncFailed(format!(
        "push rejected {MAX_PUSH_ATTEMPTS} times; another device is writing concurrently ({})",
        last_rejection.unwrap_or_else(|| "unknown reason".into())
    )))
}

fn push(git: &Git, mode: SyncMode) -> Result<PushOutcome> {
    if mode == SyncMode::Pull {
        // `--pull` 不推送。
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

/// 解密三份密文、合并、把结果落成远端之上的一个新提交。
fn merge(store: &Store, git: &Git, base_rev: &str, remote_rev: &str) -> Result<MergeOutcome> {
    let base = match git.show_bytes(base_rev, VAULT_FILE)? {
        Some(bytes) => store.open_ciphertext(&bytes)?,
        None => Vault::default(),
    };
    let theirs_ciphertext = git.show_bytes(remote_rev, VAULT_FILE)?.ok_or_else(|| {
        Error::SyncFailed("remote revision has no vault.age; refusing to overwrite".into())
    })?;
    let theirs = store.open_ciphertext(&theirs_ciphertext)?;
    let ours = store.load()?;

    let result = merge3(&base, &ours, &theirs);

    let base_recipients = recipients_at(git, base_rev)?;
    let theirs_recipients = recipients_at(git, remote_rev)?;
    let ours_recipients = store.load_recipients()?;
    let merged_recipients = merge_recipients(&base_recipients, &ours_recipients, &theirs_recipients);

    // 关键：把 HEAD 移到远端，再提交我们的合并结果 —— 这样提交以远端为祖先，push 才能快进。
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
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| Error::Corrupt(format!("{RECIPIENTS_FILE}@{rev} is not valid JSON: {e}"))),
        None => Ok(Recipients::default()),
    }
}

/// 收件人清单的三方合并。
///
/// 与条目合并的规则不同，这里**吊销优先**：任一侧吊销过就保持吊销。
/// 否则两台设备各自同步一次就能把已被吊销的设备复活——那是安全事件，不是合并冲突。
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
            (_, None, None) => continue, // 两侧都删了
            (_, Some(o), None) => o.clone(),
            (_, None, Some(t)) => t.clone(),
            (_, Some(o), Some(t)) => {
                let mut rec = o.clone();
                // 名字/类型：以 ours 为准，若 ours 是新增而 theirs 更早则取 theirs 的 added_at。
                rec.added_at = o.added_at.min(t.added_at);
                rec.last_seen_at = match (o.last_seen_at, t.last_seen_at) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                // 吊销优先，且取更早的那次吊销。
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

/// 供 `doctor` 使用：当前是否有未收敛的冲突条目。
pub fn pending_conflicts(vault: &Vault) -> Vec<String> {
    vault
        .live_entries()
        .filter(|e| e.tags.iter().any(|t| t == "conflict"))
        .map(|e| e.name.clone())
        .collect()
}

/// 记录同步时间，供人类输出。
pub fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

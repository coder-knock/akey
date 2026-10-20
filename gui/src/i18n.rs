//! Localization for the GUI.
//!
//! The design is the CLI's (`src/i18n.rs`), deliberately: a message is a **value** holding
//! every language, not a key into a table. A message that exists at all therefore exists in
//! every language — there is no "missing translation" state and no key that can go stale.
//!
//! One difference: the CLI resolves its language once per process because it runs one
//! command and exits. The GUI is long-lived and the user can switch language without
//! restarting, so the current [`Lang`] lives on the app and is passed in. [`Lang::resolve`]
//! is still used for the *initial* value, with the CLI's exact precedence, so a user who set
//! `AKEY_LANG=zh-CN` for the CLI gets a Chinese GUI too.

use std::fmt::Display;

/// A supported output language. Mirrors `akey::i18n::Lang`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// Source language, and the fallback for anything unrecognized.
    #[default]
    En,
    /// Simplified Chinese.
    ZhCn,
}

impl Lang {
    /// The BCP-47 tag.
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhCn => "zh-CN",
        }
    }

    /// The language's own name, for the switcher. Shown in its own language so the menu is
    /// readable to someone who cannot read the current one.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::ZhCn => "中文",
        }
    }

    /// Match on the primary subtag only, so `zh`, `zh_CN.UTF-8`, `zh-Hans-CN` and `ZH-cn`
    /// all land on [`Lang::ZhCn`]. Same rule as the CLI.
    pub fn from_tag(tag: &str) -> Option<Lang> {
        let primary = tag
            .split(['.', '@'])
            .next()
            .unwrap_or("")
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match primary.as_str() {
            "en" => Some(Lang::En),
            "zh" => Some(Lang::ZhCn),
            _ => None,
        }
    }

    /// Precedence: `--lang`-equivalent, then `$AKEY_LANG`, then the locale variables in the
    /// order the C library uses, then English.
    ///
    /// An explicit value naming no supported language is a hard error, so a typo is
    /// reported rather than silently producing English. An unsupported *locale* is not an
    /// error — most of the world's locales are not a request for anything.
    pub fn resolve(explicit: Option<&str>) -> Result<Lang, UnsupportedLanguage> {
        if let Some(tag) = explicit.map(str::trim).filter(|t| !t.is_empty()) {
            return Lang::from_tag(tag).ok_or_else(|| UnsupportedLanguage(tag.to_string()));
        }
        for key in ["AKEY_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Some(tag) = std::env::var(key).ok().filter(|t| !t.trim().is_empty())
                && let Some(lang) = Lang::from_tag(&tag)
            {
                return Ok(lang);
            }
        }
        Ok(Lang::En)
    }

    /// The language to start in, never failing: a bad explicit value warns on stderr and
    /// falls back, because a GUI that refuses to open over a locale typo is worse than one
    /// that opens in English.
    pub fn resolve_lossy(explicit: Option<&str>) -> Lang {
        match Lang::resolve(explicit) {
            Ok(lang) => lang,
            Err(e) => {
                eprintln!("akey-gui: {e}; falling back to English");
                Lang::En
            }
        }
    }

    pub fn next(self) -> Lang {
        match self {
            Lang::En => Lang::ZhCn,
            Lang::ZhCn => Lang::En,
        }
    }
}

/// An explicit language value that names no supported language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedLanguage(pub String);

impl Display for UnsupportedLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported language '{}'; supported: {}",
            self.0,
            supported()
                .iter()
                .map(|l| l.code())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for UnsupportedLanguage {}

pub const fn supported() -> &'static [Lang] {
    &[Lang::En, Lang::ZhCn]
}

/// One user-facing message in every supported language.
#[derive(Debug, Clone, Copy)]
pub struct Msg {
    en: &'static str,
    zh_cn: &'static str,
}

impl Msg {
    pub const fn new(en: &'static str, zh_cn: &'static str) -> Msg {
        Msg { en, zh_cn }
    }

    pub const fn text(self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => self.en,
            Lang::ZhCn => self.zh_cn,
        }
    }

    /// The English source, for tests and the parity check.
    pub const fn source(self) -> &'static str {
        self.en
    }

    pub const fn all(self) -> [&'static str; 2] {
        [self.en, self.zh_cn]
    }
}

/// Shorthand for the catalogue below: `m("English", "中文")`.
pub const fn m(en: &'static str, zh_cn: &'static str) -> Msg {
    Msg::new(en, zh_cn)
}

/// Substitute `{}` placeholders. `{{` / `}}` escape to a literal brace, matching `format!`.
///
/// Hand-rolled because `format!` needs a literal template at the call site, and the whole
/// point is that the template is a value varying by language.
pub fn fill(template: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut args = args.iter();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' if chars.peek() == Some(&'}') => {
                chars.next();
                match args.next() {
                    Some(arg) => out.push_str(&arg.to_string()),
                    // Too few arguments is a programming error, but this runs on error and
                    // status paths: leaving the placeholder visible beats panicking inside
                    // the reporter.
                    None => out.push_str("{}"),
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Count `{}` placeholders. `{{`/`}}` are counted too, which is harmless — the check is
/// that the two templates agree, and they use escapes alike.
pub const fn placeholder_count(template: &str) -> usize {
    let bytes = template.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'{' && bytes[i + 1] == b'}' {
            count += 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}

/// Compile-time guard: a translation with a different number of `{}` than its English
/// source would swallow an argument or print a stray placeholder.
pub const fn assert_placeholder_parity(en: &str, zh_cn: &str) {
    if placeholder_count(en) != placeholder_count(zh_cn) {
        panic!("translation placeholder count differs from its English source");
    }
}

/// Translate with the language in scope.
///
/// `t!(lang, "{} entries", "{} 个条目", n)` — the parity check runs at compile time on the
/// two templates, and the arguments are formatted in the chosen language's template.
#[allow(unused_macros)] // consumed by the gpui-gated views
macro_rules! t {
    ($lang:expr, $en:expr, $zh:expr $(, $arg:expr)* $(,)?) => {{
        const _: () = $crate::i18n::assert_placeholder_parity($en, $zh);
        $crate::i18n::fill(
            $crate::i18n::Msg::new($en, $zh).text($lang),
            &[$(&$arg as &dyn ::std::fmt::Display),*],
        )
    }};
}
// `pub(crate) use` rather than `#[macro_export]`: the macro is an internal convenience, and
// exporting it would put it in the crate's public surface where it can never be removed.
#[allow(unused_imports)] // ditto: unused in a build without the `gpui` feature
pub(crate) use t;

// ─────────────────────────────── catalogue ───────────────────────────────
//
// Grouped by where it appears. Every string the views render lives here; a literal in
// `views.rs` would be a string that silently cannot be translated.

/// Chrome: the header, the tabs, the status bar.
pub mod chrome {
    use super::m;

    pub const APP_TAGLINE: super::Msg = m("agent-safe credential vault", "面向 agent 的安全凭证库");
    pub const LOCAL_ONLY: super::Msg = m("local only", "仅本地");
    pub const TOKEN_SESSION: super::Msg = m("token session — read only", "令牌会话——只读");
    pub const DOCTOR_ERRORS: super::Msg = m("doctor: errors", "doctor：有错误");
    pub const AUDIT_COUNT: super::Msg = m("audit: {}", "审计：{}");
    pub const THEME: super::Msg = m("Theme", "主题");
    pub const LANGUAGE: super::Msg = m("Language", "语言");
    pub const READY: super::Msg = m("ready", "就绪");

    pub const TAB_ENTRIES: super::Msg = m("Entries", "条目");
    pub const TAB_SYNC: super::Msg = m("Sync", "同步");
    pub const TAB_DEVICES: super::Msg = m("Devices", "设备");
    pub const TAB_TOKENS: super::Msg = m("Tokens", "令牌");
    pub const TAB_RECOVERY: super::Msg = m("Recovery", "恢复");
    pub const TAB_DIAGNOSTICS: super::Msg = m("Diagnostics", "诊断");

    /// Every entry, for the tests that walk the catalogue. Kept beside the definitions so
    /// adding a message and forgetting to list it is visible in one screen of diff.
    pub const ALL: &[super::Msg] = &[
        APP_TAGLINE,
        LOCAL_ONLY,
        TOKEN_SESSION,
        DOCTOR_ERRORS,
        AUDIT_COUNT,
        THEME,
        LANGUAGE,
        READY,
        TAB_ENTRIES,
        TAB_SYNC,
        TAB_DEVICES,
        TAB_TOKENS,
        TAB_RECOVERY,
        TAB_DIAGNOSTICS,
    ];
}

/// The start-up gate (`FR-28`).
pub mod startup {
    use super::m;

    pub const NO_VAULT_TITLE: super::Msg = m("This machine has no vault yet", "本机还没有金库");
    pub const NO_VAULT_BODY: super::Msg = m(
        "Run `akey init` in a terminal to create one. It needs a git remote and a recovery \
         passphrase, so it stays an explicit choice rather than something this window does \
         for you.",
        "请在终端运行 `akey init` 创建。它需要一个 git 远端与一句恢复密码，所以它是一次明确的\
         选择，而不是本窗口替你做的事。",
    );
    pub const LOCKED_TITLE: super::Msg =
        m("This device cannot open the vault", "本设备无法打开金库");
    pub const FORMAT_TITLE: super::Msg = m(
        "This vault is newer than the installed akey",
        "金库比已安装的 akey 更新",
    );

    pub const ALL: &[super::Msg] = &[NO_VAULT_TITLE, NO_VAULT_BODY, LOCKED_TITLE, FORMAT_TITLE];
}

/// The entries surface.
pub mod entries {
    use super::m;

    pub const NO_MATCHES: super::Msg = m("no entries match", "没有匹配的条目");
    pub const SELECT_AN_ENTRY: super::Msg = m("select an entry", "选择一个条目");
    pub const CLEAR_FILTERS: super::Msg = m("clear filters", "清除筛选");
    /// The list filter that shows soft-deleted entries too. Named `FILTER_ALL` because a bare
    /// `ALL` is the catalogue's own "every message" list below.
    pub const FILTER_ALL: super::Msg = m("all", "全部");
    pub const EXPIRING: super::Msg = m("expiring 30d", "30 天内到期");
    pub const FILTER_CATEGORY: super::Msg = m("category", "分类");
    pub const DELETED: super::Msg = m("deleted", "已删除");
    pub const EXPIRING_SOON: super::Msg = m("expiring", "即将到期");
    pub const CONCEALED: super::Msg = m("concealed", "已遮蔽");

    pub const REVEAL: super::Msg = m("Reveal", "揭示");
    pub const HIDE: super::Msg = m("Hide", "隐藏");
    pub const COPY: super::Msg = m("Copy", "复制");
    pub const EDIT: super::Msg = m("Edit", "编辑");
    pub const FAVORITE: super::Msg = m("favorite", "收藏");
    pub const REVEAL_POLICY: super::Msg = m("reveal policy", "揭示策略");
    pub const RESTORE: super::Msg = m("Restore", "恢复");
    pub const DELETE: super::Msg = m("Delete", "删除");
    pub const PURGE: super::Msg = m("Purge", "彻底删除");

    pub const NEW_ENTRY: super::Msg = m("new / update entry", "新建 / 更新条目");
    pub const FIELD_NAME: super::Msg = m("name", "名称");
    pub const FIELD_FIELD: super::Msg = m(
        "field (blank: the category's default secret)",
        "字段（留空：该分类的默认秘密字段）",
    );
    pub const FIELD_VALUE: super::Msg = m(
        "value — sent on stdin, never in argv",
        "值——走 stdin，绝不进 argv",
    );
    pub const GENERATE: super::Msg = m("Generate", "生成");
    pub const PASSPHRASE: super::Msg = m("Passphrase", "词组");
    pub const SAVE: super::Msg = m("Save", "保存");
    pub const READ_ONLY_NOTE: super::Msg = m(
        "This session holds a capability token. Writing requires the local device identity.",
        "本会话持有能力令牌。写入需要本机设备身份。",
    );

    pub const SELECT_FIRST: super::Msg = m("select an entry first", "请先选择一个条目");
    pub const NAME_REQUIRED: super::Msg = m("entry name is required", "必须填写条目名称");
    pub const VALUE_REQUIRED: super::Msg = m("value is required", "必须填写值");
    pub const COPIED_WARNING: super::Msg = m(
        "copied — the clipboard is readable by other apps",
        "已复制——剪贴板可被其它程序读取",
    );
    pub const REVEAL_EXPIRED: super::Msg = m("reveal expired", "揭示已过期");
    pub const REVEAL_REFUSED: super::Msg = m("reveal refused: {}", "揭示被拒绝：{}");
    pub const NO_CONCEALED_FIELD: super::Msg =
        m("{} has no concealed field", "{} 没有可遮蔽的字段");
    pub const NOT_REVEALED: super::Msg = m("{} is not revealed", "{} 未处于揭示状态");
    pub const CONFIRM_ACTION: super::Msg = m(
        "Confirm {}: click the same action again",
        "确认{}：请再次点击同一操作",
    );

    pub const ALL: &[super::Msg] = &[
        NO_MATCHES,
        SELECT_AN_ENTRY,
        CLEAR_FILTERS,
        FILTER_ALL,
        EXPIRING,
        FILTER_CATEGORY,
        DELETED,
        EXPIRING_SOON,
        CONCEALED,
        REVEAL,
        HIDE,
        COPY,
        EDIT,
        FAVORITE,
        REVEAL_POLICY,
        RESTORE,
        DELETE,
        PURGE,
        NEW_ENTRY,
        FIELD_NAME,
        FIELD_FIELD,
        FIELD_VALUE,
        GENERATE,
        PASSPHRASE,
        SAVE,
        READ_ONLY_NOTE,
        SELECT_FIRST,
        NAME_REQUIRED,
        VALUE_REQUIRED,
        COPIED_WARNING,
        REVEAL_EXPIRED,
        REVEAL_REFUSED,
        NO_CONCEALED_FIELD,
        NOT_REVEALED,
        CONFIRM_ACTION,
    ];
}

/// The sync surface.
pub mod sync {
    use super::m;

    pub const SYNC_NOW: super::Msg = m("Sync now", "立即同步");
    pub const SYNCING: super::Msg = m("syncing in the background…", "正在后台同步…");
    pub const ALREADY_SYNCING: super::Msg = m("a sync is already running", "同步任务正在运行");
    pub const RELOAD: super::Msg = m("Reload conflicts", "重新载入冲突");
    pub const NO_CONFLICTS: super::Msg = m("no unresolved conflicts", "没有未解决的冲突");
    pub const KEEP_OURS: super::Msg = m("keep ours", "保留本地");
    pub const TAKE_THEIRS: super::Msg = m("take theirs", "采用对端");
    pub const CONFLICTS_PENDING: super::Msg = m(
        "Conflict copies were created. The merge and push already succeeded — nothing was \
         lost. Pick a side below.",
        "已产生冲突副本。合并与推送已经成功——没有丢数据。请在下面挑一边。",
    );
    pub const PENDING_RECIPIENTS: super::Msg = m(
        "These recipients are in the repository but not approved by this machine. They \
         receive no ciphertext.",
        "这些收件人在仓库里，但未被本机批准。它们收不到任何密文。",
    );
    pub const TRUST: super::Msg = m("Trust", "信任");
    pub const VS: super::Msg = m("vs {}", "对比 {}");
    pub const UNRESOLVED: super::Msg = m("conflicts need resolution", "冲突待处理");

    pub const ALL: &[super::Msg] = &[
        SYNC_NOW,
        SYNCING,
        ALREADY_SYNCING,
        RELOAD,
        NO_CONFLICTS,
        KEEP_OURS,
        TAKE_THEIRS,
        CONFLICTS_PENDING,
        PENDING_RECIPIENTS,
        TRUST,
        VS,
        UNRESOLVED,
    ];
}

/// The devices surface.
pub mod devices {
    use super::m;

    pub const TITLE: super::Msg = m("Devices", "设备");
    pub const RELOAD: super::Msg = m("Reload", "重新载入");
    pub const NONE: super::Msg = m("no devices", "没有设备");
    pub const THIS_DEVICE: super::Msg = m("this device", "本设备");
    pub const REVOKED: super::Msg = m("revoked", "已吊销");
    pub const UNTRUST: super::Msg = m("Untrust", "取消信任");
    pub const REVOKE: super::Msg = m("Revoke", "吊销");

    pub const ALL: &[super::Msg] = &[TITLE, RELOAD, NONE, THIS_DEVICE, REVOKED, UNTRUST, REVOKE];
}

/// The tokens surface.
pub mod tokens {
    use super::m;

    pub const TITLE: super::Msg = m("Capability tokens", "能力令牌");
    pub const RELOAD: super::Msg = m("Reload", "重新载入");
    pub const EXPLAINER: super::Msg = m(
        "Tokens are read-only credentials. The plaintext is shown once and never stored.",
        "令牌是只读凭据。明文只显示一次，不会被存储。",
    );
    pub const NAME: super::Msg = m("name", "名称");
    pub const TTL: super::Msg = m("ttl (e.g. 30d)", "有效期（如 30d）");
    pub const ISSUE: super::Msg = m("Issue (deny reveal)", "签发（禁止揭示）");
    pub const NONE: super::Msg = m("no tokens", "没有令牌");
    pub const DENY_REVEAL: super::Msg = m("deny reveal", "禁止揭示");
    pub const INACTIVE: super::Msg = m("inactive", "已失效");
    pub const EXPIRES: super::Msg = m("expires {}", "{} 到期");
    pub const ALL_ENTRIES: super::Msg = m("all entries", "全部条目");
    pub const NO_ENTRIES: super::Msg = m("no entries", "无条目");
    pub const ISSUED: super::Msg = m(
        "token {} issued — copy it now: {}",
        "令牌 {} 已签发——请立即复制：{}",
    );

    pub const ALL: &[super::Msg] = &[
        TITLE,
        RELOAD,
        EXPLAINER,
        NAME,
        TTL,
        ISSUE,
        NONE,
        DENY_REVEAL,
        INACTIVE,
        EXPIRES,
        ALL_ENTRIES,
        NO_ENTRIES,
        ISSUED,
    ];
}

/// The recovery surface.
pub mod recovery {
    use super::m;

    pub const TITLE: super::Msg = m("Recovery passphrase", "恢复密码");
    pub const CONFIGURED: super::Msg = m("configured", "已配置");
    pub const NOT_CONFIGURED: super::Msg = m("NOT configured", "未配置");
    pub const MIN_LENGTH: super::Msg = m("min {} characters", "最少 {} 个字符");
    pub const STATUS_UNAVAILABLE: super::Msg = m("status unavailable", "状态不可用");
    pub const NEEDS_IDENTITY: super::Msg = m(
        "Managing the recovery passphrase requires the local device identity.",
        "管理恢复密码需要本机设备身份。",
    );
    pub const FIELD_PASSPHRASE: super::Msg = m(
        "passphrase (hidden, sent on stdin)",
        "密码（隐藏，走 stdin）",
    );
    pub const FIELD_NEW: super::Msg = m("new passphrase (for rotate)", "新密码（用于轮换）");
    pub const FIELD_MIN: super::Msg = m("min length (optional)", "最小长度（可选）");
    pub const SET: super::Msg = m("Set", "设置");
    pub const VERIFY: super::Msg = m("Verify", "验证");
    pub const ROTATE: super::Msg = m("Rotate", "轮换");
    pub const GENERATE: super::Msg = m("Generate", "生成");
    pub const REQUIRED: super::Msg = m("passphrase is required", "必须填写密码");
    pub const MIN_INVALID: super::Msg = m(
        "minimum length must be a whole number from 0 to 65535",
        "最小长度必须是 0 到 65535 的整数",
    );
    pub const BOTH_REQUIRED: super::Msg = m(
        "both the current and the new passphrase are required",
        "当前密码与新密码都必须填写",
    );
    pub const SET_DONE: super::Msg = m("recovery passphrase set", "恢复密码已设置");
    pub const VERIFIED: super::Msg = m("recovery passphrase verified", "恢复密码已验证");
    pub const NOT_VERIFIED: super::Msg = m("not verified: {}", "未通过验证：{}");
    pub const ROTATED: super::Msg = m("recovery passphrase rotated", "恢复密码已轮换");
    pub const GENERATED: super::Msg = m("generated a 5-word passphrase", "已生成 5 词短语");

    pub const ALL: &[super::Msg] = &[
        TITLE,
        CONFIGURED,
        NOT_CONFIGURED,
        MIN_LENGTH,
        STATUS_UNAVAILABLE,
        NEEDS_IDENTITY,
        FIELD_PASSPHRASE,
        FIELD_NEW,
        FIELD_MIN,
        SET,
        VERIFY,
        ROTATE,
        GENERATE,
        REQUIRED,
        MIN_INVALID,
        BOTH_REQUIRED,
        SET_DONE,
        VERIFIED,
        NOT_VERIFIED,
        ROTATED,
        GENERATED,
    ];
}

/// The diagnostics surface.
pub mod diagnostics {
    use super::m;

    pub const TITLE: super::Msg = m("Diagnostics", "诊断");
    pub const RERUN: super::Msg = m("Re-run", "重新运行");
    pub const DOCTOR: super::Msg = m("doctor", "doctor");
    pub const AUDIT: super::Msg = m("audit", "审计");
    pub const NO_FINDINGS: super::Msg = m("no findings", "没有问题");
    pub const WEAK: super::Msg = m("weak", "弱密码");
    pub const REUSED: super::Msg = m("reused", "重复使用");
    pub const STALE: super::Msg = m("stale", "轮换陈旧");
    pub const EXPIRING: super::Msg = m("expiring", "即将过期");
    pub const DAYS_SINCE_ROTATION: super::Msg = m("{} days since rotation", "距上次轮换 {} 天");

    pub const ALL: &[super::Msg] = &[
        TITLE,
        RERUN,
        DOCTOR,
        AUDIT,
        NO_FINDINGS,
        WEAK,
        REUSED,
        STALE,
        EXPIRING,
        DAYS_SINCE_ROTATION,
    ];
}

/// Status lines for completed actions.
pub mod status {
    use super::m;

    pub const ENTRIES_LOADED: super::Msg = m("{} entries", "{} 个条目");
    pub const SHOWING: super::Msg = m("showing {}", "正在查看 {}");
    pub const REVEALED: super::Msg = m("revealed {}", "已揭示 {}");
    pub const HIDDEN: super::Msg = m("hidden", "已隐藏");
    pub const WROTE: super::Msg = m("wrote {}", "已写入 {}");
    pub const GENERATED: super::Msg = m("generated ({})", "已生成（{}）");
    pub const FAVORITED: super::Msg = m("{} favorited", "{} 已收藏");
    pub const UNFAVORITED: super::Msg = m("{} unfavorited", "{} 已取消收藏");
    pub const POLICY_TO: super::Msg = m("{} reveal policy → {}", "{} 揭示策略 → {}");
    pub const DELETED: super::Msg = m("{} deleted (restorable)", "{} 已删除（可恢复）");
    pub const PURGED: super::Msg = m("{} purged", "{} 已彻底删除");
    pub const RESTORED: super::Msg = m("restored {}", "已恢复 {}");
    pub const TRUSTED: super::Msg = m("trusted {}", "已信任 {}");
    pub const UNTRUSTED: super::Msg = m("untrusted {}", "已取消信任 {}");
    pub const REVOKED_AND_REENCRYPTED: super::Msg = m(
        "revoked {} and re-encrypted the vault",
        "已吊销 {} 并重新加密金库",
    );
    pub const TOKEN_REVOKED: super::Msg = m("revoked token {}", "已吊销令牌 {}");
    pub const RESOLVED: super::Msg = m("resolved {} → {}", "已收敛 {} → {}");
    pub const OURS: super::Msg = m("ours", "本地");
    pub const THEIRS: super::Msg = m("theirs", "对端");

    pub const ALL: &[super::Msg] = &[
        ENTRIES_LOADED,
        SHOWING,
        REVEALED,
        HIDDEN,
        WROTE,
        GENERATED,
        FAVORITED,
        UNFAVORITED,
        POLICY_TO,
        DELETED,
        PURGED,
        RESTORED,
        TRUSTED,
        UNTRUSTED,
        REVOKED_AND_REENCRYPTED,
        TOKEN_REVOKED,
        RESOLVED,
        OURS,
        THEIRS,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_tags_match_on_the_primary_subtag_only() {
        for tag in ["zh", "zh_CN.UTF-8", "zh-Hans-CN", "ZH-cn", "zh-TW", "zh_HK"] {
            assert_eq!(Lang::from_tag(tag), Some(Lang::ZhCn), "{tag}");
        }
        for tag in ["en", "en_US.UTF-8", "EN-gb", "en-AU"] {
            assert_eq!(Lang::from_tag(tag), Some(Lang::En), "{tag}");
        }
        for tag in ["fr", "de", "", "  ", "c"] {
            assert_eq!(Lang::from_tag(tag), None, "{tag}");
        }
    }

    #[test]
    fn explicit_language_wins_and_an_unknown_one_is_an_error() {
        assert_eq!(Lang::resolve(Some("zh-CN")).unwrap(), Lang::ZhCn);
        let err = Lang::resolve(Some("fr")).unwrap_err();
        assert!(err.to_string().contains("fr"), "{err}");
        assert!(err.to_string().contains("zh-CN"), "{err}");
    }

    #[test]
    fn resolve_lossy_falls_back_instead_of_refusing_to_open() {
        assert_eq!(Lang::resolve_lossy(Some("zh")), Lang::ZhCn);
        // A GUI that will not open over a locale typo is worse than one in English.
        assert_eq!(Lang::resolve_lossy(Some("klingon")), Lang::En);
    }

    #[test]
    fn supported_languages_are_the_cli_s_two() {
        assert_eq!(
            supported().iter().map(|l| l.code()).collect::<Vec<_>>(),
            vec!["en", "zh-CN"]
        );
    }

    #[test]
    fn every_language_has_a_native_name_for_the_switcher() {
        for lang in supported() {
            assert!(!lang.native_name().is_empty());
        }
        assert_eq!(Lang::ZhCn.native_name(), "中文");
        assert_eq!(Lang::En.next(), Lang::ZhCn);
        assert_eq!(Lang::ZhCn.next(), Lang::En);
    }

    /// The design guarantee: a message carries every language as a value, so "missing
    /// translation" is not a state that can exist. This walks the whole catalogue.
    #[test]
    fn no_catalogue_entry_is_empty_in_any_language() {
        let mut checked = 0;
        macro_rules! walk {
            ($module:ident) => {
                for msg in $module::ALL {
                    for (i, text) in msg.all().iter().enumerate() {
                        assert!(
                            !text.trim().is_empty(),
                            "{}::{:?} is empty in language index {i}",
                            stringify!($module),
                            msg.source()
                        );
                    }
                    checked += 1;
                }
            };
        }
        walk!(chrome);
        walk!(startup);
        walk!(entries);
        walk!(sync);
        walk!(devices);
        walk!(tokens);
        walk!(recovery);
        walk!(diagnostics);
        walk!(status);
        assert!(
            checked >= 70,
            "only {checked} catalogue entries were checked"
        );
    }

    #[test]
    fn fill_substitutes_positionally() {
        assert_eq!(fill("{} entries", &[&7]), "7 entries");
        assert_eq!(
            fill("resolved {} → {}", &[&"openai", &"ours"]),
            "resolved openai → ours"
        );
        assert_eq!(fill("no placeholders", &[]), "no placeholders");
    }

    #[test]
    fn fill_escapes_braces_like_format_does() {
        assert_eq!(fill("{{}}", &[]), "{}");
        assert_eq!(fill("{{\"ok\":true}}", &[]), "{\"ok\":true}");
    }

    #[test]
    fn fill_leaves_a_placeholder_visible_rather_than_panicking_on_a_missing_argument() {
        // Runs on error paths; a panic here would take the window down with it.
        assert_eq!(fill("{} and {}", &[&1]), "1 and {}");
    }

    #[test]
    fn placeholder_count_agrees_with_fill() {
        assert_eq!(placeholder_count("{} entries"), 1);
        assert_eq!(placeholder_count("{} → {}"), 2);
        assert_eq!(placeholder_count("none"), 0);
        assert_eq!(placeholder_count("a {{}} b"), 1); // escape counts as a pair; harmless
    }

    #[test]
    fn every_translation_has_the_same_placeholder_count_as_its_source() {
        // The compile-time guard already proves this for `t!` call sites; this proves it
        // for the catalogue, which is where a mismatch would actually be written.
        let mut checked = 0;
        macro_rules! walk {
            ($module:ident) => {
                for msg in $module::ALL {
                    let [en, zh] = msg.all();
                    assert_eq!(
                        placeholder_count(en),
                        placeholder_count(zh),
                        "{}: EN {en:?} vs ZH {zh:?}",
                        stringify!($module)
                    );
                    checked += 1;
                }
            };
        }
        walk!(chrome);
        walk!(startup);
        walk!(entries);
        walk!(sync);
        walk!(devices);
        walk!(tokens);
        walk!(recovery);
        walk!(diagnostics);
        walk!(status);
        assert!(checked >= 70);
    }

    /// A Chinese translation that is just the English text is almost always an entry
    /// someone forgot to translate. Proper nouns and identifiers are legitimately shared.
    #[test]
    fn chinese_entries_are_actually_translated() {
        // A few entries are legitimately the same in both languages: they name a CLI verb
        // that is not translated anywhere else either.
        let allow_shared = ["doctor", "audit", "English"];
        macro_rules! walk {
            ($module:ident) => {
                for msg in $module::ALL {
                    let [en, zh] = msg.all();
                    if allow_shared.contains(&en) {
                        continue;
                    }
                    assert_ne!(
                        en,
                        zh,
                        "{}: {:?} is identical in both languages",
                        stringify!($module),
                        msg.source()
                    );
                }
            };
        }
        walk!(chrome);
        walk!(startup);
        walk!(entries);
        walk!(sync);
        walk!(devices);
        walk!(tokens);
        walk!(recovery);
        walk!(diagnostics);
        walk!(status);
    }

    #[test]
    fn the_t_macro_formats_in_the_chosen_language() {
        let n = 3;
        assert_eq!(t!(Lang::En, "{} entries", "{} 个条目", n), "3 entries");
        assert_eq!(t!(Lang::ZhCn, "{} entries", "{} 个条目", n), "3 个条目");
    }
}

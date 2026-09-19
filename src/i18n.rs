//! Localization.
//!
//! One language per process, resolved once at startup from `--lang`, `$AKEY_LANG`, or the
//! usual locale variables. English is the source language and the fallback: every message
//! carries all supported languages as a value, so a message cannot exist in one language and
//! be missing from another.
//!
//! Machine-readable output is deliberately **not** localized. `--json` carries a stable
//! `error.code` and stable keys; an agent branches on those, never on prose. Only the human
//! strings change.

use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

/// A supported output language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// Source language; also the fallback for anything unrecognized.
    #[default]
    En,
    /// Simplified Chinese.
    ZhCn,
}

impl Lang {
    /// The BCP-47 tag, also what `--lang` accepts.
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhCn => "zh-CN",
        }
    }

    /// Resolve from a tag. Matches on the primary subtag only, so `zh`, `zh_CN.UTF-8`,
    /// `zh-Hans-CN` and `ZH-cn` all land on [`Lang::ZhCn`].
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

    /// Precedence: an explicit choice, then the locale variables in the order the C library
    /// itself uses (`LC_ALL` overrides `LC_MESSAGES` overrides `LANG`), then English.
    ///
    /// An explicit choice that names no supported language is a hard error rather than a
    /// silent fallback: someone who typed `--lang fr` should be told, not quietly given
    /// English. A *locale* that names no supported language is not an error — most of the
    /// world's locales would otherwise make the tool refuse to run.
    pub fn resolve(explicit: Option<&str>) -> Result<Lang, UnsupportedLanguage> {
        if let Some(tag) = explicit.map(str::trim).filter(|t| !t.is_empty()) {
            return Lang::from_tag(tag).ok_or_else(|| UnsupportedLanguage(tag.to_string()));
        }
        for key in ["AKEY_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Some(tag) = std::env::var(key).ok().filter(|t| !t.trim().is_empty()) {
                // `C` and `POSIX` mean "no locale"; they are not a request for anything.
                if let Some(lang) = Lang::from_tag(&tag) {
                    return Ok(lang);
                }
            }
        }
        Ok(Lang::En)
    }
}

impl Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// An explicit `--lang`/`$AKEY_LANG` value that names no supported language.
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

/// Every language the catalog covers. `--lang` documents this list.
pub const fn supported() -> &'static [Lang] {
    &[Lang::En, Lang::ZhCn]
}

/// One user-facing message in every supported language.
///
/// Held as a value rather than looked up by key: a message that exists at all exists in every
/// language, so there is no such thing as a missing translation and no key that can go stale.
#[derive(Debug, Clone, Copy)]
pub struct Msg {
    en: &'static str,
    zh_cn: &'static str,
}

impl Msg {
    pub const fn new(en: &'static str, zh_cn: &'static str) -> Msg {
        Msg { en, zh_cn }
    }

    pub fn text(self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => self.en,
            Lang::ZhCn => self.zh_cn,
        }
    }

    /// The English source text. Used by tests and by the placeholder-parity check.
    pub const fn source(self) -> &'static str {
        self.en
    }

    /// Every language's rendering, for the parity check.
    pub const fn all(self) -> [&'static str; 2] {
        [self.en, self.zh_cn]
    }
}

/// Substitute `format!`-style positional `{}` placeholders with `args`.
///
/// A hand-rolled formatter because `format!` needs a literal at the call site, and the whole
/// point here is that the template is a value that varies with the language. `{{` and `}}`
/// escape to a literal brace, matching `format!`.
///
/// Runs on error and diagnostic paths only, so the allocation is not on any hot path.
pub fn fill(msg: Msg, args: &[&dyn Display]) -> String {
    fill_text(msg.text(process_lang()), args)
}

/// [`fill`] against an explicit language, which is what the unit tests drive.
pub fn fill_text(template: &str, args: &[&dyn Display]) -> String {
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
                    // More placeholders than arguments is a programming error, but this is a
                    // diagnostic path: showing the placeholder is better than panicking
                    // inside the error reporter.
                    None => out.push_str("{}"),
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Count `{}` placeholders. `{{`/`}}` escapes are counted as a placeholder here, which is
/// harmless: the check is about the two templates agreeing, and they use escapes alike.
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

/// Compile-time guard for [`msg!`]: a translation with a different number of `{}` than the
/// English source would swallow an argument or print a stray placeholder. Catching it while
/// the translation is being written is the only cheap moment to catch it.
pub const fn assert_placeholder_parity(en: &str, zh_cn: &str) {
    if placeholder_count(en) != placeholder_count(zh_cn) {
        // A literal `panic!`, not `assert!`: `assert!` routes through `format_args!`, which
        // cannot be called in a const context.
        panic!("translation placeholder count differs from its English source");
    }
}

// ------------------------------------------------------------------ process language

const EN: u8 = 0;
const ZH_CN: u8 = 1;
static PROCESS_LANG: AtomicU8 = AtomicU8::new(EN);

/// Set the process language. Called once, from startup, after the global flags are parsed.
pub fn set_lang(lang: Lang) {
    PROCESS_LANG.store(
        match lang {
            Lang::En => EN,
            Lang::ZhCn => ZH_CN,
        },
        Ordering::Relaxed,
    );
}

/// The process language.
pub fn process_lang() -> Lang {
    match PROCESS_LANG.load(Ordering::Relaxed) {
        ZH_CN => Lang::ZhCn,
        _ => Lang::En,
    }
}

/// Shorthand for a message in the process language, for use in clap attributes:
/// `help = i18n::m("English", "中文")`.
///
/// clap evaluates `help`/`about` expressions when it builds the command tree, so this is a
/// runtime lookup even though the attribute looks like a literal.
pub fn m(en: &'static str, zh_cn: &'static str) -> &'static str {
    Msg::new(en, zh_cn).text(process_lang())
}

/// Pull `--lang <tag>` or `--lang=<tag>` out of argv.
///
/// A hand-rolled pre-scan rather than a second `Parser`: `--help` is *produced by* the clap
/// parse, so the language has to be known before that parse runs. This is the only reason the
/// flag is read twice.
pub fn lang_from_argv<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--lang=") {
            return Some(value.to_string());
        }
        if arg == "--lang" {
            return args.next();
        }
    }
    None
}

/// Build a message in the process language: `msg!(...)` mirrors `format!`, taking the English
/// template, the Chinese one, then the arguments for the `{}` placeholders.
///
/// ```ignore
/// return Err(Error::usage(msg!(
///     "invalid entry name '{}': expected at most {} chars",
///     "非法条目名 '{}'：最多 {} 个字符",
///     name, MAX_NAME_LEN
/// )));
/// ```
///
/// The placeholder counts are checked at compile time, so a translation cannot silently drop
/// an argument.
#[macro_export]
macro_rules! msg {
    ($en:expr, $zh_cn:expr $(, $arg:expr)* $(,)?) => {{
        const _: () = $crate::i18n::assert_placeholder_parity($en, $zh_cn);
        $crate::i18n::fill(
            $crate::i18n::Msg::new($en, $zh_cn),
            &[$(&$arg as &dyn ::std::fmt::Display),*],
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_normalize_to_a_primary_subtag() {
        for tag in ["zh", "zh-CN", "zh_CN.UTF-8", "zh-Hans-CN", "ZH-cn", "zh@cn"] {
            assert_eq!(Lang::from_tag(tag), Some(Lang::ZhCn), "{tag}");
        }
        for tag in ["en", "en-US", "en_GB.UTF-8", "EN"] {
            assert_eq!(Lang::from_tag(tag), Some(Lang::En), "{tag}");
        }
        for tag in ["", "fr", "C", "POSIX", "de-DE"] {
            assert_eq!(Lang::from_tag(tag), None, "{tag}");
        }
    }

    #[test]
    fn an_explicit_language_must_be_supported() {
        assert_eq!(Lang::resolve(Some("zh-CN")), Ok(Lang::ZhCn));
        assert_eq!(Lang::resolve(Some("en")), Ok(Lang::En));
        // Explicit and unsupported is refused, not silently downgraded to English.
        assert_eq!(
            Lang::resolve(Some("fr")),
            Err(UnsupportedLanguage("fr".to_string()))
        );
        let rendered = UnsupportedLanguage("fr".into()).to_string();
        assert!(rendered.contains("zh-CN"), "{rendered}");
        assert!(rendered.contains("en"), "{rendered}");
    }

    #[test]
    fn the_language_flag_is_found_in_both_spellings() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            lang_from_argv(argv(&["list", "--lang", "zh-CN", "--json"])),
            Some("zh-CN".to_string())
        );
        assert_eq!(
            lang_from_argv(argv(&["--lang=zh", "list"])),
            Some("zh".to_string())
        );
        assert_eq!(lang_from_argv(argv(&["list", "--json"])), None);
        // A trailing `--lang` with no value must not panic or swallow anything.
        assert_eq!(lang_from_argv(argv(&["list", "--lang"])), None);
    }

    #[test]
    fn filling_substitutes_in_order_and_keeps_escaped_braces() {
        let m = Msg::new("{} of {} ({{literal}})", "{} 共 {}（{{字面}}）");
        assert_eq!(
            fill_text(m.text(Lang::En), &[&3, &"entries"]),
            "3 of entries ({literal})"
        );
        assert_eq!(
            fill_text(m.text(Lang::ZhCn), &[&3, &"条目"]),
            "3 共 条目（{字面}）"
        );
    }

    #[test]
    fn a_template_without_placeholders_is_returned_whole() {
        let m = Msg::new("no arguments here", "这里没有占位符");
        assert_eq!(fill_text(m.text(Lang::En), &[]), "no arguments here");
        assert_eq!(fill_text(m.text(Lang::ZhCn), &[]), "这里没有占位符");
    }

    /// The invariant the `const` check in `msg!` enforces at compile time, asserted here too so
    /// the failure message is visible in a test run rather than only in a build error.
    #[test]
    fn a_translation_that_drops_a_placeholder_is_a_compile_error() {
        assert_eq!(placeholder_count("{} of {}"), 2);
        assert_eq!(placeholder_count("no arguments here"), 0);
        assert_eq!(placeholder_count("a {} b {} c {}"), 3);
        // The pairs actually used across the crate must agree.
        for (en, zh) in [
            ("invalid entry name '{}': {}.", "非法条目名 '{}'：{}。"),
            ("{} entries", "{} 个条目"),
        ] {
            assert_eq!(
                placeholder_count(en),
                placeholder_count(zh),
                "placeholder count differs for {en:?}"
            );
        }
    }
}

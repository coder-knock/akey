//! Build the injection environment and the authorization surface.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::reference::{self, Reference};
use crate::vault::model::{Category, Entry, Vault};
use crate::vault::store::Store;

use super::Injection;

/// Combine `--with` / `--bundle` / `--env-file` into one environment.
///
/// Precedence (high → low): `--with` > `--bundle` > `--env-file` (with several files, a later
/// one overrides an earlier one) > the process's own environment.
///
/// The three `--with` forms:
/// - `VAR=akey://…`: a reference (a reference may also be embedded in another string, e.g. `AUTH=Bearer akey://a/b`)
/// - `VAR=ITEM`: an entry name; take that entry's default secret field for its `category`
/// - `ITEM`: the variable name is derived from the entry name (upper-case, non-alphanumeric → `_`), same value as above
///
/// `--bundle` accepts only `env-bundle` entries and injects **all** their fields (variable name = the field slug upper-cased);
/// `--env-file` is parsed with dotenv syntax, and an `akey://` reference in a value is resolved to plaintext.
/// The result is sorted by variable name, so the same set of inputs always yields the same environment.
///
/// `store` takes no part in evaluation yet: resolving references only needs `vault`. It is kept
/// because the caller (the `cmd` layer) already has it, and an injection policy that later keys
/// off the device or the repository (an audited device name, say) will not need a new signature.
pub fn resolve(
    _store: &Store,
    vault: &Vault,
    specs: &[String],
    bundles: &[String],
    env_files: &[PathBuf],
) -> Result<Injection> {
    // Inserted low → high: `BTreeMap`'s "last write wins" is the precedence, and the final key order is the deterministic output.
    let mut vars: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    // The individual plaintexts substituted into values, for the masker to register (see `Injection::plaintexts`).
    let mut plaintexts: Vec<Zeroizing<String>> = Vec::new();

    for path in env_files {
        for (name, value) in load_env_file(path)? {
            vars.insert(name, render_refs(vault, &value, &mut plaintexts)?);
        }
    }

    for bundle in bundles {
        let entry = require_env_bundle(vault, bundle)?;
        if entry.fields.is_empty() {
            return Err(Error::usage(crate::msg!(
                "env-bundle '{}' has no fields to inject",
                "env-bundle '{}' 没有可注入的字段",
                entry.name
            )));
        }
        for field in &entry.fields {
            vars.insert(
                env_name(&field.id),
                Zeroizing::new(field.value().to_string()),
            );
        }
    }

    for spec in specs {
        let (name, value) = match spec.split_once('=') {
            Some((name, raw)) => {
                let name = name.trim();
                if !is_env_var_name(name) {
                    return Err(Error::usage(crate::msg!(
                        "--with '{}': '{}' is not a valid environment variable name",
                        "--with '{}'：'{}' 不是合法的环境变量名",
                        spec,
                        name
                    )));
                }
                (name.to_string(), with_value(vault, raw, &mut plaintexts)?)
            }
            None => {
                let entry = vault.find(spec)?;
                (env_name(&entry.name), default_secret(entry)?)
            }
        };
        vars.insert(name, value);
    }

    Ok(Injection {
        vars: vars.into_iter().collect(),
        plaintexts,
    })
}

/// The "authorization surface" of one injection: the `cmd` layer uses it to pin the token scope ahead of injection.
///
/// Injecting means handing plaintext to a child process. `run` does not go through `gate_reveal`
/// (the plaintext never reaches the caller), but the scope must still apply — otherwise a token
/// restricted to a single entry only has to inject a value into `sh -c 'cat'` to read any entry.
#[derive(Debug, Default)]
pub struct Touch {
    /// Raw text that may contain `akey://` references (each `--with` spec plus the contents of
    /// every `--env-file`): handed to `Ctx::authorize_references`.
    pub texts: Vec<String>,
    /// **Entry names** resolved from the forms that point at an entry without a reference
    /// (`VAR=ITEM` / `ITEM` / `--bundle`): handed to `Ctx::authorize`. Names are stored rather than
    /// the user's raw input because the scope compares names (the user may pass a 22-char ID).
    pub items: Vec<String>,
    /// Every entry name this injection touches (sorted, deduplicated), used as the audit `subject`.
    pub subjects: Vec<String>,
}

/// Compute the authorization surface of one injection. To avoid growing the signature of
/// [`resolve`], the env files are read a second time here (a dotenv file is only a few hundred
/// bytes, and authorization has to complete before any plaintext is decrypted).
pub fn touch(
    vault: &Vault,
    specs: &[String],
    bundles: &[String],
    env_files: &[PathBuf],
) -> Result<Touch> {
    let mut touch = Touch::default();
    let mut items: BTreeSet<String> = BTreeSet::new();
    let mut subjects: BTreeSet<String> = BTreeSet::new();

    for path in env_files {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                crate::msg!(
                    "cannot read env file {}: {}",
                    "无法读取环境变量文件 {}：{}",
                    path.display(),
                    e
                ),
            ))
        })?;
        for raw in reference::extract_references(&content) {
            subjects.insert(vault.find(&parse_ref(&raw)?.item)?.name.clone());
        }
        touch.texts.push(content);
    }

    for bundle in bundles {
        let entry = require_env_bundle(vault, bundle)?;
        items.insert(entry.name.clone());
        subjects.insert(entry.name.clone());
    }

    for spec in specs {
        match spec.split_once('=') {
            Some((_, raw)) if raw.contains(reference::SCHEME) => {
                for raw in reference::extract_references(raw.trim()) {
                    subjects.insert(vault.find(&parse_ref(&raw)?.item)?.name.clone());
                }
            }
            Some((_, raw)) => {
                let name = vault.find(raw.trim())?.name.clone();
                items.insert(name.clone());
                subjects.insert(name);
            }
            None => {
                let name = vault.find(spec)?.name.clone();
                items.insert(name.clone());
                subjects.insert(name);
            }
        }
        touch.texts.push(spec.clone());
    }

    touch.items = items.into_iter().collect();
    touch.subjects = subjects.into_iter().collect();
    Ok(touch)
}

/// Replace every `akey://` reference in the input text with plaintext.
///
/// A reference that does not resolve → `NotFound` naming that reference (no field value is echoed: there are no secrets in the error message).
pub fn render_template(vault: &Vault, input: &str) -> Result<String> {
    // The sink here is discarded: the masking of `inject` does not apply (the caller is going to
    // get the plaintext anyway, and the gate has already vetted it in `Ctx::gate_references_reveal`).
    let mut unused: Vec<Zeroizing<String>> = Vec::new();
    Ok(render_refs(vault, input, &mut unused)?.to_string())
}

/// Environment variable name derivation: upper-case, non-alphanumeric → `_`.
///
/// Entry names and field slugs may both contain `.` / `-`, and upper-casing them directly would
/// yield names the shell cannot reference, so everything folds to underscores. `export` / `import`
/// use this to keep the naming identical on both sides.
pub fn env_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Parse dotenv text.
///
/// Supported: an `export ` prefix, a whole-line `#` comment, single/double quotes, blank lines, a
/// `=` inside the value, `\r\n` line endings. In a double-quoted value `\n` `\r` `\t` `\\` `\"` are
/// unescaped; a single-quoted value is always literal. A syntax error → `usage`, naming `label`
/// (the caller passes the file name) and the line number.
pub fn parse_dotenv(label: &str, input: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (index, raw_line) in input.lines().enumerate() {
        let lineno = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
            _ => line,
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::usage(crate::msg!(
                "{}:{}: expected `NAME=value`",
                "{}:{}：应为 `NAME=value`",
                label,
                lineno
            )));
        };
        let key = key.trim();
        if !is_env_var_name(key) {
            return Err(Error::usage(crate::msg!(
                "{}:{}: '{}' is not a valid environment variable name",
                "{}:{}：'{}' 不是合法的环境变量名",
                label,
                lineno,
                key
            )));
        }
        out.push((key.to_string(), unquote(value.trim())));
    }
    Ok(out)
}

/// The right-hand side of `--with`: replace references when it contains `akey://`, otherwise take the default secret field by entry name.
fn with_value(
    vault: &Vault,
    raw: &str,
    sink: &mut Vec<Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    let raw = raw.trim();
    if raw.contains(reference::SCHEME) {
        return render_refs(vault, raw, sink);
    }
    default_secret(vault.find(raw)?)
}

/// The default secret field value for an entry `category`.
fn default_secret(entry: &Entry) -> Result<Zeroizing<String>> {
    let label = entry.category.default_secret_field();
    if label.is_empty() {
        return Err(Error::usage(crate::msg!(
            "entry '{}' is an env-bundle and has no single secret field; use `--bundle {}`",
            "条目 '{}' 是 env-bundle，没有单一秘密字段；请使用 `--bundle {}`",
            entry.name,
            entry.name
        )));
    }
    let field = entry.field(label).ok_or_else(|| {
        Error::not_found(crate::msg!(
            "entry '{}' has no '{}' field to inject",
            "条目 '{}' 没有可注入的 '{}' 字段",
            entry.name,
            label
        ))
    })?;
    Ok(Zeroizing::new(field.value().to_string()))
}

/// `--bundle` accepts only `env-bundle` entries — flattening a single field of another category into an environment variable would only surprise people.
fn require_env_bundle<'a>(vault: &'a Vault, item: &str) -> Result<&'a Entry> {
    let entry = vault.find(item)?;
    if entry.category != Category::EnvBundle {
        return Err(Error::usage(crate::msg!(
            "entry '{}' is a {}, not an env-bundle; use `--with` for single values",
            "条目 '{}' 是 {}，不是 env-bundle；单个值请使用 `--with`",
            entry.name,
            entry.category
        )));
    }
    Ok(entry)
}

/// Replace every reference in the text with plaintext. Reference texts are processed in order of appearance; a repeated reference is replaced each time.
fn render_refs(
    vault: &Vault,
    input: &str,
    sink: &mut Vec<Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    let now = Utc::now();
    let rendered = walk_refs(input, |raw| {
        let value = resolve_ref(vault, raw, now)?;
        // Record the **individual** plaintext, not just the assembled string.
        if !value.is_empty() {
            sink.push(Zeroizing::new(value.clone()));
        }
        Ok(value)
    })?;
    Ok(Zeroizing::new(rendered))
}

/// Walk the `akey://` references in `input` in order of appearance, replacing each with the value returned by `visit`.
///
/// Reference boundaries are decided by [`reference::extract_references`] (the single source of
/// truth); it returns non-overlapping texts in order of appearance, so a `find` from the cursor
/// always hits.
fn walk_refs(input: &str, mut visit: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let raws = reference::extract_references(input);
    if raws.is_empty() {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for raw in &raws {
        let Some(offset) = input[cursor..].find(raw.as_str()) else {
            // Unreachable in theory; if it ever drifts, keep the original text — never replace at the wrong offset.
            continue;
        };
        let start = cursor + offset;
        out.push_str(&input[cursor..start]);
        out.push_str(&visit(raw)?);
        cursor = start + raw.len();
    }
    out.push_str(&input[cursor..]);
    Ok(out)
}

/// Parse one reference text (including `$VAR` expansion) and resolve it.
fn resolve_ref(vault: &Vault, raw: &str, now: DateTime<Utc>) -> Result<String> {
    let reference = parse_ref(raw)?;
    match reference::resolve(vault, &reference, now) {
        Ok(value) => Ok(value.to_string()),
        // Name the reference text so an agent knows what to fix; the message holds names only, no values.
        Err(Error::NotFound(msg)) => Err(Error::not_found(crate::msg!(
            "cannot resolve '{}': {}",
            "无法解析 '{}'：{}",
            raw,
            msg
        ))),
        Err(Error::Ambiguous(msg)) => Err(Error::Ambiguous(crate::msg!(
            "cannot resolve '{}': {}",
            "无法解析 '{}'：{}",
            raw,
            msg
        ))),
        Err(other) => Err(other),
    }
}

/// The single entry point for reference parsing (`$VAR` comes from the current process environment).
fn parse_ref(raw: &str) -> Result<Reference> {
    Reference::parse_in(raw, &|name| std::env::var(name).ok())
}

/// Read and parse one `--env-file`.
pub(super) fn load_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            crate::msg!(
                "cannot read env file {}: {}",
                "无法读取环境变量文件 {}：{}",
                path.display(),
                e
            ),
        ))
    })?;
    parse_dotenv(&path.display().to_string(), &raw)
}

/// A valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
pub(super) fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Strip quotes from a dotenv value. A single-quoted value is always literal; a double-quoted one handles escapes per dotenv convention.
fn unquote(value: &str) -> String {
    if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return unescape_double(inner);
    }
    if let Some(inner) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return inner.to_string();
    }
    value.to_string()
}

/// Escapes inside a double-quoted value: `\n` `\r` `\t` `\\` `\"`; an unknown escape is kept as is.
fn unescape_double(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

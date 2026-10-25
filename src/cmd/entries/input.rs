//! Assignment parsing, the two `--stdin` shapes, and password generation.

use std::io::Read as _;

use zeroize::Zeroizing;

use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::vault::model::{Entry, Field, FieldType, slug};

/// One assignment: `[<section>.]<field>[[<type>]]=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Assignment {
    pub(super) section: Option<String>,
    pub(super) label: String,
    pub(super) ty: Option<FieldType>,
    pub(super) action: AssignAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AssignAction {
    Set(String),
    Delete,
}

const ASSIGNABLE_TYPES: [FieldType; 10] = [
    FieldType::String,
    FieldType::Concealed,
    FieldType::Email,
    FieldType::Url,
    FieldType::Otp,
    FieldType::Date,
    FieldType::Number,
    FieldType::File,
    FieldType::SshKey,
    FieldType::Notes,
];

/// Characters a backslash may escape (any other `\x` is kept verbatim, so a private key or regex containing a backslash survives).
fn is_escapable(c: char) -> bool {
    matches!(c, '.' | '=' | '[' | ']' | '\\')
}

/// Find the **first unescaped** separator and split the input in two.
fn split_unescaped(input: &str, sep: char) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (idx, c) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' && input[idx + 1..].chars().next().is_some_and(is_escapable) {
            escaped = true;
            continue;
        }
        if c == sep {
            return Some((&input[..idx], &input[idx + c.len_utf8()..]));
        }
    }
    None
}

fn unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().copied().is_some_and(is_escapable) {
            out.push(chars.next().expect("peeked"));
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_field_type(raw: &str, spec: &str) -> Result<FieldType> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    if let Some(ty) = ASSIGNABLE_TYPES.iter().find(|ty| ty.as_str() == normalized) {
        return Ok(*ty);
    }
    Err(Error::usage(crate::msg!(
        "unknown field type '{}' in '{}'; expected one of string, concealed, email, url, otp, date, number, file, ssh-key, notes",
        "字段类型 '{}' 未知（位于 '{}' 中）；应为 string、concealed、email、url、otp、date、number、file、ssh-key、notes 之一",
        raw,
        spec
    )))
}

/// Parse `[section.]field[type]=value`; `value == [delete]` means delete that field.
pub(super) fn parse_assignment(spec: &str) -> Result<Assignment> {
    let (lhs, raw_value) = split_unescaped(spec, '=').ok_or_else(|| {
        Error::usage(crate::msg!(
            "assignment '{}' is missing '='; expected [section.]field[[type]]=value",
            "赋值 '{}' 缺少 '='；应为 [section.]field[[type]]=value",
            spec
        ))
    })?;

    let (head, ty) = match split_unescaped(lhs, '[') {
        Some((head, rest)) => {
            // Both spellings are accepted: `field[type]` and the 1Password-style `field[[type]]`.
            // DESIGN.md always wrote the latter while the parser only took the former — a doc and
            // an implementation disagreeing is itself a defect.
            let inner = rest
                .strip_suffix(']')
                .map(|inner| inner.strip_prefix('[').unwrap_or(inner))
                .map(|inner| inner.strip_suffix(']').unwrap_or(inner))
                .filter(|inner| !inner.is_empty() && !inner.contains(['[', ']']));
            let inner = inner.ok_or_else(|| {
                Error::usage(crate::msg!(
                    "malformed type suffix in '{}'; expected field[type]=value",
                    "赋值 '{}' 的类型后缀格式不对；应为 field[type]=value",
                    spec
                ))
            })?;
            (head, Some(parse_field_type(inner, spec)?))
        }
        None => (lhs, None),
    };

    let (section, label) = match split_unescaped(head, '.') {
        Some((section, label)) => {
            if section.is_empty() {
                return Err(Error::usage(crate::msg!(
                    "assignment '{}' has an empty section",
                    "赋值 '{}' 的 section 为空",
                    spec
                )));
            }
            (Some(unescape(section)), unescape(label))
        }
        None => (None, unescape(head)),
    };
    if label.is_empty() {
        return Err(Error::usage(crate::msg!(
            "assignment '{}' has an empty field name",
            "赋值 '{}' 的字段名为空",
            spec
        )));
    }

    let value = unescape(raw_value);
    let action = if value == "[delete]" {
        AssignAction::Delete
    } else {
        AssignAction::Set(value)
    };
    Ok(Assignment {
        section,
        label,
        ty,
        action,
    })
}

fn field_matches(field: &Field, assignment: &Assignment) -> bool {
    let target = slug(&assignment.label);
    let name_hit = field.id == target
        || field.id == assignment.label
        || field.label.eq_ignore_ascii_case(&assignment.label);
    let section_hit = assignment
        .section
        .as_ref()
        .is_none_or(|s| field.section.as_deref() == Some(s.as_str()));
    name_hit && section_hit
}

/// Apply one assignment. If the field exists, change its value (filling in the given section / type); otherwise create it.
pub(super) fn apply_assignment(entry: &mut Entry, assignment: &Assignment) {
    match &assignment.action {
        AssignAction::Delete => entry.fields.retain(|f| !field_matches(f, assignment)),
        AssignAction::Set(value) => {
            if let Some(field) = entry
                .fields
                .iter_mut()
                .find(|f| field_matches(f, assignment))
            {
                field.value = Zeroizing::new(value.clone());
                if let Some(section) = &assignment.section {
                    field.section = Some(section.clone());
                }
                if let Some(ty) = assignment.ty {
                    field.ty = ty;
                }
            } else {
                let ty = assignment.ty.unwrap_or(FieldType::Concealed);
                let mut field = Field::new(&assignment.label, ty, value.clone());
                field.section = assignment.section.clone();
                entry.fields.push(field);
            }
        }
    }
}

pub(super) fn apply_assignments(entry: &mut Entry, assignments: &[Assignment]) {
    for assignment in assignments {
        apply_assignment(entry, assignment);
    }
}

/// Labels whose plaintext came in through argv and landed in a concealed field (for the warning). Empty values do not count.
pub(super) fn argv_secret_labels(entry: &Entry, assignments: &[Assignment]) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for assignment in assignments {
        let AssignAction::Set(value) = &assignment.action else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if let Some(field) = entry.fields.iter().find(|f| field_matches(f, assignment))
            && field.is_concealed()
            && !labels.contains(&field.label)
        {
            labels.push(field.label.clone());
        }
    }
    labels
}

pub(super) fn warn_argv_secrets_edit(ctx: &Ctx, assignments: &[Assignment], entry: &Entry) {
    let labels = argv_secret_labels(entry, assignments);
    if labels.is_empty() {
        return;
    }
    ctx.out.warn(&crate::msg!(
        "plaintext for {} came in through argv (visible to `ps` and shell history); prefer --stdin or --template",
        "{} 的明文来自 argv（`ps` 与 shell 历史可见）；请改用 --stdin 或 --template",
        labels.join(", ")
    ));
}

// ─────────────────────────── stdin / password generation ───────────────────────────

pub(super) fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// The two shapes of `--stdin`: lines containing `=` are parsed one by one as assignments; otherwise the whole input is a single secret value.
pub(super) fn apply_stdin(entry: &mut Entry, text: &str, secret_field: Option<&str>) -> Result<()> {
    let body = text.trim_end_matches(['\n', '\r']);
    if body.trim().is_empty() {
        return Err(Error::usage(crate::msg!(
            "--stdin received no input",
            "`--stdin` 没有收到输入"
        )));
    }
    if body.lines().any(|line| line.contains('=')) {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let assignment = parse_assignment(line)?;
            apply_assignment(entry, &assignment);
        }
        return Ok(());
    }
    let label = match secret_field {
        Some(label) if !label.is_empty() => label.to_string(),
        _ => {
            let default = entry.category.default_secret_field();
            if default.is_empty() {
                return Err(Error::usage(crate::msg!(
                    "category '{}' has no default secret field; pass --secret-field",
                    "分类 '{}' 没有默认秘密字段；请传 --secret-field",
                    entry.category
                )));
            }
            default.to_string()
        }
    };
    apply_assignment(
        entry,
        &Assignment {
            section: None,
            label,
            ty: None,
            action: AssignAction::Set(body.to_string()),
        },
    );
    Ok(())
}

const LETTER_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT_CHARS: &str = "0123456789";
/// No quotes, backslashes, or spaces, keeping shells and serialization out of trouble.
const SYMBOL_CHARS: &str = "!@#$%^&*()-_=+[]{}:,.?/";

pub(super) const DEFAULT_PASSWORD_LEN: usize = 32;
const MAX_PASSWORD_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Recipe {
    pub(super) letters: bool,
    pub(super) digits: bool,
    pub(super) symbols: bool,
    pub(super) len: usize,
}

/// A recipe looks like `letters,digits,symbols,32`: character classes default to all, length to 32.
pub(super) fn parse_recipe(raw: &str) -> Result<Recipe> {
    let mut letters = false;
    let mut digits = false;
    let mut symbols = false;
    let mut len: Option<usize> = None;
    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        match token.to_ascii_lowercase().as_str() {
            "letters" | "letter" | "alpha" => letters = true,
            "digits" | "digit" | "numbers" | "number" => digits = true,
            "symbols" | "symbol" | "punct" => symbols = true,
            other => match other.parse::<usize>() {
                Ok(n) if n > 0 && n <= MAX_PASSWORD_LEN => len = Some(n),
                Ok(n) => {
                    return Err(Error::usage(crate::msg!(
                        "password length {} out of range; expected 1..={}",
                        "密码长度 {} 超出范围；应为 1..={}",
                        n,
                        MAX_PASSWORD_LEN
                    )));
                }
                Err(_) => {
                    return Err(Error::usage(crate::msg!(
                        "unknown password recipe token '{}'; expected letters, digits, symbols or a length",
                        "无法识别的密码配方项 '{}'；应为 letters、digits、symbols 或一个长度",
                        token
                    )));
                }
            },
        }
    }
    if !(letters || digits || symbols) {
        letters = true;
        digits = true;
        symbols = true;
    }
    Ok(Recipe {
        letters,
        digits,
        symbols,
        len: len.unwrap_or(DEFAULT_PASSWORD_LEN),
    })
}

fn recipe_pool(recipe: &Recipe) -> Vec<char> {
    let mut pool = Vec::new();
    if recipe.letters {
        pool.extend(LETTER_CHARS.chars());
    }
    if recipe.digits {
        pool.extend(DIGIT_CHARS.chars());
    }
    if recipe.symbols {
        pool.extend(SYMBOL_CHARS.chars());
    }
    pool
}

/// Draw characters from a byte source. Bytes `>= limit` are rejected (removing modulo bias); if the source misbehaves, a final
/// modulo fallback guarantees the **length always equals the recipe length** without looping forever.
pub(super) fn password_from_bytes<F: FnMut() -> u8>(recipe: &Recipe, mut next: F) -> String {
    let pool = recipe_pool(recipe);
    let size = pool.len();
    let limit = 256 - (256 % size);
    let mut out = String::with_capacity(recipe.len);
    let cap = recipe.len.saturating_mul(64).saturating_add(64);
    let mut attempts = 0usize;
    while out.len() < recipe.len && attempts < cap {
        attempts += 1;
        let byte = next();
        if (byte as usize) < limit {
            out.push(pool[byte as usize % size]);
        }
    }
    while out.len() < recipe.len {
        out.push(pool[next() as usize % size]);
    }
    out
}

pub(super) fn generate_password(recipe: &Recipe) -> String {
    let mut buf = vec![0u8; recipe.len + recipe.len / 2 + 8];
    rand::fill(buf.as_mut_slice());
    let mut cursor = 0usize;
    password_from_bytes(recipe, || {
        if cursor >= buf.len() {
            rand::fill(buf.as_mut_slice());
            cursor = 0;
        }
        let byte = buf[cursor];
        cursor += 1;
        byte
    })
}

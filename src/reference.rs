//! `akey://` 引用：用**名字**而不是明文来指代秘密。
//!
//! 语法见 `REQUIREMENTS.md` §12.3。本模块只做寻址与取值，不做暴露策略判断
//! （策略归 `cmd` 层），因此它的输出必须由调用方小心处理。

use std::fmt;

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::vault::model::{DEFAULT_VAULT, Entry, Field, Vault, slug};

pub const SCHEME: &str = "akey://";

/// 引用元数据查询参数（`?attribute=`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Attribute {
    /// 字段值本身。
    #[default]
    Value,
    /// 由 `otp` 字段现场算出的 TOTP（6 位，30 秒窗口）。
    Otp,
    /// 条目标题。
    Title,
    /// 字段类型。
    Type,
    /// 条目 ID。
    Id,
}

impl Attribute {
    /// query 里 `attribute=` 的规范取值。
    pub fn as_str(self) -> &'static str {
        match self {
            Attribute::Value => "value",
            Attribute::Otp => "otp",
            Attribute::Title => "title",
            Attribute::Type => "type",
            Attribute::Id => "id",
        }
    }

    /// 解析 `attribute=` 的取值；大小写不敏感，未知取值 → `usage`。
    fn parse_value(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "value" => Ok(Attribute::Value),
            "otp" => Ok(Attribute::Otp),
            "title" => Ok(Attribute::Title),
            "type" => Ok(Attribute::Type),
            "id" => Ok(Attribute::Id),
            _ => Err(Error::usage(format!(
                "unknown attribute '{value}'; expected one of value, otp, title, type, id"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub vault: String,
    pub item: String,
    pub section: Option<String>,
    pub field: String,
    pub attribute: Attribute,
}

impl Reference {
    /// 解析，不做变量展开。
    pub fn parse(input: &str) -> Result<Reference> {
        Reference::parse_plain(input)
    }

    /// 解析，并先用 `env` 展开 `$VAR`。未定义的变量 → `usage`。
    pub fn parse_in(input: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Reference> {
        let expanded = expand_vars(input, env)?;
        Reference::parse_plain(&expanded)
    }

    /// 展开后的纯解析：段数、字符集、query 语法。
    fn parse_plain(input: &str) -> Result<Reference> {
        let body = match input.get(..SCHEME.len()) {
            Some(prefix) if prefix.eq_ignore_ascii_case(SCHEME) => &input[SCHEME.len()..],
            _ => {
                return Err(Error::usage(format!(
                    "'{input}' is not an akey:// reference"
                )));
            }
        };

        let (path, query) = match body.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (body, None),
        };

        let segments: Vec<&str> = path.split('/').collect();
        let (vault, item, section, field) = match segments.as_slice() {
            [item, field] => (DEFAULT_VAULT, *item, None, *field),
            [vault, item, field] => (*vault, *item, None, *field),
            [vault, item, section, field] => (*vault, *item, Some(*section), *field),
            _ => {
                return Err(Error::usage(format!(
                    "'{input}' has {} segments; expected akey://[vault/]item[/section]/field",
                    segments.len()
                )));
            }
        };

        for segment in [Some(vault), Some(item), section, Some(field)].into_iter().flatten() {
            validate_segment(segment, input)?;
        }

        let attribute = match query {
            Some(query) => parse_query(query, input)?,
            None => Attribute::Value,
        };

        Ok(Reference {
            vault: vault.to_string(),
            item: item.to_string(),
            section: section.map(str::to_string),
            field: field.to_string(),
            attribute,
        })
    }
}

impl fmt::Display for Reference {
    /// 规范形式：`akey://vault/item[/section]/field[?attribute=…]`，`attribute=value` 省略。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}/{}", SCHEME, self.vault, self.item)?;
        if let Some(section) = &self.section {
            write!(f, "/{section}")?;
        }
        write!(f, "/{}", self.field)?;
        if self.attribute != Attribute::Value {
            write!(f, "?attribute={}", self.attribute.as_str())?;
        }
        Ok(())
    }
}

/// 段（vault/item/section/field）允许的字符：字母数字与 `-` `_` `.`。
fn is_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// 段必须非空且只含合法字符。
fn validate_segment(segment: &str, input: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(Error::usage(format!("empty segment in '{input}'")));
    }
    if let Some(bad) = segment.chars().find(|c| !is_segment_char(*c)) {
        return Err(Error::usage(format!(
            "invalid character '{bad}' in segment '{segment}' of '{input}'"
        )));
    }
    Ok(())
}

/// 解析 `?attribute=a&attribute=b`。参数名未知、取值未知、缺 `=` → `usage`。
fn parse_query(query: &str, input: &str) -> Result<Attribute> {
    if query.is_empty() {
        return Err(Error::usage(format!("empty query in '{input}'")));
    }
    let mut attribute = Attribute::Value;
    for param in query.split('&') {
        let (key, value) = param.split_once('=').ok_or_else(|| {
            Error::usage(format!(
                "malformed query parameter '{param}' in '{input}'; expected key=value"
            ))
        })?;
        if !key.eq_ignore_ascii_case("attribute") {
            return Err(Error::usage(format!(
                "unknown query parameter '{key}' in '{input}'; only 'attribute' is supported"
            )));
        }
        attribute = Attribute::parse_value(value)?;
    }
    Ok(attribute)
}

/// `$` 之后变量名（`[A-Za-z_][A-Za-z0-9_]*`）的字节长度；0 表示不是变量。
fn var_name_len(tail: &str) -> usize {
    let mut len = 0;
    for (i, c) in tail.char_indices() {
        let ok = if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        };
        if !ok {
            break;
        }
        len = i + c.len_utf8();
    }
    len
}

/// 展开 `$VAR`。未定义 → `usage` 且点名该变量；`$` 后不是变量名则原样保留
/// （随后会被段字符校验拒绝）。
fn expand_vars(input: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find('$') {
        out.push_str(&rest[..idx]);
        let tail = &rest[idx + 1..];
        let len = var_name_len(tail);
        if len == 0 {
            out.push('$');
            rest = tail;
            continue;
        }
        let name = &tail[..len];
        let value = env(name).ok_or_else(|| {
            Error::usage(format!("undefined variable '{name}' in reference '{input}'"))
        })?;
        out.push_str(&value);
        rest = &tail[len..];
    }
    out.push_str(rest);
    Ok(out)
}

/// 在条目内定位字段。名字大小写不敏感；跨 section 重名 → `ambiguous`。
pub fn find_field<'a>(entry: &'a Entry, reference: &Reference) -> Result<&'a Field> {
    let section = reference.section.as_deref();
    let hit = |field: &Field| {
        if let Some(want) = section {
            match field.section.as_deref() {
                Some(have) if have.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        field.id.eq_ignore_ascii_case(&reference.field)
            || field.label.eq_ignore_ascii_case(&reference.field)
            || slug(&field.label).eq_ignore_ascii_case(&reference.field)
    };

    let hits: Vec<&Field> = entry.fields.iter().filter(|f| hit(f)).collect();
    match hits.len() {
        0 => Err(Error::not_found(match section {
            Some(section) => format!(
                "no field '{}' in section '{section}' of entry '{}'",
                reference.field, entry.name
            ),
            None => format!("no field '{}' in entry '{}'", reference.field, entry.name),
        })),
        1 => Ok(hits[0]),
        n => Err(Error::Ambiguous(format!(
            "'{}' matches {n} fields in entry '{}'; qualify with a section",
            reference.field, entry.name
        ))),
    }
}

/// 求值。`attribute != Value` 时返回的是元数据（非秘密）。
pub fn resolve(
    vault: &Vault,
    reference: &Reference,
    now: DateTime<Utc>,
) -> Result<Zeroizing<String>> {
    let entry = vault.find(&reference.item)?;
    match reference.attribute {
        Attribute::Id => Ok(Zeroizing::new(entry.id.to_string())),
        Attribute::Title => Ok(Zeroizing::new(
            entry.title.clone().unwrap_or_else(|| entry.name.clone()),
        )),
        Attribute::Type => {
            let field = find_field(entry, reference)?;
            Ok(Zeroizing::new(field.ty.as_str().to_string()))
        }
        Attribute::Value => {
            let field = find_field(entry, reference)?;
            Ok(Zeroizing::new(field.value().to_string()))
        }
        Attribute::Otp => {
            let field = find_field(entry, reference)?;
            let code = totp_at(field.value(), field.label.as_str(), now)?;
            Ok(Zeroizing::new(code))
        }
    }
}

/// 用字段值里的 `otpauth://` URI 现算 TOTP。
///
/// 用 `Totp::generate(secs)` 而不是 `generate_current()`：`totp-rs` 6.0.0 的
/// `generate_current` 需要 `std` feature（本仓库按 `default-features = false` 引入），
/// 且显式时间让测试可以确定性断言。
fn totp_at(value: &str, label: &str, now: DateTime<Utc>) -> Result<String> {
    // 出错时不回显字段值：它就是秘密（URI 里带 base32 secret）。
    let totp = totp_rs::Totp::from_url(value)
        .map_err(|_| Error::usage(format!("field '{label}' is not a valid otpauth:// URI")))?;
    let seconds = u64::try_from(now.timestamp()).map_err(|_| {
        Error::crypto("cannot generate a TOTP for a timestamp before the unix epoch")
    })?;
    Ok(totp.generate(seconds).to_string())
}

/// 从任意文本（env 文件、配置模板）里扫出全部引用原文，供 `run` / `inject` 使用。
///
/// 扫描在空白或集合外字符处停止——带空格的引用需由调用方加引号。
pub fn extract_references(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find(SCHEME) {
        let start = cursor + offset;
        let after = start + SCHEME.len();
        let tail = &text[after..];

        let mut len = 0;
        for (i, c) in tail.char_indices() {
            let allowed = c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | '?' | '&' | '=' | '$' | '%' | ':');
            if !allowed {
                break;
            }
            len = i + c.len_utf8();
        }

        // 光秃秃的 `akey://`（后面没有任何引用字符，如文档里写法）不算引用。
        if len == 0 {
            cursor = after;
            continue;
        }
        out.push(text[start..after + len].to_string());
        cursor = after + len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{Category, FieldType};
    use ulid::Ulid;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("timestamp in range")
    }

    fn make_id(tag: u8) -> Ulid {
        Ulid::from_bytes([tag; 16])
    }

    fn field(label: &str, ty: FieldType, value: &str, section: Option<&str>) -> Field {
        let mut f = Field::new(label, ty, value.to_string());
        f.section = section.map(str::to_string);
        f
    }

    /// RFC 6238 附录 B 的测试密钥（ASCII "12345678901234567890" 的 base32）。
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn otp_uri(digits: u8) -> String {
        format!("otpauth://totp/Acme:alice?secret={RFC_SECRET}&digits={digits}&algorithm=SHA1&period=30")
    }

    struct Fixture {
        vault: Vault,
        openai: Ulid,
        acme: Ulid,
    }

    fn fixture() -> Fixture {
        let now = ts(1_700_000_000);
        let openai = make_id(1);
        let acme = make_id(2);

        let mut o = Entry::new(openai, "openai".to_string(), Category::Apikey, now);
        o.title = Some("OpenAI".to_string());
        o.fields
            .push(field("credential", FieldType::Concealed, "sk-live-123", None));
        o.fields.push(field("Org", FieldType::String, "org-acme", None));
        o.fields
            .push(field("Private Key", FieldType::SshKey, "ssh-rsa AAAA", None));

        let mut a = Entry::new(acme, "acme".to_string(), Category::Login, now);
        a.fields
            .push(field("password", FieldType::Concealed, "prod-pw", Some("Prod")));
        a.fields
            .push(field("password", FieldType::Concealed, "dev-pw", Some("Dev")));
        a.fields
            .push(field("otp", FieldType::Otp, &otp_uri(8), None));
        a.fields
            .push(field("otp6", FieldType::Otp, &otp_uri(6), None));
        a.fields
            .push(field("broken", FieldType::Concealed, "not-an-otpauth-uri", None));

        let mut vault = Vault::default();
        vault.entries.insert(openai, o);
        vault.entries.insert(acme, a);
        Fixture {
            vault,
            openai,
            acme,
        }
    }

    fn parse_err(input: &str) -> Error {
        match Reference::parse(input) {
            Ok(reference) => panic!("'{input}' unexpectedly parsed as {reference}"),
            Err(e) => e,
        }
    }

    #[test]
    fn parse_table_accepts_valid_forms() {
        let cases: Vec<(&str, Reference)> = vec![
            (
                "akey://openai/credential",
                Reference {
                    vault: "default".into(),
                    item: "openai".into(),
                    section: None,
                    field: "credential".into(),
                    attribute: Attribute::Value,
                },
            ),
            (
                "akey://default/openai/credential",
                Reference {
                    vault: "default".into(),
                    item: "openai".into(),
                    section: None,
                    field: "credential".into(),
                    attribute: Attribute::Value,
                },
            ),
            (
                "akey://vault-1/openai/Team/org",
                Reference {
                    vault: "vault-1".into(),
                    item: "openai".into(),
                    section: Some("Team".into()),
                    field: "org".into(),
                    attribute: Attribute::Value,
                },
            ),
            (
                // 段保留原文大小写，匹配时才不区分
                "AKEY://OpenAI/Credential",
                Reference {
                    vault: "default".into(),
                    item: "OpenAI".into(),
                    section: None,
                    field: "Credential".into(),
                    attribute: Attribute::Value,
                },
            ),
            (
                "akey://default/openai/credential?attribute=otp",
                Reference {
                    vault: "default".into(),
                    item: "openai".into(),
                    section: None,
                    field: "credential".into(),
                    attribute: Attribute::Otp,
                },
            ),
            (
                "akey://default/openai/credential?ATTRIBUTE=Title",
                Reference {
                    vault: "default".into(),
                    item: "openai".into(),
                    section: None,
                    field: "credential".into(),
                    attribute: Attribute::Title,
                },
            ),
            (
                "akey://default/openai/credential?attribute=id",
                Reference {
                    vault: "default".into(),
                    item: "openai".into(),
                    section: None,
                    field: "credential".into(),
                    attribute: Attribute::Id,
                },
            ),
            (
                "akey://default/openai/credential?attribute=type",
                Reference {
                    vault: "default".into(),
                    item: "openai".into(),
                    section: None,
                    field: "credential".into(),
                    attribute: Attribute::Type,
                },
            ),
        ];

        for (input, want) in cases {
            let got = Reference::parse(input).unwrap_or_else(|e| panic!("'{input}': {e}"));
            assert_eq!(got, want, "input '{input}'");
        }
    }

    #[test]
    fn parse_table_rejects_invalid_forms() {
        let cases: &[&str] = &[
            "",
            "akey://",
            "akey://openai",
            "akey://a/b/c/d/e",
            "http://openai/credential",
            "akey:/openai/credential",
            "akey://open ai/credential",
            "akey://openai/cred$ential",
            "akey://openai//credential",
            "akey://openai/credential/",
            "akey://openai/cre~dential",
            "akey://$APP_ENV/credential",
            "akey://openai/credential?",
            "akey://openai/credential?attribute",
            "akey://openai/credential?attribute=",
            "akey://openai/credential?attribute=secret",
            "akey://openai/credential?foo=bar",
            "akey://openai/credential?attribute=value&ssh-format=openssh",
        ];

        for input in cases {
            let e = parse_err(input);
            assert!(
                matches!(&e, Error::Usage(_)),
                "'{input}' should be usage, got {e:?}"
            );
            assert_eq!(e.code(), "usage", "input '{input}'");
            assert_eq!(e.exit_code(), 2, "input '{input}'");
        }
    }

    #[test]
    fn parse_in_expands_variables() {
        let env = |name: &str| match name {
            "APP_ENV" => Some("prod".to_string()),
            "ITEM" => Some("OpenAI".to_string()),
            _ => None,
        };

        let got = Reference::parse_in("akey://$APP_ENV/$ITEM/credential", &env).expect("expands");
        assert_eq!(got.vault, "prod");
        assert_eq!(got.item, "OpenAI");
        assert_eq!(got.field, "credential");

        // 展开发生在解析之前，因此展开结果可以出现在任意段。
        let got = Reference::parse_in("akey://$ITEM/credential?attribute=otp", &env)
            .expect("expands");
        assert_eq!(got.item, "OpenAI");
        assert_eq!(got.field, "credential");
        assert_eq!(got.attribute, Attribute::Otp);

        let e = Reference::parse_in("akey://$APP_ENV/db/password", &|_| None)
            .err()
            .expect("undefined variable must fail");
        assert!(matches!(&e, Error::Usage(_)), "got {e:?}");
        assert!(
            e.to_string().contains("APP_ENV"),
            "message must name the variable: {e}"
        );
        assert_eq!(e.exit_code(), 2);

        // `$` 后面不是变量名：保留 `$`，随后被判为非法字符。
        let e = Reference::parse_in("akey://db/pw$", &|_| None).err().expect("$ stays");
        assert!(matches!(&e, Error::Usage(_)), "got {e:?}");
    }

    #[test]
    fn display_round_trips_canonical_form() {
        let canonical = [
            "akey://default/openai/credential",
            "akey://default/openai/Team/org",
            "akey://default/openai/credential?attribute=otp",
            "akey://default/openai/credential?attribute=title",
            "akey://prod/acme/prod/password",
        ];
        for input in canonical {
            let got = Reference::parse(input).expect(input).to_string();
            assert_eq!(got, input, "round trip of '{input}'");
        }

        // 省略 vault 的写法被补全为规范形式。
        assert_eq!(
            Reference::parse("akey://db/password").expect("parses").to_string(),
            "akey://default/db/password"
        );
        // `attribute=value` 是默认值，规范形式里省略。
        assert_eq!(
            Reference::parse("akey://default/db/password?attribute=value")
                .expect("parses")
                .to_string(),
            "akey://default/db/password"
        );
    }

    #[test]
    fn find_field_is_section_scoped() {
        let f = fixture();
        let acme = &f.vault.entries[&f.acme];

        // 跨 section 同名 → ambiguous。
        let reference = Reference::parse("akey://acme/password").expect("parses");
        let e = find_field(acme, &reference).err().expect("ambiguous");
        assert!(matches!(&e, Error::Ambiguous(_)), "got {e:?}");
        assert_eq!(e.code(), "ambiguous");
        assert_eq!(e.exit_code(), 3);

        // 指定 section 后唯一；section 名大小写不敏感。
        for (input, want) in [
            ("akey://default/acme/Prod/password", "prod-pw"),
            ("akey://default/acme/dev/PASSWORD", "dev-pw"),
        ] {
            let reference = Reference::parse(input).expect(input);
            assert_eq!(find_field(acme, &reference).expect(input).value(), want);
        }

        // section 不存在、字段不存在 → not_found。
        for input in [
            "akey://default/acme/staging/password",
            "akey://acme/credential",
            "akey://acme/nosuchfield",
        ] {
            let reference = Reference::parse(input).expect(input);
            let e = find_field(acme, &reference).err().expect("not found");
            assert!(matches!(&e, Error::NotFound(_)), "'{input}' got {e:?}");
            assert_eq!(e.exit_code(), 3, "input '{input}'");
        }
    }

    #[test]
    fn find_field_matches_slug_and_label_case_insensitively() {
        let f = fixture();
        let openai = &f.vault.entries[&f.openai];

        for input in [
            "akey://openai/credential",
            "akey://openai/CREDENTIAL",
            "akey://openai/Credential",
        ] {
            let reference = Reference::parse(input).expect(input);
            assert_eq!(find_field(openai, &reference).expect(input).id, "credential");
        }

        // `private-key` 是 "Private Key" 的 slug：带空格的 label 只能这样引用。
        for input in ["akey://openai/private-key", "akey://openai/PRIVATE-KEY"] {
            let reference = Reference::parse(input).expect(input);
            assert_eq!(find_field(openai, &reference).expect(input).label, "Private Key");
        }

        // label 大小写不敏感。
        let reference = Reference::parse("akey://openai/ORG").expect("parses");
        assert_eq!(find_field(openai, &reference).expect("hits").value(), "org-acme");
    }

    #[test]
    fn resolve_returns_each_attribute() {
        let f = fixture();
        let now = ts(1_700_000_000);
        let resolve_str = |input: &str| {
            let reference = Reference::parse(input).expect(input);
            resolve(&f.vault, &reference, now)
                .unwrap_or_else(|e| panic!("'{input}': {e}"))
                .to_string()
        };

        assert_eq!(resolve_str("akey://openai/credential"), "sk-live-123");
        assert_eq!(resolve_str("akey://default/acme/prod/password"), "prod-pw");

        assert_eq!(resolve_str("akey://openai/credential?attribute=title"), "OpenAI");
        // 没有 title 时回落到条目名。
        assert_eq!(resolve_str("akey://acme/password?attribute=title"), "acme");

        assert_eq!(resolve_str("akey://openai/credential?attribute=type"), "concealed");
        assert_eq!(resolve_str("akey://openai/org?attribute=type"), "string");

        let id = resolve_str("akey://openai/credential?attribute=id");
        assert_eq!(id, f.openai.to_string());
        assert_eq!(id.len(), 26);
        // 元数据查询不需要字段存在。
        assert_eq!(resolve_str("akey://openai/nosuchfield?attribute=id"), id);

        // 名字与 ID 都能命中同一条目。
        assert_eq!(
            resolve_str(&format!("akey://{}/credential", f.openai)),
            "sk-live-123"
        );

        // 条目不存在 → not_found（复用 Vault::find 的错误）。
        let reference = Reference::parse("akey://nosuchitem/credential").expect("parses");
        let e = resolve(&f.vault, &reference, now).err().expect("not found");
        assert!(matches!(&e, Error::NotFound(_)), "got {e:?}");
        assert_eq!(e.exit_code(), 3);
    }

    #[test]
    fn resolve_otp_matches_rfc6238_vectors() {
        let f = fixture();
        let reference = Reference::parse("akey://acme/otp?attribute=otp").expect("parses");

        // RFC 6238 附录 B：T = 59（SHA-1）→ 94287082。
        assert_eq!(
            resolve(&f.vault, &reference, ts(59))
                .expect("generates")
                .to_string(),
            "94287082"
        );
        // 同一时间窗（T = 60 落在 step 1）→ 仍与 T = 59 无关的另一个稳定值。
        assert_eq!(
            resolve(&f.vault, &reference, ts(1111111109))
                .expect("generates")
                .to_string(),
            "07081804"
        );

        // 6 位变体：RFC 6238 同密钥同时间截断到 6 位 → 287082。
        let six = Reference::parse("akey://acme/otp6?attribute=otp").expect("parses");
        let code = resolve(&f.vault, &six, ts(59)).expect("generates").to_string();
        assert_eq!(code, "287082");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn resolve_otp_rejects_non_otpauth_values_without_leaking_them() {
        let f = fixture();
        let reference = Reference::parse("akey://acme/broken?attribute=otp").expect("parses");
        let e = resolve(&f.vault, &reference, ts(0)).err().expect("usage");
        assert!(matches!(&e, Error::Usage(_)), "got {e:?}");
        assert_eq!(e.exit_code(), 2);
        let msg = e.to_string();
        assert!(!msg.contains("not-an-otpauth-uri"), "leaked value: {msg}");
    }

    #[test]
    fn extract_references_scans_arbitrary_text() {
        let text = "\"akey://openai/credential\" and (akey://default/acme/Prod/password?attribute=otp)\n\
                    ZONE=akey://$APP_ENV/db/password\n\
                    PLAIN=no-refs-here";
        assert_eq!(
            extract_references(text),
            vec![
                "akey://openai/credential".to_string(),
                "akey://default/acme/Prod/password?attribute=otp".to_string(),
                "akey://$APP_ENV/db/password".to_string(),
            ]
        );

        // 行尾无分隔符（无尾随换行）也能吃满。
        assert_eq!(
            extract_references("TOKEN=akey://openai/credential"),
            vec!["akey://openai/credential".to_string()]
        );

        // 没有引用（含只有 scheme 的文档写法）→ 空。
        assert_eq!(extract_references(""), Vec::<String>::new());
        assert_eq!(extract_references("nothing to see here"), Vec::<String>::new());
        assert_eq!(
            extract_references("see akey://[vault/]item/field for details"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn resolve_by_id_reference_addresses_the_same_entry() {
        let f = fixture();
        let input = format!("akey://{}/credential", f.openai);
        let reference = Reference::parse(&input).expect("parses");
        assert_eq!(reference.item, f.openai.to_string());
        // Display 输出规范形式：省略的 vault 被补成 `default`。
        assert_eq!(
            reference.to_string(),
            format!("akey://default/{}/credential", f.openai)
        );

        assert_eq!(
            resolve(&f.vault, &reference, ts(0)).expect("resolves").to_string(),
            "sk-live-123"
        );
    }
}

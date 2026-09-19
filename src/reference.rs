//! `akey://` references: name a secret by its **name** rather than its plaintext.
//!
//! The grammar is in `REQUIREMENTS.md` §12.3. This module only addresses and fetches values;
//! it makes no exposure-policy decision (policy belongs to the `cmd` layer), so callers must handle its output with care.

use std::fmt;

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::vault::model::{DEFAULT_VAULT, Entry, Field, Vault, slug};

pub const SCHEME: &str = "akey://";

/// Reference metadata query parameter (`?attribute=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Attribute {
    /// The field value itself.
    #[default]
    Value,
    /// A TOTP computed on the fly from an `otp` field (6 digits, 30-second window).
    Otp,
    /// The entry title.
    Title,
    /// The field type.
    Type,
    /// The entry ID.
    Id,
}

impl Attribute {
    /// Canonical values of `attribute=` in a query.
    pub fn as_str(self) -> &'static str {
        match self {
            Attribute::Value => "value",
            Attribute::Otp => "otp",
            Attribute::Title => "title",
            Attribute::Type => "type",
            Attribute::Id => "id",
        }
    }

    /// Parse an `attribute=` value; case-insensitive, with an unknown value → `usage`.
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
    /// Parse without variable expansion.
    pub fn parse(input: &str) -> Result<Reference> {
        Reference::parse_plain(input)
    }

    /// Parse after expanding `$VAR` through `env`. An undefined variable → `usage`.
    pub fn parse_in(input: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Reference> {
        let expanded = expand_vars(input, env)?;
        Reference::parse_plain(&expanded)
    }

    /// Plain parse of the expanded input: segment count, character set, query grammar.
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
    /// Canonical form: `akey://vault/item[/section]/field[?attribute=…]`, with `attribute=value` omitted.
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

/// Characters a segment (vault/item/section/field) may hold: alphanumerics plus `-` `_` `.`.
fn is_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// A segment must be non-empty and hold only legal characters.
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

/// Parse `?attribute=a&attribute=b`. An unknown parameter name, an unknown value, or a missing `=` → `usage`.
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

/// Byte length of the variable name (`[A-Za-z_][A-Za-z0-9_]*`) after `$`; 0 means it is not a variable.
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

/// Expand `$VAR`. Undefined → `usage` naming that variable; when no variable name follows
/// the `$`, it is kept verbatim (and the segment-character check rejects it afterwards).
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

/// Locate a field inside an entry. Names are case-insensitive; one name across sections → `ambiguous`.
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

/// Resolve. When `attribute != Value` the result is metadata (not a secret).
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

/// Compute a TOTP on the fly from the `otpauth://` URI in a field value.
///
/// We call `Totp::generate(secs)` rather than `generate_current()`: in `totp-rs` 6.0.0
/// `generate_current` needs the `std` feature (this crate pulls it in with `default-features = false`),
/// and an explicit time lets tests assert deterministically.
fn totp_at(value: &str, label: &str, now: DateTime<Utc>) -> Result<String> {
    // Do not echo the field value on error: it is the secret (the URI carries the base32 secret).
    let totp = totp_rs::Totp::from_url(value)
        .map_err(|_| Error::usage(format!("field '{label}' is not a valid otpauth:// URI")))?;
    let seconds = u64::try_from(now.timestamp()).map_err(|_| {
        Error::crypto("cannot generate a TOTP for a timestamp before the unix epoch")
    })?;
    Ok(totp.generate(seconds).to_string())
}

/// Scan arbitrary text (an env file, a config template) for every reference written out in full, for `run` / `inject` to use.
///
/// The scan stops at whitespace or a character outside the set — a reference containing a space has to be quoted by the caller.
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

        // A bare `akey://` (no reference characters after it, the way the docs write it) is not a reference.
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

    /// The test secret from RFC 6238 Appendix B (base32 of the ASCII "12345678901234567890").
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
                // Segments keep their original case; only matching is case-insensitive
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

        // Expansion happens before parsing, so an expanded value may appear in any segment.
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

        // What follows `$` is not a variable name: the `$` is kept and then judged an illegal character.
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

        // The vault-less spelling is completed into the canonical form.
        assert_eq!(
            Reference::parse("akey://db/password").expect("parses").to_string(),
            "akey://default/db/password"
        );
        // `attribute=value` is the default and is omitted from the canonical form.
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

        // The same name across sections → ambiguous.
        let reference = Reference::parse("akey://acme/password").expect("parses");
        let e = find_field(acme, &reference).err().expect("ambiguous");
        assert!(matches!(&e, Error::Ambiguous(_)), "got {e:?}");
        assert_eq!(e.code(), "ambiguous");
        assert_eq!(e.exit_code(), 3);

        // Unique once a section is named; section names are case-insensitive.
        for (input, want) in [
            ("akey://default/acme/Prod/password", "prod-pw"),
            ("akey://default/acme/dev/PASSWORD", "dev-pw"),
        ] {
            let reference = Reference::parse(input).expect(input);
            assert_eq!(find_field(acme, &reference).expect(input).value(), want);
        }

        // No such section, no such field → not_found.
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

        // `private-key` is the slug of "Private Key": a label with spaces can only be referenced this way.
        for input in ["akey://openai/private-key", "akey://openai/PRIVATE-KEY"] {
            let reference = Reference::parse(input).expect(input);
            assert_eq!(find_field(openai, &reference).expect(input).label, "Private Key");
        }

        // Label matching is case-insensitive.
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
        // With no title it falls back to the entry name.
        assert_eq!(resolve_str("akey://acme/password?attribute=title"), "acme");

        assert_eq!(resolve_str("akey://openai/credential?attribute=type"), "concealed");
        assert_eq!(resolve_str("akey://openai/org?attribute=type"), "string");

        let id = resolve_str("akey://openai/credential?attribute=id");
        assert_eq!(id, f.openai.to_string());
        assert_eq!(id.len(), 26);
        // A metadata query does not require the field to exist.
        assert_eq!(resolve_str("akey://openai/nosuchfield?attribute=id"), id);

        // Both the name and the ID hit the same entry.
        assert_eq!(
            resolve_str(&format!("akey://{}/credential", f.openai)),
            "sk-live-123"
        );

        // No such entry → not_found (reusing `Vault::find`'s error).
        let reference = Reference::parse("akey://nosuchitem/credential").expect("parses");
        let e = resolve(&f.vault, &reference, now).err().expect("not found");
        assert!(matches!(&e, Error::NotFound(_)), "got {e:?}");
        assert_eq!(e.exit_code(), 3);
    }

    #[test]
    fn resolve_otp_matches_rfc6238_vectors() {
        let f = fixture();
        let reference = Reference::parse("akey://acme/otp?attribute=otp").expect("parses");

        // RFC 6238 Appendix B: T = 59 (SHA-1) → 94287082.
        assert_eq!(
            resolve(&f.vault, &reference, ts(59))
                .expect("generates")
                .to_string(),
            "94287082"
        );
        // Same time window (T = 60 falls in step 1) → another stable value, independent of T = 59.
        assert_eq!(
            resolve(&f.vault, &reference, ts(1111111109))
                .expect("generates")
                .to_string(),
            "07081804"
        );

        // The 6-digit variant: the same secret and time as RFC 6238, truncated to 6 digits → 287082.
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

        // A line end with no separator (no trailing newline) still consumes the whole reference.
        assert_eq!(
            extract_references("TOKEN=akey://openai/credential"),
            vec!["akey://openai/credential".to_string()]
        );

        // No reference (including the scheme-only spelling from the docs) → empty.
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
        // Display prints the canonical form: the omitted vault is filled in as `default`.
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

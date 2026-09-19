//! 金库数据模型。
//!
//! 这里是**密文内**的数据形状——`vault.age` 解密后就是 `Vault` 的 JSON。
//! 合并、引用、命令三层都依赖本模块，改动波及面最大。

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const FORMAT_VERSION: u32 = 1;
pub const DEFAULT_VAULT: &str = "default";
pub const MAX_NAME_LEN: usize = 64;

/// 条目名的合法字符集：小写字母数字开头，其余允许 `a-z0-9._-`。
///
/// 冲突副本名形如 `<name>.conflict.<tag>`，落在同一字符集内。
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().expect("checked non-empty");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// 字段标签 → 稳定 slug（引用里的 `field` 段）。
pub fn slug(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        match c {
            'a'..='z' | '0'..='9' | '-' | '_' | '.' => out.push(c),
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            _ => out.push('-'),
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    pub vault: String,
    #[serde(default)]
    pub entries: BTreeMap<Ulid, Entry>,
    #[serde(default)]
    pub tokens: BTreeMap<Ulid, TokenMeta>,
    /// 永久删除的墓碑：防止对端同步时把已 purge 的条目复活。
    #[serde(default)]
    pub purged: BTreeMap<Ulid, DateTime<Utc>>,
}

impl Default for Vault {
    fn default() -> Self {
        Vault {
            version: FORMAT_VERSION,
            vault: DEFAULT_VAULT.to_string(),
            entries: BTreeMap::new(),
            tokens: BTreeMap::new(),
            purged: BTreeMap::new(),
        }
    }
}

impl Vault {
    /// 按 ID 或名字查条目。ID 优先，其次精确名，最后大小写不敏感名。
    pub fn find(&self, key: &str) -> Result<&Entry> {
        if let Ok(id) = Ulid::from_string(key)
            && let Some(entry) = self.entries.get(&id)
        {
            return Ok(entry);
        }
        if let Some(entry) = self.entries.values().find(|e| e.name == key) {
            return Ok(entry);
        }
        let hits: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.name.eq_ignore_ascii_case(key))
            .collect();
        match hits.len() {
            0 => Err(Error::not_found(format!("no entry named '{key}'"))),
            1 => Ok(hits[0]),
            _ => Err(Error::Ambiguous(format!(
                "'{key}' matches {} entries; use the ID",
                hits.len()
            ))),
        }
    }

    /// 名字是否已被占用（含已软删条目，避免恢复时撞名）。
    pub fn name_taken(&self, name: &str, except: Ulid) -> bool {
        self.entries
            .values()
            .any(|e| e.id != except && e.name == name)
    }

    pub fn live_entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values().filter(|e| !e.is_deleted())
    }

    pub fn find_token(&self, name: &str) -> Result<&TokenMeta> {
        let mut hits = self.tokens.values().filter(|t| t.name == name);
        let first = hits
            .next()
            .ok_or_else(|| Error::not_found(format!("no token named '{name}'")))?;
        if hits.next().is_some() {
            return Err(Error::Ambiguous(format!("multiple tokens named '{name}'")));
        }
        Ok(first)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Ulid,
    pub name: String,
    pub category: Category,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub reveal: Reveal,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// 软删标记。合并时它是普通字段——"一边删一边改"因此不会被静默丢弃。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Entry {
    pub fn new(id: Ulid, name: String, category: Category, now: DateTime<Utc>) -> Self {
        Entry {
            id,
            name,
            category,
            title: None,
            fields: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            url: None,
            notes: None,
            expires_at: None,
            reveal: Reveal::default(),
            created_at: now,
            updated_at: now,
            rotated_at: None,
            last_used_at: None,
            deleted_at: None,
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    pub fn field(&self, label: &str) -> Option<&Field> {
        let slug = slug(label);
        self.fields
            .iter()
            .find(|f| f.id == slug || f.id == label || f.label.eq_ignore_ascii_case(label))
    }

    pub fn field_mut(&mut self, label: &str) -> Option<&mut Field> {
        let slug = slug(label);
        self.fields
            .iter_mut()
            .find(|f| f.id == slug || f.id == label || f.label.eq_ignore_ascii_case(label))
    }

    /// 全部字段值的顺序无关哈希。用于让冲突副本 ID 可复现（见 DESIGN §9）。
    pub fn value_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut rows: Vec<(&str, &str)> = self
            .fields
            .iter()
            .map(|f| (f.id.as_str(), f.value.as_str()))
            .collect();
        rows.sort_unstable();
        for (id, value) in rows {
            hasher.update(id.as_bytes());
            hasher.update([0]);
            hasher.update(value.as_bytes());
            hasher.update([0xff]);
        }
        hasher.update(self.name.as_bytes());
        hasher.finalize().into()
    }

    /// 最近使用时间：`last_used_at` 与 `updated_at` 取较新者。
    pub fn latest_activity(&self) -> DateTime<Utc> {
        match self.last_used_at {
            Some(used) if used > self.updated_at => used,
            _ => self.updated_at,
        }
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("category", &self.category)
            .field("fields", &self.fields)
            .field("tags", &self.tags)
            .field("updated_at", &self.updated_at)
            .field("deleted_at", &self.deleted_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// 稳定 slug，引用中使用的名字。
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(rename = "type")]
    pub ty: FieldType,
    pub value: Zeroizing<String>,
}

impl Field {
    pub fn new(label: &str, ty: FieldType, value: String) -> Self {
        Field {
            id: slug(label),
            label: label.to_string(),
            section: None,
            ty,
            value: Zeroizing::new(value),
        }
    }

    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    /// 交付给调用者前是否必须显式 `--reveal`。
    pub fn is_concealed(&self) -> bool {
        self.ty.is_concealed()
    }

    /// 人类可读展示值。
    pub fn display_value(&self, reveal: bool) -> String {
        if self.is_concealed() && !reveal {
            crate::output::REDACTED.to_string()
        } else {
            self.value.to_string()
        }
    }
}

impl fmt::Debug for Field {
    /// 值永不出现在 Debug 中——避免任何 `{:?}` 泄漏密钥。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("section", &self.section)
            .field("type", &self.ty)
            .field("value", &self.display_value(false))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Apikey,
    Login,
    Token,
    Database,
    SshKey,
    SecureNote,
    EnvBundle,
}

impl Category {
    /// 新建条目时的内置字段骨架。
    pub fn builtin_fields(self) -> &'static [(&'static str, FieldType)] {
        use FieldType::*;
        match self {
            Category::Apikey => &[("credential", Concealed), ("url", Url)],
            Category::Login => &[
                ("username", String),
                ("password", Concealed),
                ("url", Url),
            ],
            Category::Token => &[("token", Concealed), ("scopes", String)],
            Category::Database => &[
                ("host", String),
                ("port", Number),
                ("database", String),
                ("username", String),
                ("password", Concealed),
            ],
            Category::SshKey => &[("private key", SshKey), ("public key", String)],
            Category::SecureNote => &[("notes", Notes)],
            Category::EnvBundle => &[],
        }
    }

    /// 默认的"秘密字段"，用于 `--stdin` 时决定取哪个值。
    pub fn default_secret_field(self) -> &'static str {
        match self {
            Category::Apikey => "credential",
            Category::Login => "password",
            Category::Token => "token",
            Category::Database => "password",
            Category::SshKey => "private key",
            Category::SecureNote => "notes",
            Category::EnvBundle => "",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Apikey => "apikey",
            Category::Login => "login",
            Category::Token => "token",
            Category::Database => "database",
            Category::SshKey => "ssh-key",
            Category::SecureNote => "secure-note",
            Category::EnvBundle => "env-bundle",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum FieldType {
    String,
    Concealed,
    Email,
    Url,
    Otp,
    Date,
    Number,
    File,
    SshKey,
    Notes,
}

impl FieldType {
    pub fn is_concealed(self) -> bool {
        matches!(self, FieldType::Concealed | FieldType::Notes | FieldType::SshKey)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FieldType::String => "string",
            FieldType::Concealed => "concealed",
            FieldType::Email => "email",
            FieldType::Url => "url",
            FieldType::Otp => "otp",
            FieldType::Date => "date",
            FieldType::Number => "number",
            FieldType::File => "file",
            FieldType::SshKey => "ssh-key",
            FieldType::Notes => "notes",
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reveal {
    #[default]
    Allow,
    Deny,
}

impl Reveal {
    pub fn as_str(self) -> &'static str {
        match self {
            Reveal::Allow => "allow",
            Reveal::Deny => "deny",
        }
    }
}

/// 能力令牌的公开元数据。明文只在签发那一刻回显一次。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMeta {
    pub id: Ulid,
    pub name: String,
    /// `base64(sha256(token))`。明文不可恢复。
    pub hash: Zeroizing<String>,
    /// `None` = 允许全部条目（仍受 `deny_reveal` 与 `expires_at` 约束）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deny_reveal: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl TokenMeta {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|exp| exp > now)
    }

    /// 该令牌是否有权访问此条目。
    pub fn permits(&self, entry_name: &str) -> bool {
        match &self.allow {
            None => true,
            Some(list) => list.iter().any(|n| n == entry_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation_accepts_and_rejects_expected_forms() {
        for good in ["openai", "a", "a.b_c-d", "0start", "openai.conflict.9f2a"] {
            assert!(is_valid_name(good), "{good} should be valid");
        }
        for bad in ["", "OpenAI", "-lead", ".lead", "has space", "a/b", "a@b"] {
            assert!(!is_valid_name(bad), "{bad} should be invalid");
        }
        assert!(!is_valid_name(&"a".repeat(MAX_NAME_LEN + 1)));
    }

    #[test]
    fn slug_normalises_labels() {
        assert_eq!(slug("private key"), "private-key");
        assert_eq!(slug("Access Keys"), "access-keys");
        assert_eq!(slug("one-time password"), "one-time-password");
        assert_eq!(slug("  spaced  "), "spaced");
    }

    #[test]
    fn concealed_types_cover_secret_bearing_fields() {
        assert!(FieldType::Concealed.is_concealed());
        assert!(FieldType::Notes.is_concealed());
        assert!(FieldType::SshKey.is_concealed());
        assert!(!FieldType::String.is_concealed());
        assert!(!FieldType::Url.is_concealed());
        assert!(!FieldType::Otp.is_concealed());
    }

    #[test]
    fn field_debug_never_leaks_value() {
        let f = Field::new("password", FieldType::Concealed, "hunter2".into());
        let rendered = format!("{f:?}");
        assert!(!rendered.contains("hunter2"), "concealed value leaked: {rendered}");
        assert!(rendered.contains(crate::output::REDACTED));
    }

    #[test]
    fn display_value_respects_reveal() {
        let f = Field::new("credential", FieldType::Concealed, "sk-secret".into());
        assert_eq!(f.display_value(false), crate::output::REDACTED);
        assert_eq!(f.display_value(true), "sk-secret");

        let plain = Field::new("username", FieldType::String, "me".into());
        assert_eq!(plain.display_value(false), "me");
    }

    #[test]
    fn value_hash_is_order_independent_but_value_sensitive() {
        let mut a = Entry::new(Ulid::generate(), "x".into(), Category::Apikey, Utc::now());
        a.fields = vec![
            Field::new("a", FieldType::String, "1".into()),
            Field::new("b", FieldType::String, "2".into()),
        ];
        let mut b = a.clone();
        b.fields.reverse();
        assert_eq!(a.value_hash(), b.value_hash(), "order must not matter");

        let mut c = a.clone();
        c.fields[0].value = Zeroizing::new("9".into());
        assert_ne!(a.value_hash(), c.value_hash(), "value must matter");
    }

    #[test]
    fn find_resolves_id_then_exact_name_then_case_insensitive() {
        let now = Utc::now();
        let id = Ulid::generate();
        let mut vault = Vault::default();
        vault
            .entries
            .insert(id, Entry::new(id, "openai".into(), Category::Apikey, now));

        assert_eq!(vault.find("openai").unwrap().id, id);
        assert_eq!(vault.find(&id.to_string()).unwrap().id, id);
        assert_eq!(vault.find("OpenAI").unwrap().id, id);
        assert!(matches!(vault.find("nope"), Err(Error::NotFound(_))));
    }

    #[test]
    fn token_permit_rules() {
        let now = Utc::now();
        let open = TokenMeta {
            id: Ulid::generate(),
            name: "open".into(),
            hash: Zeroizing::new("h".into()),
            allow: None,
            deny_reveal: false,
            expires_at: None,
            created_at: now,
            last_used_at: None,
            revoked_at: None,
        };
        assert!(open.permits("anything"));

        let scoped = TokenMeta {
            allow: Some(vec!["openai".into()]),
            ..open.clone()
        };
        assert!(scoped.permits("openai"));
        assert!(!scoped.permits("anthropic"));

        let expired = TokenMeta {
            expires_at: Some(now - chrono::Duration::seconds(1)),
            ..open.clone()
        };
        assert!(!expired.is_active(now));

        let revoked = TokenMeta {
            revoked_at: Some(now),
            ..open.clone()
        };
        assert!(!revoked.is_active(now));
        assert!(open.is_active(now));
    }

    #[test]
    fn category_builtin_fields_cover_default_secret() {
        for cat in [
            Category::Apikey,
            Category::Login,
            Category::Token,
            Category::Database,
            Category::SshKey,
            Category::SecureNote,
        ] {
            let secret = cat.default_secret_field();
            assert!(
                cat.builtin_fields().iter().any(|(l, _)| *l == secret),
                "{cat} default secret field '{secret}' missing from builtins"
            );
        }
    }

    #[test]
    fn vault_serialises_with_string_keys_and_reads_back() {
        let now = Utc::now();
        let id = Ulid::generate();
        let mut vault = Vault::default();
        vault
            .entries
            .insert(id, Entry::new(id, "openai".into(), Category::Apikey, now));

        let json = serde_json::to_string(&vault).unwrap();
        assert!(json.contains("openai"));
        let back: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(vault, back);
    }
}

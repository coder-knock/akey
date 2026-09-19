//! 能力令牌：对标 1Password service account —— 给 agent / CI 用的最小权限、可吊销凭据。
//!
//! 明文只在签发时回显一次；金库里只留 SHA-256 摘要（见 `DESIGN.md` §5）。
//!
//! **为什么不用 Argon2id**：令牌是 256 位均匀随机值，暴力搜索不可行，慢 KDF 在这里
//! 没有安全收益，却会把每次 `akey run` 拖进几十毫秒。改用 SHA-256 + 常数时间比较。
//! 同理 `TokenMeta` 不含盐字段——盐对预映像攻击无增益。

use base64::Engine;
use chrono::{DateTime, Utc};
use subtle::ConstantTimeEq;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::vault::model::{TokenMeta, is_valid_name};

/// 令牌明文前缀。便于在日志/仓库里被识别与拦截。
pub const TOKEN_PREFIX: &str = "akey_";

/// 令牌明文字节长度（base64url 后 43 字符）。
pub const TOKEN_BYTES: usize = 32;

/// `TOKEN_BYTES` 字节经 base64url（无填充）后的字符数。
///
/// 无填充编码长度 = `ceil(n / 3) * 4 - 填充数`，等价于 `(n * 4 + 2) / 3`。
const TOKEN_BODY_LEN: usize = (TOKEN_BYTES * 4).div_ceil(3);

pub struct IssuedToken {
    /// **只回显一次**，之后不可恢复。
    pub plaintext: String,
    pub meta: TokenMeta,
}

/// 签发：生成随机明文，落库只存 SHA-256 摘要。
pub fn issue(
    name: &str,
    allow: Option<Vec<String>>,
    deny_reveal: bool,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<IssuedToken> {
    if !is_valid_name(name) {
        return Err(Error::Usage(format!("非法令牌名 `{name}`")));
    }
    if let Some(list) = &allow {
        for entry in list {
            if !is_valid_name(entry) {
                return Err(Error::Usage(format!("`--allow` 中的条目名 `{entry}` 非法")));
            }
        }
    }

    let mut buf = [0u8; TOKEN_BYTES];
    // `rand::fill` 只在底层 RNG 报错时 panic，而线程局部 `ThreadRng` 的
    // `TryRng::Error = Infallible`（rand 0.10），故此处不可能 panic。
    rand::fill(&mut buf);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);

    let meta = TokenMeta {
        id: Ulid::generate(),
        name: name.to_string(),
        hash: Zeroizing::new(hash_token(&body)),
        allow,
        deny_reveal,
        expires_at,
        created_at: now,
        last_used_at: None,
        revoked_at: None,
    };

    Ok(IssuedToken {
        plaintext: format!("{TOKEN_PREFIX}{body}"),
        meta,
    })
}

/// 校验候选明文是否匹配该令牌。必须常数时间比较。
///
/// 不匹配 → `locked`（退出码 4）。
pub fn verify(candidate: &str, meta: &TokenMeta) -> Result<()> {
    let body = normalize(candidate)?;
    let digest = hash_token(&body);
    let matches: bool = digest.as_bytes().ct_eq(meta.hash.as_bytes()).into();
    if matches {
        Ok(())
    } else {
        Err(Error::Locked(format!("令牌无效：`{}`", meta.name)))
    }
}

/// 校验令牌当前是否有权访问某条目。
///
/// 已吊销 / 已过期 → `locked`（4）；不在 `allow` 列表 → `token_scope`（8）。
pub fn authorize(meta: &TokenMeta, entry_name: &str, now: DateTime<Utc>) -> Result<()> {
    if meta.revoked_at.is_some() {
        return Err(Error::Locked(format!("令牌 `{}` 已吊销", meta.name)));
    }
    if meta.expires_at.is_some_and(|exp| exp <= now) {
        return Err(Error::Locked(format!("令牌 `{}` 已过期", meta.name)));
    }
    if !meta.permits(entry_name) {
        return Err(Error::TokenScope(format!(
            "令牌 `{}` 无权访问条目 `{entry_name}`",
            meta.name
        )));
    }
    Ok(())
}

/// 从环境变量或 `--token` 中剥掉前缀。形式不符 → `usage`。
///
/// 返回**规范串**：不带前缀的 base64url 令牌体。哈希与比较都基于它。
pub fn normalize(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix(TOKEN_PREFIX).unwrap_or(trimmed);
    if !is_token_body(body) {
        return Err(Error::Usage(
            "令牌格式不对：应为 43 位 base64url 字符，可带 `akey_` 前缀".into(),
        ));
    }
    Ok(body.to_string())
}

/// 令牌体是否为 `TOKEN_BYTES` 字节 base64url 编码后的一个合法串。
fn is_token_body(body: &str) -> bool {
    body.len() == TOKEN_BODY_LEN
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `base64(sha256(token_body))`。摘要本身不是秘密，但仍用 `Zeroizing` 收口。
fn hash_token(body: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(body.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_776_000_000, 0).expect("fixed timestamp is representable")
    }

    fn issue_named(name: &str) -> IssuedToken {
        issue(name, None, false, None, now()).expect("valid name should issue")
    }

    /// `IssuedToken` 故意不实现 `Debug`（内含明文），故手工展开 `Result`。
    fn issue_err(name: &str, allow: Option<Vec<String>>) -> Error {
        match issue(name, allow, false, None, now()) {
            Err(err) => err,
            Ok(_) => panic!("issue should have failed for name {name:?}"),
        }
    }

    /// 把令牌体中间某一位换成另一个**仍在 base64url 字母表内**的字符。
    fn mutate(token: &str) -> String {
        let mut chars: Vec<char> = token.chars().collect();
        let at = chars.len() / 2;
        chars[at] = if chars[at] == 'a' { 'b' } else { 'a' };
        chars.into_iter().collect()
    }

    #[test]
    fn issued_token_verifies_and_wrong_token_is_rejected() {
        let issued = issue_named("ci");
        verify(&issued.plaintext, &issued.meta).expect("fresh token should verify");

        // 带前缀与不带前缀是同一个令牌。
        let body = issued.plaintext.strip_prefix(TOKEN_PREFIX).expect("prefix");
        verify(body, &issued.meta).expect("unprefixed form should verify");

        let bad = mutate(&issued.plaintext);
        assert_ne!(bad, issued.plaintext);
        let err = verify(&bad, &issued.meta).expect_err("mutated token must be rejected");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn malformed_token_is_a_usage_error() {
        let issued = issue_named("ci");
        // 形状不对（空 / 过短 / 过长 / 非 base64url 字符）→ usage。
        for bad in [
            "",
            "akey_",
            "akey_short",
            "not a token",
            &"a".repeat(TOKEN_BODY_LEN - 1),
            &"a".repeat(TOKEN_BODY_LEN + 1),
        ] {
            let err = verify(bad, &issued.meta).expect_err("malformed token must be rejected");
            assert!(matches!(err, Error::Usage(_)), "{bad:?} gave {err:?}");
            assert_eq!(err.exit_code(), 2);
        }
    }

    #[test]
    fn secrets_never_appear_in_hash_debug_or_json() {
        let issued = issue_named("ci");
        let body = issued.plaintext.strip_prefix(TOKEN_PREFIX).expect("prefix");

        assert!(!issued.meta.hash.contains(body), "hash leaks token body");
        assert_ne!(issued.meta.hash.as_str(), body);
        assert_eq!(issued.meta.hash.len(), 43, "sha256 → 32 bytes → 43 b64 chars");

        let debug = format!("{:?}", issued.meta);
        assert!(!debug.contains(body), "Debug leaks token body: {debug}");
        assert!(!debug.contains(&issued.plaintext), "Debug leaks plaintext");

        let json = serde_json::to_string(&issued.meta).expect("TokenMeta is serialisable");
        assert!(!json.contains(body), "serde output leaks token body: {json}");
        assert!(!json.contains(&issued.plaintext), "serde output leaks plaintext");
    }

    #[test]
    fn each_issue_is_unique() {
        let a = issue_named("ci");
        let b = issue_named("ci");
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.meta.hash.as_str(), b.meta.hash.as_str());
        assert_ne!(a.meta.id, b.meta.id);
        // 互不通用。
        assert!(verify(&a.plaintext, &b.meta).is_err());
        assert!(verify(&b.plaintext, &a.meta).is_err());
    }

    #[test]
    fn invalid_names_and_allow_members_are_usage_errors() {
        for bad in ["", "CI", "-lead", "has space", &"a".repeat(65)] {
            let err = issue_err(bad, None);
            assert!(matches!(err, Error::Usage(_)), "{bad:?} gave {err:?}");
            assert_eq!(err.exit_code(), 2);
        }

        let err = issue_err("ci", Some(vec!["openai".into(), "Bad Name".into()]));
        assert!(matches!(err, Error::Usage(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 2);

        // 合法的 allow 原样保留。
        let issued =
            issue("ci", Some(vec!["openai".into()]), true, None, now()).expect("valid allow");
        assert_eq!(issued.meta.allow.as_deref(), Some(&["openai".to_string()][..]));
        assert!(issued.meta.deny_reveal);
        assert_eq!(issued.meta.created_at, now());
        assert!(issued.meta.revoked_at.is_none());
        assert!(issued.meta.last_used_at.is_none());
    }

    #[test]
    fn authorize_respects_allow_list() {
        let open = issue_named("open");
        authorize(&open.meta, "openai", now()).expect("no allow list ⇒ any entry");
        authorize(&open.meta, "anthropic", now()).expect("no allow list ⇒ any entry");

        let scoped = issue("scoped", Some(vec!["openai".into()]), false, None, now())
            .expect("valid allow list");
        authorize(&scoped.meta, "openai", now()).expect("listed entry is allowed");
        let err = authorize(&scoped.meta, "anthropic", now())
            .expect_err("unlisted entry must be refused");
        assert!(matches!(err, Error::TokenScope(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 8);

        let empty = issue("empty", Some(Vec::new()), false, None, now()).expect("empty list");
        assert!(matches!(
            authorize(&empty.meta, "openai", now()),
            Err(Error::TokenScope(_))
        ));
    }

    #[test]
    fn expired_and_revoked_tokens_are_locked() {
        let t0 = now();

        let expired = issue("ci", None, false, Some(t0), t0).expect("expires_at == now");
        let err = authorize(&expired.meta, "openai", t0).expect_err("expiry is exclusive");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);

        let future = issue("ci", None, false, Some(t0 + chrono::Duration::seconds(1)), t0)
            .expect("valid expiry");
        authorize(&future.meta, "openai", t0).expect("not expired yet");
        let err = authorize(&future.meta, "openai", t0 + chrono::Duration::seconds(1))
            .expect_err("expired at the boundary");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");

        let mut revoked = issue_named("ci");
        revoked.meta.revoked_at = Some(t0);
        let err = authorize(&revoked.meta, "openai", t0).expect_err("revoked token");
        assert!(matches!(err, Error::Locked(_)), "got {err:?}");
        assert_eq!(err.exit_code(), 4);

        // 吊销优先于作用域判定：即便条目在 allow 里也必须拒绝。
        let mut revoked_scoped = issue("ci", Some(vec!["openai".into()]), false, None, t0)
            .expect("valid allow");
        revoked_scoped.meta.revoked_at = Some(t0);
        assert!(matches!(
            authorize(&revoked_scoped.meta, "openai", t0),
            Err(Error::Locked(_))
        ));
    }

    #[test]
    fn normalize_strips_optional_prefix() {
        let issued = issue_named("ci");
        let body = issued.plaintext.strip_prefix(TOKEN_PREFIX).expect("prefix");

        let with = normalize(&issued.plaintext).expect("prefixed form");
        let without = normalize(body).expect("bare form");
        assert_eq!(with, without);
        assert_eq!(with, body);
        assert_eq!(with.len(), TOKEN_BODY_LEN);
        // 空白（shell/env 常有的换行）不应影响解析。
        assert_eq!(normalize(&format!("  {}\n", issued.plaintext)).expect("padded"), with);

        for bad in ["", "   ", TOKEN_PREFIX, "akey_", "too-short", &"x".repeat(44)] {
            let err = normalize(bad).expect_err("malformed token must be usage error");
            assert!(matches!(err, Error::Usage(_)), "{bad:?} gave {err:?}");
            assert_eq!(err.exit_code(), 2);
        }
    }

    #[test]
    fn body_len_constant_matches_the_encoder() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; TOKEN_BYTES]);
        assert_eq!(encoded.len(), TOKEN_BODY_LEN);
        assert!(is_token_body(&encoded));
        assert!(!is_token_body(&format!("{encoded}=")), "padding must be rejected");
    }
}

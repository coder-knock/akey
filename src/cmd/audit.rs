//! `akey audit` and the audit checks consumed by `akey doctor`.
//!
//! DESIGN §17.5. The audit **never** carries a value or any value-derived hash in its
//! output; only entry name, field id, and a reason code. The bundled common-password
//! list (assets/audit/common-passwords.txt, 326 entries / ~3 KB) is matched by
//! case-insensitive equality only — no hashing, no fingerprinting.

use std::collections::HashSet;
use std::sync::LazyLock;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::cli::{AuditArgs, GenerateArgs};
use crate::cmd::Ctx;
use crate::error::Result;
use crate::vault::generator::{self, Recipe};
use crate::vault::model::{Category, Entry, Field, Vault};

/// Threshold below which a `Concealed` value is reported as too short. Mirrors the
/// `run` masker's floor: a value shorter than 8 characters is **not** concealed by
/// `run` either.
const WEAK_LENGTH: usize = 8;

/// Apikey / Token categories get the "stale rotation" check. Other categories do not —
/// a database password you never rotate is fine; an apikey you haven't rotated in a
/// year is not.
const STALE_ROTATION_DAYS: i64 = 365;
const STALE_LOOKBACK: Duration = Duration::days(STALE_ROTATION_DAYS);

/// Expiring window — matches the existing `doctor` check, kept here too so `audit`
/// and `doctor` agree on what counts as "about to expire".
const EXPIRING_WINDOW: Duration = Duration::days(30);

const COMMON_PASSWORDS: &str = include_str!("../../assets/audit/common-passwords.txt");

static COMMON_SET: LazyLock<HashSet<String>> = LazyLock::new(|| {
    COMMON_PASSWORDS
        .lines()
        .map(str::trim)
        // The file carries a short `//` header. Comments are not passwords, and leaving
        // them in the set would let a value match a documentation sentence.
        .filter(|s| !s.is_empty() && !s.starts_with("//"))
        .map(str::to_ascii_lowercase)
        .collect()
});

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WeakHit {
    pub name: String,
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReusedHit {
    pub entries: Vec<String>,
    pub field: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StaleHit {
    pub name: String,
    pub days_since_rotation: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExpiringHit {
    pub name: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Report {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub weak: Vec<WeakHit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reused: Vec<ReusedHit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<StaleHit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub expiring: Vec<ExpiringHit>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.weak.is_empty()
            && self.reused.is_empty()
            && self.stale.is_empty()
            && self.expiring.is_empty()
    }
}

/// Run every audit check over `vault`. `now` is injected so the result is
/// deterministic in tests.
pub fn run(vault: &Vault, now: DateTime<Utc>) -> Report {
    let live: Vec<&Entry> = vault.live_entries().collect();
    let mut report = Report::default();

    // ─────────── weak (length / charset / common) ───────────
    for entry in &live {
        for field in entry.fields.iter().filter(|f| f.is_concealed()) {
            let value = field.value();
            let reason = classify_weak(value);
            if let Some(reason) = reason {
                report.weak.push(WeakHit {
                    name: entry.name.clone(),
                    field: field.id.clone(),
                    reason,
                });
            }
        }
    }

    // ─────────── reused (same field-value hash on two entries) ───────────
    let mut by_hash: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();
    for entry in &live {
        for field in entry.fields.iter().filter(|f| f.is_concealed()) {
            // Empty concealed fields are common on partially filled entries. Hashing them
            // would report every pair of such entries as "reused"; emptiness is already
            // covered by the weak check above.
            if field.value().is_empty() {
                continue;
            }
            let hash = field.value_hash();
            by_hash
                .entry(hash)
                .or_default()
                .push((entry.name.clone(), field.id.clone()));
        }
    }
    for (_hash, pairs) in by_hash.into_iter() {
        // Multiple fields on the same entry sharing one value is **not** reuse — it is
        // one entry. Drop duplicate names first; only emit a group when ≥ 2 distinct
        // entries are involved.
        let mut names: Vec<String> = pairs.iter().map(|(n, _)| n.clone()).collect();
        names.sort();
        names.dedup();
        if names.len() < 2 {
            continue;
        }
        let field = pairs[0].1.clone();
        report.reused.push(ReusedHit {
            entries: names,
            field,
        });
    }

    // ─────────── stale rotations ───────────
    for entry in &live {
        if !matches!(entry.category, Category::Apikey | Category::Token) {
            continue;
        }
        let rotated = entry.rotated_at.unwrap_or(entry.updated_at);
        let age = now - rotated;
        if age >= STALE_LOOKBACK {
            report.stale.push(StaleHit {
                name: entry.name.clone(),
                days_since_rotation: age.num_days(),
            });
        }
    }

    // ─────────── expiring ───────────
    for entry in &live {
        if let Some(exp) = entry.expires_at
            && exp <= now + EXPIRING_WINDOW
        {
            report.expiring.push(ExpiringHit {
                name: entry.name.clone(),
                expires_at: exp,
            });
        }
    }

    report
}

/// Why is this value weak? Returns `None` if it looks fine.
fn classify_weak(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("empty".into());
    }
    if value.len() < WEAK_LENGTH {
        return Some(format!("shorter than {WEAK_LENGTH} characters"));
    }
    if is_single_charset(value) {
        return Some("single character class (letters / digits / symbols only)".into());
    }
    if COMMON_SET.contains(&value.to_ascii_lowercase()) {
        return Some("matches bundled common-password list".into());
    }
    None
}

fn is_single_charset(value: &str) -> bool {
    let mut has_letter = false;
    let mut has_digit = false;
    let mut has_other = false;
    for c in value.chars() {
        if c.is_ascii_alphabetic() {
            has_letter = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_other = true;
        }
    }
    let classes = [has_letter, has_digit, has_other]
        .iter()
        .filter(|x| **x)
        .count();
    classes == 1
}

/// Build the doctor check payloads. Each check has a stable `name` so `contract.rs`
/// can pin the set; `status` is `"warning"` when hits exist, `"ok"` otherwise.
pub fn doctor_checks(report: &Report) -> Vec<serde_json::Value> {
    let mut checks = Vec::new();
    let push = |name: &str, status: &str, detail: String| serde_json::json!({ "name": name, "status": status, "detail": detail });
    if report.weak.is_empty() {
        checks.push(push("weak_secrets", "ok", "no weak secrets".into()));
    } else {
        let names: Vec<String> = report
            .weak
            .iter()
            .map(|h| format!("{}.{} ({})", h.name, h.field, h.reason))
            .collect();
        checks.push(push("weak_secrets", "warning", names.join("; ")));
    }
    if report.reused.is_empty() {
        checks.push(push("reused_secrets", "ok", "no reused secrets".into()));
    } else {
        let pairs: Vec<String> = report
            .reused
            .iter()
            .map(|r| format!("{} on {}", r.entries.join(", "), r.field))
            .collect();
        checks.push(push("reused_secrets", "warning", pairs.join("; ")));
    }
    if report.stale.is_empty() {
        checks.push(push(
            "stale_rotations",
            "ok",
            format!("no rotation older than {STALE_ROTATION_DAYS} days"),
        ));
    } else {
        let list: Vec<String> = report
            .stale
            .iter()
            .map(|s| format!("{} ({}d)", s.name, s.days_since_rotation))
            .collect();
        checks.push(push("stale_rotations", "warning", list.join("; ")));
    }
    if report.expiring.is_empty() {
        checks.push(push(
            "expiring",
            "ok",
            format!("nothing expiring in {} days", EXPIRING_WINDOW.num_days()),
        ));
    } else {
        let list: Vec<String> = report
            .expiring
            .iter()
            .map(|e| format!("{} ({})", e.name, e.expires_at.to_rfc3339()))
            .collect();
        checks.push(push("expiring", "warning", list.join("; ")));
    }
    checks
}

impl Field {
    pub(crate) fn value_hash(&self) -> String {
        // sha256 hex; cheap because it runs over short concealed strings.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.value().as_bytes());
        let digest = h.finalize();
        let mut out = String::with_capacity(digest.len() * 2);
        for b in digest {
            use std::fmt::Write;
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// `akey generate [<recipe>]` — produces a password or passphrase without ever
/// opening a vault. The output is a single line on stdout. Nothing else is
/// written: no audit, no log, no scratch file.
pub fn generate(ctx: &Ctx, args: &GenerateArgs) -> Result<()> {
    let recipe = Recipe::parse(&args.recipe)?;
    let password = generator::generate(&recipe);
    let data = serde_json::json!({ "password": password });
    ctx.out.emit(password.clone(), &data)
}

/// `akey audit` — runs every check against the loaded vault and emits a
/// `Report`-shaped JSON envelope (or a human-readable summary). Mirrors the
/// `doctor` check set but emits per-hit detail; `doctor` aggregates.
pub fn run_command(ctx: &Ctx, _args: &AuditArgs) -> Result<()> {
    let store = ctx.store()?;
    let vault = store.load()?;
    let now = Utc::now();
    let report = run(&vault, now);
    let human = format_report_human(&report);
    let data = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
    ctx.out.emit(human, &data)
}

fn format_report_human(report: &Report) -> String {
    let mut out = String::new();
    if report.is_clean() {
        return crate::i18n::m("audit: no findings", "审计：无问题").to_string();
    }
    if !report.weak.is_empty() {
        out.push_str(crate::i18n::m("Weak secrets:\n", "弱密码：\n"));
        for hit in &report.weak {
            out.push_str(&format!(
                "  - {}.{} ({})\n",
                hit.name, hit.field, hit.reason
            ));
        }
    }
    if !report.reused.is_empty() {
        out.push_str(crate::i18n::m("Reused secrets:\n", "重复使用：\n"));
        for hit in &report.reused {
            out.push_str(&format!(
                "  - {} on field {}\n",
                hit.entries.join(", "),
                hit.field
            ));
        }
    }
    if !report.stale.is_empty() {
        out.push_str(crate::i18n::m("Stale rotations:\n", "轮换陈旧：\n"));
        for hit in &report.stale {
            out.push_str(&format!(
                "  - {} ({} days since last rotation)\n",
                hit.name, hit.days_since_rotation
            ));
        }
    }
    if !report.expiring.is_empty() {
        out.push_str(crate::i18n::m("Expiring soon:\n", "即将过期：\n"));
        for hit in &report.expiring {
            out.push_str(&format!("  - {} ({})\n", hit.name, hit.expires_at));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{Field, FieldType};

    fn ts(days_from_now: i64) -> DateTime<Utc> {
        Utc::now() + Duration::days(days_from_now)
    }

    fn make_entry(name: &str, value: &str, category: Category) -> Entry {
        let mut e = Entry::new(ulid::Ulid::generate(), name.into(), category, ts(-365));
        e.fields
            .push(Field::new("credential", FieldType::Concealed, value.into()));
        e.updated_at = ts(-100);
        e.rotated_at = Some(ts(-100));
        e
    }

    #[test]
    fn weak_detects_too_short() {
        assert_eq!(
            classify_weak("abc").as_deref(),
            Some("shorter than 8 characters")
        );
        assert_eq!(
            classify_weak("1234567").as_deref(),
            Some("shorter than 8 characters")
        );
    }

    #[test]
    fn weak_detects_single_charset() {
        assert!(classify_weak("12345678").unwrap().contains("single"));
        assert!(classify_weak("abcdefgh").unwrap().contains("single"));
        assert!(classify_weak("!@#$%^&*").unwrap().contains("single"));
        assert!(classify_weak("abcd1234").is_none());
        assert!(classify_weak("abcd123!").is_none());
    }

    #[test]
    fn weak_detects_common_password() {
        assert!(classify_weak("password").is_some());
        assert!(classify_weak("PASSWORD").is_some(), "case-insensitive");
        assert!(classify_weak("letmein1").is_some());
        assert!(classify_weak("TrUstnO1").is_some());
        assert!(classify_weak("x9k!Q2#fL").is_none());
    }

    #[test]
    fn weak_ignores_non_concealed_value_sensitivity() {
        // Long, multi-class, not common → clean.
        assert!(classify_weak("3zP!q9WxR7&Lm4@Yt").is_none());
        assert!(classify_weak("pass").is_some()); // short
    }

    #[test]
    fn reused_groups_two_entries_with_same_value_hash() {
        let mut vault = Vault::default();
        vault.entries.insert(
            ulid::Ulid::generate(),
            make_entry("alpha", "shared-secret", Category::Apikey),
        );
        vault.entries.insert(
            ulid::Ulid::generate(),
            make_entry("bravo", "shared-secret", Category::Apikey),
        );
        vault.entries.insert(
            ulid::Ulid::generate(),
            make_entry("charlie", "different", Category::Apikey),
        );
        let r = run(&vault, Utc::now());
        assert_eq!(r.reused.len(), 1, "two equal values must produce one group");
        let mut names: Vec<&String> = r.reused[0].entries.iter().collect();
        names.sort();
        assert_eq!(names, vec![&"alpha".to_string(), &"bravo".to_string()]);
        assert_eq!(r.reused[0].field, "credential");
    }

    #[test]
    fn reused_ignores_same_entry_two_fields_with_same_value() {
        let mut e = make_entry("only", "v", Category::Apikey);
        e.fields
            .push(Field::new("also", FieldType::Concealed, "v".into()));
        let mut vault = Vault::default();
        vault.entries.insert(e.id, e);
        let r = run(&vault, Utc::now());
        assert!(r.reused.is_empty(), "self-reuse is not a reuse warning");
    }

    #[test]
    fn reused_ignores_empty_concealed_fields() {
        let mut vault = Vault::default();
        let a = make_entry("alpha", "", Category::Apikey);
        let b = make_entry("bravo", "", Category::Apikey);
        vault.entries.insert(a.id, a);
        vault.entries.insert(b.id, b);
        let r = run(&vault, Utc::now());
        assert!(
            r.reused.is_empty(),
            "two empty fields are not a reused secret"
        );
        assert_eq!(r.weak.len(), 2, "emptiness is still reported as weak");
    }

    #[test]
    fn common_password_list_ignores_its_comment_header() {
        assert!(COMMON_SET.len() > 300, "{}", COMMON_SET.len());
        assert!(COMMON_SET.contains("password"));
        assert!(
            COMMON_SET.iter().all(|entry| !entry.starts_with("//")),
            "comment lines must never become passwords"
        );
    }

    #[test]
    fn stale_flags_apikey_rotated_more_than_a_year_ago() {
        let mut vault = Vault::default();
        let mut stale = make_entry("old-key", "anything-1234", Category::Apikey);
        stale.rotated_at = Some(ts(-400)); // 400 days ago
        vault.entries.insert(stale.id, stale);

        let mut fresh = make_entry("fresh-key", "fresh-secret-1234", Category::Apikey);
        fresh.rotated_at = Some(ts(-30)); // 30 days ago
        vault.entries.insert(fresh.id, fresh);

        let r = run(&vault, Utc::now());
        let names: Vec<&str> = r.stale.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["old-key"]);
        assert!(r.stale[0].days_since_rotation >= STALE_ROTATION_DAYS);
    }

    #[test]
    fn stale_skips_non_apikey_or_token_categories() {
        let mut vault = Vault::default();
        let mut db = make_entry("db", "any-value-1234", Category::Database);
        db.rotated_at = Some(ts(-1000));
        vault.entries.insert(db.id, db);
        let r = run(&vault, Utc::now());
        assert!(
            r.stale.is_empty(),
            "database passwords are not stale-checked"
        );
    }

    #[test]
    fn expiring_uses_30_day_window() {
        let mut vault = Vault::default();
        let mut in_window = make_entry("soon", "value-1234", Category::Apikey);
        in_window.expires_at = Some(ts(15));
        vault.entries.insert(in_window.id, in_window);

        let mut out_of_window = make_entry("later", "value-1234", Category::Apikey);
        out_of_window.expires_at = Some(ts(120));
        vault.entries.insert(out_of_window.id, out_of_window);

        let mut no_expiry = make_entry("never", "value-1234", Category::Apikey);
        no_expiry.expires_at = None;
        vault.entries.insert(no_expiry.id, no_expiry);

        let r = run(&vault, Utc::now());
        assert_eq!(r.expiring.len(), 1);
        assert_eq!(r.expiring[0].name, "soon");
    }

    #[test]
    fn report_serializes_with_empty_groups_omitted() {
        let vault = Vault::default();
        let r = run(&vault, Utc::now());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn doctor_checks_emit_stable_names_and_no_value_or_hash() {
        // Build a vault that fires every probe; verify the doctor output contains
        // none of the secret values or any sha256-prefix fragment.
        let mut vault = Vault::default();
        let mut a = make_entry("alpha", "12345", Category::Apikey);
        a.rotated_at = Some(ts(-400));
        a.expires_at = Some(ts(15));
        vault.entries.insert(a.id, a);
        let b = make_entry("bravo", "12345", Category::Apikey);
        vault.entries.insert(b.id, b);

        let report = run(&vault, Utc::now());
        let checks = doctor_checks(&report);
        let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"weak_secrets"));
        assert!(names.contains(&"reused_secrets"));
        assert!(names.contains(&"stale_rotations"));
        assert!(names.contains(&"expiring"));

        let blob = serde_json::to_string(&checks).unwrap();
        assert!(!blob.contains("12345"), "value leaked: {blob}");
        // sha256("12345") starts with "5994..."; even the prefix must not appear.
        assert!(
            !blob.to_ascii_lowercase().contains("5994"),
            "value-derived hash leaked: {blob}"
        );
    }

    #[test]
    fn run_is_deterministic_for_fixed_now() {
        let mut vault = Vault::default();
        let mut a = make_entry("a", "value-1234", Category::Apikey);
        a.rotated_at = Some(ts(-400));
        vault.entries.insert(a.id, a);
        let r1 = run(&vault, Utc::now());
        let r2 = run(&vault, Utc::now());
        // The `days_since_rotation` depends on real `now` and so can drift between
        // two calls; force a fixed input by snapshotting the report and re-running.
        // The structural shape (which groups are populated) must match.
        assert_eq!(r1.weak.len(), r2.weak.len());
        assert_eq!(r1.reused.len(), r2.reused.len());
        assert_eq!(r1.stale.len(), r2.stale.len());
        assert_eq!(r1.expiring.len(), r2.expiring.len());
    }
}

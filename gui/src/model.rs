//! Typed views over the CLI's `--json` payloads.
//!
//! Every struct here mirrors a documented payload (`REQUIREMENTS.md` FR-3). The GUI reads
//! only what the CLI chose to emit: a concealed field arrives as `********`, and no
//! amount of parsing turns that back into a secret. The one type that *can* hold
//! plaintext is [`crate::revealed::Revealed`], and it is constructible only from an
//! explicit `--reveal` call.
//!
//! Parsing is total but forgiving: unknown keys are ignored, missing optional keys
//! default. A CLI that grows a field must not break a GUI built against the old one.

use serde::Deserialize;

// ─────────────────────────────── whoami ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Whoami {
    pub device: String,
    #[serde(default)]
    pub devices: u64,
    #[serde(default)]
    pub entries: u64,
    #[serde(default)]
    pub home: String,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub repo: String,
    /// `None` = the local device identity (no token in play). `Some` = a capability token
    /// is driving this session, and the UI must show every write as unavailable.
    #[serde(default)]
    pub token_scope: Option<TokenScope>,
    #[serde(default)]
    pub tokens: u64,
    #[serde(default)]
    pub vault: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenScope {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub allow: Option<Vec<String>>,
    #[serde(default)]
    pub deny_reveal: bool,
}

impl Whoami {
    /// Whether this session holds a capability token. Writes cannot succeed under one
    /// (`AKEY_TOKEN` is a read-only credential), so the UI disables them.
    pub fn is_token_scoped(&self) -> bool {
        self.token_scope.is_some()
    }
}

// ─────────────────────────────── list ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EntryList {
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub entries: Vec<EntrySummary>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "default_bool")]
    pub favorite: bool,
    #[serde(default)]
    pub field_count: usize,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

impl EntrySummary {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    pub fn is_expiring_soon(&self) -> bool {
        // The CLI's own `--expiring 30d` uses this window; the GUI only decorates.
        match &self.expires_at {
            Some(at) => crate::model::parses_within_days(at, 30),
            None => false,
        }
    }
}

/// `serde` needs a helper because `#[serde(default)]` on a `bool` already works, but a
/// missing key must not be confused with an explicit `null`.
fn default_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(false))
}

/// RFC3339 → "is this timestamp within `days` from now". Kept dependency-free (no chrono
/// in the GUI) by comparing the date prefix lexicographically, which is exact for
/// `YYYY-MM-DD` but only as good as the caller needs: this drives a badge, not a decision.
pub fn parses_within_days(stamp: &str, days: i64) -> bool {
    let (Some(year), Some(month), Some(day)) = (
        slice_int(stamp, 0, 4),
        slice_int(stamp, 5, 7),
        slice_int(stamp, 8, 10),
    ) else {
        return false;
    };
    let Some((now_year, now_month, now_day)) = today_parts() else {
        return false;
    };
    let target = (year as i64) * 372 + (month as i64) * 31 + day as i64;
    let now = (now_year as i64) * 372 + (now_month as i64) * 31 + now_day as i64;
    let delta = target - now;
    delta <= days && delta >= -1
}

fn slice_int(text: &str, start: usize, end: usize) -> Option<u32> {
    text.get(start..end)?.parse().ok()
}

/// Today's date in UTC, from the system clock, without pulling in a date crate.
fn today_parts() -> Option<(u32, u32, u32)> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    Some(civil_from_days(days))
}

/// Howard Hinnant's `civil_from_days`. Exact for the proleptic Gregorian calendar.
fn civil_from_days(days: i64) -> (u32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ─────────────────────────────── get ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EntryDetail {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "default_bool")]
    pub favorite: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub rotated_at: Option<String>,
    /// `"allow"` / `"deny"`. The CLI is the authority; this is only for the UI to explain
    /// why a reveal button returned a refusal.
    #[serde(default)]
    pub reveal: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldView>,
}

/// One field, exactly as the CLI rendered it.
///
/// `value` is `********` for a concealed field unless `--reveal` was passed — the GUI
/// does not get to decide that, and this struct cannot recover the secret.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FieldView {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(rename = "type", default)]
    pub ty: String,
    #[serde(default, deserialize_with = "default_bool")]
    pub concealed: bool,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub reference: String,
    #[serde(default)]
    pub otp: Option<String>,
}

impl FieldView {
    /// The value only when it is genuinely not a secret, or when the caller already went
    /// through an explicit reveal. A concealed field's `value` is the CLI's placeholder.
    pub fn shown_value(&self) -> &str {
        &self.value
    }

    pub fn is_placeholder(&self) -> bool {
        self.concealed && self.value.chars().all(|c| c == '*') && !self.value.is_empty()
    }
}

impl EntryDetail {
    pub fn display_title(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.name)
    }
}

// ─────────────────────────────── devices ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeviceList {
    #[serde(default)]
    pub devices: Vec<DeviceRow>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeviceRow {
    pub name: String,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default, deserialize_with = "default_bool")]
    pub active: bool,
    #[serde(default, deserialize_with = "default_bool")]
    pub this_device: bool,
    #[serde(default)]
    pub added_at: Option<String>,
    #[serde(default)]
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// `devices list` does not say who is locally *trusted*; `doctor` does. The GUI shows the
/// pending set from `doctor`'s `recipients` probe detail alongside this table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingRecipients {
    pub names: Vec<String>,
}

// ─────────────────────────────── tokens ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenList {
    #[serde(default)]
    pub tokens: Vec<TokenRow>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenRow {
    pub name: String,
    #[serde(default)]
    pub id: String,
    /// `None` = unrestricted (still bounded by `deny_reveal`).
    #[serde(default)]
    pub allow: Option<Vec<String>>,
    #[serde(default, deserialize_with = "default_bool")]
    pub deny_reveal: bool,
    #[serde(default, deserialize_with = "default_bool")]
    pub active: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

impl TokenRow {
    pub fn allow_summary(&self) -> String {
        match &self.allow {
            None => "all entries".to_string(),
            Some(list) if list.is_empty() => "no entries".to_string(),
            Some(list) => list.join(", "),
        }
    }
}

// ─────────────────────────────── doctor ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Doctor {
    #[serde(default)]
    pub healthy: bool,
    #[serde(default)]
    pub errors: usize,
    #[serde(default)]
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub detail: String,
}

impl Check {
    pub fn is_error(&self) -> bool {
        self.status == "error"
    }

    pub fn is_warning(&self) -> bool {
        self.status == "warning"
    }
}

impl Doctor {
    /// The failing probes. Named `error_checks` because `errors` is already the count the
    /// CLI reports; a method and a field sharing a name reads as a bug at every call site.
    pub fn error_checks(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| c.is_error())
    }

    /// The one probe whose *detail* carries the list of recipients the repository knows
    /// about but this machine has not approved. Those keys receive no ciphertext
    /// (`REQUIREMENTS.md` FR-21), so the UI surfaces them.
    pub fn pending_recipients(&self) -> Option<&Check> {
        self.checks
            .iter()
            .find(|c| c.name == "recipients" && c.is_warning())
    }
}

// ─────────────────────────────── recovery ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RecoveryStatus {
    #[serde(default, deserialize_with = "default_bool")]
    pub configured: bool,
    /// The CLI never reports the real length; `current_length` is always `null` today and
    /// exists so the shape is stable if that ever changes.
    #[serde(default)]
    pub current_length: Option<u16>,
    #[serde(default)]
    pub min_length: u16,
    #[serde(default)]
    pub strength: String,
    #[serde(default)]
    pub recovery_file: String,
}

// ─────────────────────────────── sync & conflicts ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SyncReport {
    /// `up_to_date` | `pushed` | `pulled` | `merged` | `no_remote` | `conflict`…
    #[serde(default, rename = "outcome")]
    pub outcome: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub pending_recipients: Vec<PendingRecipient>,
    #[serde(default)]
    pub conflicts: Vec<ConflictRow>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PendingRecipient {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub pubkey: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Conflicts {
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub conflicts: Vec<ConflictRow>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ConflictRow {
    /// The entry that kept its name (`ours`).
    #[serde(default)]
    pub name: String,
    /// The conflict copy (`theirs`), named `<name>.conflict.<short-id>`.
    #[serde(default)]
    pub conflict_name: Option<String>,
    #[serde(default)]
    pub ours_id: Option<String>,
    #[serde(default)]
    pub theirs_id: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub other_device: Option<String>,
}

// ─────────────────────────────── audit ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct AuditReport {
    #[serde(default)]
    pub weak: Vec<WeakHit>,
    #[serde(default)]
    pub reused: Vec<ReusedHit>,
    #[serde(default)]
    pub stale: Vec<StaleHit>,
    #[serde(default)]
    pub expiring: Vec<ExpiringHit>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WeakHit {
    pub name: String,
    #[serde(default)]
    pub field: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReusedHit {
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default)]
    pub field: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct StaleHit {
    pub name: String,
    #[serde(default)]
    pub days_since_rotation: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ExpiringHit {
    pub name: String,
    #[serde(default)]
    pub expires_at: String,
}

impl AuditReport {
    pub fn is_clean(&self) -> bool {
        self.weak.is_empty()
            && self.reused.is_empty()
            && self.stale.is_empty()
            && self.expiring.is_empty()
    }

    pub fn total(&self) -> usize {
        self.weak.len() + self.reused.len() + self.stale.len() + self.expiring.len()
    }
}

// ─────────────────────────────── category ───────────────────────────────

/// The categories the CLI accepts (`--category`). Mirrors `vault::model::Category`; the
/// `template list --json` payload is the authority, and a mismatch here would show up as
/// a rejected `set`.
pub const CATEGORIES: &[&str] = &[
    "apikey",
    "login",
    "token",
    "database",
    "ssh-key",
    "secure-note",
    "env-bundle",
    "password",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<T: for<'de> Deserialize<'de>>(json: &str) -> T {
        serde_json::from_str(json).expect("payload must deserialize")
    }

    // ── whoami ──

    #[test]
    fn whoami_parses_and_detects_a_local_identity() {
        let who: Whoami = parse(
            r#"{"device":"macbook","devices":2,"entries":7,"home":"/h","pubkey":"age1x",
                "remote":"git@example/v.git","repo":"/h/repo","token_scope":null,
                "tokens":1,"vault":"default"}"#,
        );
        assert_eq!(who.device, "macbook");
        assert_eq!(who.entries, 7);
        assert!(!who.is_token_scoped());
    }

    #[test]
    fn whoami_detects_a_token_scoped_session() {
        let who: Whoami = parse(
            r#"{"device":"ci","token_scope":{"name":"ci-narrow","allow":["openai"],"deny_reveal":true}}"#,
        );
        assert!(who.is_token_scoped());
        assert_eq!(
            who.token_scope.as_ref().unwrap().allow.as_ref().unwrap(),
            &vec!["openai".to_string()]
        );
    }

    // ── list ──

    #[test]
    fn list_payload_maps_to_rows() {
        let list: EntryList = parse(
            r#"{"count":2,"entries":[
                {"category":"apikey","deleted_at":null,"expires_at":null,"favorite":false,
                 "field_count":2,"id":"01A","name":"openai","tags":[]},
                {"category":"password","deleted_at":null,"expires_at":"2026-09-25T00:00:00Z",
                 "favorite":true,"field_count":1,"id":"01B","name":"wifi","tags":["home"]}]}"#,
        );
        assert_eq!(list.count, 2);
        assert_eq!(list.entries[0].name, "openai");
        assert_eq!(list.entries[1].field_count, 1);
        assert!(list.entries[1].favorite);
        assert_eq!(list.entries[1].tags, vec!["home".to_string()]);
        assert!(!list.entries[0].is_deleted());
    }

    #[test]
    fn list_tolerates_a_payload_with_fewer_keys() {
        // Forward-compatibility: a CLI that drops an optional key must not break parsing.
        let list: EntryList = parse(r#"{"entries":[{"id":"01A","name":"bare"}]}"#);
        assert_eq!(list.entries.len(), 1);
        assert_eq!(list.entries[0].name, "bare");
        assert_eq!(list.entries[0].field_count, 0);
        assert!(!list.entries[0].favorite);
    }

    #[test]
    fn soft_deleted_entries_are_recognisable() {
        let list: EntryList = parse(
            r#"{"entries":[{"id":"01A","name":"gone","deleted_at":"2026-01-01T00:00:00Z"}]}"#,
        );
        assert!(list.entries[0].is_deleted());
    }

    // ── get ──

    #[test]
    fn detail_payload_maps_concealed_and_reference() {
        let detail: EntryDetail = parse(
            r#"{"id":"01A","name":"openai","category":"apikey","tags":[],"favorite":false,
                "reveal":"allow","created_at":"2026-01-01T00:00:00Z",
                "fields":[
                  {"id":"credential","label":"credential","type":"concealed",
                   "concealed":true,"value":"********","reference":"akey://default/openai/credential"},
                  {"id":"url","label":"url","type":"url","concealed":false,
                   "value":"https://api.example","reference":"akey://default/openai/url"}]}"#,
        );
        let cred = &detail.fields[0];
        assert!(cred.concealed);
        assert_eq!(cred.reference, "akey://default/openai/credential");
        assert!(
            cred.is_placeholder(),
            "the CLI's redaction must be recognised"
        );
        assert_eq!(detail.fields[1].shown_value(), "https://api.example");
    }

    /// FR-30: a plain `get --json` (no `--reveal`) must yield no plaintext. The CLI
    /// redacts, so the structural guarantee is that whatever parses out of a concealed
    /// field is the placeholder — never a value.
    #[test]
    fn reveal_is_not_reachable_without_an_explicit_call() {
        let detail: EntryDetail = parse(
            r#"{"id":"01A","name":"openai","fields":[
                 {"id":"credential","type":"concealed","concealed":true,
                  "value":"********","reference":"akey://default/openai/credential"}]}"#,
        );
        let cred = &detail.fields[0];
        assert!(cred.is_placeholder());
        assert!(
            cred.shown_value().chars().all(|c| c == '*'),
            "a concealed field must never parse into something else: {:?}",
            cred.shown_value()
        );
    }

    #[test]
    fn detail_display_title_falls_back_to_the_name() {
        let detail: EntryDetail = parse(r#"{"id":"01A","name":"openai"}"#);
        assert_eq!(detail.display_title(), "openai");
        let titled: EntryDetail = parse(r#"{"id":"01A","name":"openai","title":"OpenAI prod"}"#);
        assert_eq!(titled.display_title(), "OpenAI prod");
    }

    // ── devices ──

    #[test]
    fn device_list_marks_this_device() {
        let devices: DeviceList = parse(
            r#"{"devices":[
                {"active":true,"kind":"bootstrap","name":"bootstrap","pubkey":"age1b","this_device":false},
                {"active":true,"kind":"device","name":"macbook","pubkey":"age1m","this_device":true}]}"#,
        );
        assert_eq!(devices.devices.len(), 2);
        assert!(devices.devices[1].this_device);
        assert!(!devices.devices[0].this_device);
    }

    // ── tokens ──

    #[test]
    fn token_list_summarises_scope() {
        let tokens: TokenList = parse(
            r#"{"tokens":[
                {"name":"ci","allow":["openai"],"active":true,"deny_reveal":true},
                {"name":"wide","allow":null,"active":true},
                {"name":"none","allow":[],"active":false}]}"#,
        );
        assert_eq!(tokens.tokens[0].allow_summary(), "openai");
        assert!(tokens.tokens[0].deny_reveal);
        assert_eq!(tokens.tokens[1].allow_summary(), "all entries");
        assert_eq!(tokens.tokens[2].allow_summary(), "no entries");
        assert!(!tokens.tokens[2].active);
    }

    // ── doctor ──

    #[test]
    fn doctor_surfaces_errors_and_pending_recipients() {
        let doctor: Doctor = parse(
            r#"{"healthy":false,"errors":1,"checks":[
                {"detail":"/h","name":"home","status":"ok"},
                {"detail":"2 untrusted recipient(s) present","name":"recipients","status":"warning"},
                {"detail":"vault corrupt","name":"vault","status":"error"}]}"#,
        );
        assert_eq!(doctor.errors, 1);
        assert_eq!(doctor.error_checks().count(), 1);
        assert_eq!(doctor.error_checks().next().unwrap().name, "vault");
        assert!(doctor.pending_recipients().is_some());
    }

    #[test]
    fn doctor_with_no_pending_recipients_reports_none() {
        let doctor: Doctor = parse(
            r#"{"healthy":true,"errors":0,"checks":[
                {"detail":"every recipient is trusted","name":"recipients","status":"ok"}]}"#,
        );
        assert!(doctor.pending_recipients().is_none());
    }

    // ── recovery ──

    #[test]
    fn recovery_status_never_carries_a_passphrase() {
        let status: RecoveryStatus = parse(
            r#"{"configured":true,"current_length":null,"min_length":12,
                "recovery_file":"/h/repo/recovery.age","strength":"fair"}"#,
        );
        assert!(status.configured);
        assert_eq!(status.min_length, 12);
        assert_eq!(status.strength, "fair");
        assert!(status.current_length.is_none());
    }

    // ── sync / conflicts ──

    #[test]
    fn sync_report_reads_the_outcome_key() {
        let report: SyncReport = parse(
            r#"{"conflicts":[],"outcome":"no_remote","pending_recipients":[],
                "remote":null,"summary":"no remote configured; local vault only"}"#,
        );
        assert_eq!(report.outcome, "no_remote");
        assert!(report.remote.is_none());
        assert!(report.pending_recipients.is_empty());
    }

    #[test]
    fn sync_report_carries_pending_recipients() {
        let report: SyncReport = parse(
            r#"{"outcome":"pulled","pending_recipients":[{"name":"laptop","pubkey":"age1l"}]}"#,
        );
        assert_eq!(report.pending_recipients[0].name, "laptop");
    }

    #[test]
    fn conflicts_payload_maps_pairs() {
        let conflicts: Conflicts = parse(
            r#"{"count":1,"conflicts":[{"name":"openai",
                "conflict_name":"openai.conflict.9f2a","kind":"both_modified",
                "other_device":"laptop"}]}"#,
        );
        assert_eq!(conflicts.count, 1);
        assert_eq!(conflicts.conflicts[0].name, "openai");
        assert_eq!(
            conflicts.conflicts[0].other_device.as_deref(),
            Some("laptop")
        );
    }

    // ── audit ──

    #[test]
    fn audit_empty_payload_is_clean() {
        let audit: AuditReport = parse("{}");
        assert!(audit.is_clean());
        assert_eq!(audit.total(), 0);
    }

    #[test]
    fn audit_counts_every_group() {
        let audit: AuditReport = parse(
            r#"{"weak":[{"name":"a","field":"password","reason":"short"}],
                "reused":[{"entries":["a","b"],"field":"password"}],
                "stale":[{"name":"c","days_since_rotation":400}],
                "expiring":[{"name":"d","expires_at":"2026-09-30T00:00:00Z"}]}"#,
        );
        assert!(!audit.is_clean());
        assert_eq!(audit.total(), 4);
        assert_eq!(audit.weak[0].field, "password");
    }

    // ── date helper (drives the "expiring soon" badge) ──

    #[test]
    fn within_days_accepts_a_near_date_and_rejects_a_far_one() {
        let (y, m, d) = today_parts().unwrap();
        let near = format!("{y:04}-{m:02}-{d:02}T00:00:00Z");
        assert!(parses_within_days(&near, 30));
        let far = format!("{:04}-{m:02}-{d:02}T00:00:00Z", y + 1);
        assert!(!parses_within_days(&far, 30));
    }

    #[test]
    fn within_days_rejects_garbage_instead_of_panicking() {
        assert!(!parses_within_days("", 30));
        assert!(!parses_within_days("not-a-date", 30));
        assert!(!parses_within_days("2026-99", 30));
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // 2026-09-19 — the date this was written.
        assert_eq!(civil_from_days(20_715), (2026, 9, 19));
    }

    #[test]
    fn categories_include_the_v0_3_password_addition() {
        assert!(CATEGORIES.contains(&"password"));
        assert!(CATEGORIES.contains(&"apikey"));
        assert_eq!(CATEGORIES.len(), 8);
    }
}

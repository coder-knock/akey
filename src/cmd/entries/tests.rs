use chrono::{DateTime, Duration, Utc};
use ulid::Ulid;

use super::conflict::{Side, apply_resolve, conflict_views};
use super::input::{
    AssignAction, Assignment, DEFAULT_PASSWORD_LEN, apply_assignments, apply_stdin,
    argv_secret_labels, generate_password, parse_assignment, parse_recipe, password_from_bytes,
};
use super::lifecycle::{apply_cp, apply_mv, apply_restore, apply_rm};
use super::read::{EntrySummary, entry_view, select_entries};
use super::template::{ALL_CATEGORIES, EntryTemplate, category_template};
use super::write::{SetPlan, apply_set};
use super::{cp, edit, mv, resolve, restore, rm, set};
use crate::cli::ListArgs;
use crate::cmd::Ctx;
use crate::error::Error;
use crate::output::REDACTED;
use crate::vault::model::{Category, Entry, Field, FieldType, Vault};

const CANARY: &str = "CANARY-3f9a-secret-value";

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn entry(name: &str, category: Category) -> Entry {
    Entry::new(Ulid::generate(), name.to_string(), category, now())
}

fn vault_with(entries: Vec<Entry>) -> Vault {
    let mut vault = Vault::default();
    for entry in entries {
        vault.entries.insert(entry.id, entry);
    }
    vault
}

fn set_plan(name: &str, category: Option<Category>, assignments: &[&str]) -> SetPlan {
    SetPlan {
        name: name.to_string(),
        category,
        title: None,
        tags: None,
        template: None,
        stdin_text: None,
        secret_field: None,
        generate_password: None,
        assignments: assignments
            .iter()
            .map(|spec| parse_assignment(spec).expect("test assignment must parse"))
            .collect(),
    }
}

fn list_args(tags: &[&str], all: bool, expiring: Option<&str>) -> ListArgs {
    ListArgs {
        tags: tags.iter().map(|t| t.to_string()).collect(),
        category: None,
        expiring: expiring.map(str::to_string),
        favorite: false,
        all,
    }
}

// 1. Assignment parsing
#[test]
fn assignment_parsing_table() {
    let cases: &[(&str, Assignment)] = &[
        (
            "credential=sk-1",
            Assignment {
                section: None,
                label: "credential".into(),
                ty: None,
                action: AssignAction::Set("sk-1".into()),
            },
        ),
        (
            "api.username=me",
            Assignment {
                section: Some("api".into()),
                label: "username".into(),
                ty: None,
                action: AssignAction::Set("me".into()),
            },
        ),
        (
            "notes[string]=hello",
            Assignment {
                section: None,
                label: "notes".into(),
                ty: Some(FieldType::String),
                action: AssignAction::Set("hello".into()),
            },
        ),
        (
            "token[ssh-key]=k",
            Assignment {
                section: None,
                label: "token".into(),
                ty: Some(FieldType::SshKey),
                action: AssignAction::Set("k".into()),
            },
        ),
        (
            // The value contains '=': only the first unescaped '=' is the separator.
            "dsn=postgres://u:p@h/db?sslmode=require",
            Assignment {
                section: None,
                label: "dsn".into(),
                ty: None,
                action: AssignAction::Set("postgres://u:p@h/db?sslmode=require".into()),
            },
        ),
        (
            // An escaped dot: the field name really contains a dot, not a section separator.
            r"a\.b=x",
            Assignment {
                section: None,
                label: "a.b".into(),
                ty: None,
                action: AssignAction::Set("x".into()),
            },
        ),
        (
            // An escaped equals sign stays in the value.
            r"password=pa\=ss",
            Assignment {
                section: None,
                label: "password".into(),
                ty: None,
                action: AssignAction::Set("pa=ss".into()),
            },
        ),
        (
            "custom=[delete]",
            Assignment {
                section: None,
                label: "custom".into(),
                ty: None,
                action: AssignAction::Delete,
            },
        ),
        (
            "sec.old[concealed]=[delete]",
            Assignment {
                section: Some("sec".into()),
                label: "old".into(),
                ty: Some(FieldType::Concealed),
                action: AssignAction::Delete,
            },
        ),
    ];
    for (spec, expected) in cases {
        let parsed = parse_assignment(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
        assert_eq!(&parsed, expected, "{spec}");
    }

    for bad in [
        "nothing",
        "=x",
        "field[bogus]=1",
        "[delete]",
        "a[=1",
        "a[]=1",
        ".field=x",
    ] {
        let err = parse_assignment(bad).unwrap_err();
        assert!(matches!(err, Error::Usage(_)), "{bad} -> {err:?}");
    }
}

#[test]
fn assignment_applies_sections_and_deletes_only_matching_field() {
    let mut e = entry("x", Category::EnvBundle);
    apply_assignments(
        &mut e,
        &[
            parse_assignment("prod.token=one").unwrap(),
            parse_assignment("dev.token=two").unwrap(),
            parse_assignment("plain=three").unwrap(),
        ],
    );
    assert_eq!(e.field("token").map(|f| f.value()), Some("one"));
    assert_eq!(e.fields.len(), 3);

    // A delete with a section removes only that section's field.
    apply_assignments(&mut e, &[parse_assignment("prod.token=[delete]").unwrap()]);
    let remaining: Vec<&Field> = e.fields.iter().filter(|f| f.id == "token").collect();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].section.as_deref(), Some("dev"));

    // New fields are concealed by default — under D1, not asking for plaintext means concealed.
    let plain = e.field("plain").expect("plain");
    assert!(plain.is_concealed());
}

// 2. set: create → update
#[test]
fn set_creates_then_updates_in_place() {
    let mut vault = Vault::default();
    let t0 = now();
    let plan = set_plan("openai", Some(Category::Apikey), &["credential=sk-aaa"]);
    let created = apply_set(&mut vault, &plan, t0).unwrap();
    assert!(created.created);
    assert_eq!(vault.entries.len(), 1);
    assert_eq!(created.entry.fields.len(), 2, "apikey skeleton");
    assert_eq!(
        created.entry.field("credential").map(|f| f.value()),
        Some("sk-aaa")
    );

    let t1 = t0 + Duration::seconds(5);
    let plan = set_plan("openai", None, &["credential=sk-bbb"]);
    let updated = apply_set(&mut vault, &plan, t1).unwrap();
    assert!(!updated.created);
    assert_eq!(vault.entries.len(), 1, "must not create a second entry");
    assert_eq!(updated.entry.id, created.entry.id);
    assert_eq!(updated.entry.created_at, created.entry.created_at);
    assert!(updated.entry.updated_at > created.entry.updated_at);
    assert_eq!(
        updated.entry.field("credential").map(|f| f.value()),
        Some("sk-bbb")
    );
    assert_eq!(updated.entry.category, Category::Apikey, "category kept");

    let bad = set_plan("Bad Name", None, &[]);
    assert!(matches!(
        apply_set(&mut vault, &bad, t1).unwrap_err(),
        Error::Usage(_)
    ));
    assert_eq!(vault.entries.len(), 1);
}

#[test]
fn set_refuses_to_silently_resurrect_deleted_entry() {
    let mut vault = Vault::default();
    let t = now();
    apply_set(
        &mut vault,
        &set_plan("openai", Some(Category::Apikey), &[]),
        t,
    )
    .unwrap();
    apply_rm(&mut vault, &["openai".to_string()], false, t);
    assert!(matches!(
        apply_set(&mut vault, &set_plan("openai", None, &[]), t).unwrap_err(),
        Error::Usage(_)
    ));

    apply_restore(&mut vault, &["openai".to_string()], t);
    let outcome = apply_set(&mut vault, &set_plan("openai", None, &[]), t).unwrap();
    assert!(!outcome.created);
}

// 3. The two shapes of --stdin
#[test]
fn stdin_forms_land_in_the_right_fields() {
    let mut e = entry("github", Category::Login);
    e.fields = Category::Login
        .builtin_fields()
        .iter()
        .map(|(l, t)| Field::new(l, *t, String::new()))
        .collect();

    apply_stdin(&mut e, "username=me\npassword=pw\n", None).unwrap();
    assert_eq!(e.field("username").map(|f| f.value()), Some("me"));
    assert_eq!(e.field("password").map(|f| f.value()), Some("pw"));

    // A bare secret value lands in the category's default secret field, overwriting any existing value.
    apply_stdin(&mut e, CANARY, None).unwrap();
    assert_eq!(e.field("password").map(|f| f.value()), Some(CANARY));
    assert_eq!(e.field("username").map(|f| f.value()), Some("me"));

    // --secret-field overrides the default target.
    apply_stdin(&mut e, "token-value\n", Some("username")).unwrap();
    assert_eq!(e.field("username").map(|f| f.value()), Some("token-value"));

    // env-bundle has no default secret field.
    let err = apply_stdin(&mut entry("env", Category::EnvBundle), "raw", None).unwrap_err();
    assert!(matches!(err, Error::Usage(_)));
    apply_stdin(
        &mut entry("env", Category::EnvBundle),
        "raw",
        Some("API_KEY"),
    )
    .unwrap();
}

// 4. Password recipes
#[test]
fn password_recipe_parsing_and_charset() {
    let default = parse_recipe("").unwrap();
    assert_eq!(default.len, DEFAULT_PASSWORD_LEN);
    assert!(default.letters && default.digits && default.symbols);

    let digits_only = parse_recipe("digits,16").unwrap();
    assert_eq!(digits_only.len, 16);
    assert!(digits_only.digits && !digits_only.letters && !digits_only.symbols);

    let letters_only = parse_recipe("letters").unwrap();
    assert_eq!(letters_only.len, DEFAULT_PASSWORD_LEN);
    assert!(letters_only.letters && !letters_only.digits);

    assert!(matches!(
        parse_recipe("bogus").unwrap_err(),
        Error::Usage(_)
    ));
    assert!(matches!(parse_recipe("0").unwrap_err(), Error::Usage(_)));
    assert!(matches!(
        parse_recipe("s,99999").unwrap_err(),
        Error::Usage(_)
    ));

    // A fixed byte source → deterministic assertions on length and character set.
    let mut counter = 0u8;
    let generated = password_from_bytes(&digits_only, move || {
        let value = counter;
        counter = counter.wrapping_add(1);
        value
    });
    assert_eq!(generated.len(), 16);
    assert!(
        generated.chars().all(|c| c.is_ascii_digit()),
        "digits-only recipe leaked other classes: {generated}"
    );

    // The letters+digits pool: bytes 0..61 cover a-z, A-Z, 0-9 in order.
    let letters_digits = parse_recipe("letters,digits,62").unwrap();
    let mut counter = 0u8;
    let generated = password_from_bytes(&letters_digits, move || {
        let value = counter % 62;
        counter = counter.wrapping_add(1);
        value
    });
    assert_eq!(generated.len(), 62);
    assert!(generated.chars().any(|c| c.is_ascii_digit()));
    assert!(generated.chars().any(|c| c.is_ascii_alphabetic()));
    assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));

    // A truly random source must hold the length and character set too.
    let random = generate_password(&digits_only);
    assert_eq!(random.len(), 16);
    assert!(random.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn set_generate_password_fills_default_secret_field() {
    let mut vault = Vault::default();
    let mut plan = set_plan("db", Some(Category::Database), &[]);
    plan.generate_password = Some("digits,24".to_string());
    let outcome = apply_set(&mut vault, &plan, now()).unwrap();
    let password = outcome.entry.field("password").expect("password field");
    assert!(password.is_concealed());
    assert_eq!(password.value().len(), 24);
    assert!(password.value().chars().all(|c| c.is_ascii_digit()));

    let mut conflicting = set_plan("other", None, &[]);
    conflicting.generate_password = Some(String::new());
    conflicting.stdin_text = Some("x".to_string());
    // The CLI layer rejects this combination first; the pure-function layer only guarantees the generated password is non-empty.
    let outcome = apply_set(&mut vault, &conflicting, now()).unwrap();
    assert!(
        !outcome
            .entry
            .field("credential")
            .unwrap()
            .value()
            .is_empty()
    );
}

#[test]
fn set_template_is_overridden_by_assignments() {
    let template: EntryTemplate = serde_json::from_str(
        r#"{"category":"token","title":"CI","tags":["ci"],
            "fields":[{"label":"token","type":"concealed","value":"from-template"},
                      {"label":"scopes","type":"string","value":"read"}]}"#,
    )
    .unwrap();
    let mut plan = set_plan("ci", None, &["token=from-argv"]);
    plan.template = Some(template);

    let mut vault = Vault::default();
    let outcome = apply_set(&mut vault, &plan, now()).unwrap();
    assert_eq!(outcome.entry.category, Category::Token);
    assert_eq!(outcome.entry.title.as_deref(), Some("CI"));
    assert_eq!(outcome.entry.tags, vec!["ci".to_string()]);
    assert_eq!(
        outcome.entry.field("token").map(|f| f.value()),
        Some("from-argv"),
        "argv must win over the template base"
    );
    assert_eq!(
        outcome.entry.field("scopes").map(|f| f.value()),
        Some("read")
    );
}

// 5. rm / purge
#[test]
fn rm_soft_deletes_then_purges_with_tombstone() {
    let source = entry("openai", Category::Apikey);
    let id = source.id;
    let mut vault = vault_with(vec![source]);
    let t = now();

    let report = apply_rm(&mut vault, &["openai".to_string()], false, t);
    assert!(report.failed.is_empty());
    assert_eq!(report.results[0].action, "deleted");
    assert!(vault.entries[&id].deleted_at.is_some());
    assert_eq!(
        select_entries(&vault, &list_args(&[], false, None), t)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        select_entries(&vault, &list_args(&[], true, None), t)
            .unwrap()
            .len(),
        1
    );

    // Idempotent: deleting again is not a failure.
    let again = apply_rm(&mut vault, &["openai".to_string()], false, t);
    assert!(again.failed.is_empty());
    assert_eq!(again.results[0].action, "already_deleted");

    // A nonexistent entry → failure, but the report still carries the successful items.
    let third = apply_rm(
        &mut vault,
        &["openai".to_string(), "ghost".to_string()],
        false,
        t,
    );
    assert_eq!(third.results.len(), 1);
    assert_eq!(third.failed.len(), 1);
    let err = third.error().unwrap();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    assert!(err.to_string().contains("openai"), "{err}");

    let purged = apply_rm(&mut vault, &["openai".to_string()], true, t);
    assert_eq!(purged.results[0].action, "purged");
    assert!(!vault.entries.contains_key(&id));
    assert!(
        vault.purged.contains_key(&id),
        "purge must leave a tombstone"
    );
}

// 6. restore
#[test]
fn restore_clears_marker_and_rejects_name_conflicts() {
    let mut source = entry("openai", Category::Apikey);
    source.deleted_at = Some(now());
    source.updated_at = now() - Duration::seconds(10);
    let id = source.id;
    let mut vault = vault_with(vec![source]);
    let t = now();

    let report = apply_restore(&mut vault, &[id.to_string()], t);
    assert!(report.failed.is_empty());
    assert_eq!(report.results[0].action, "restored");
    assert!(vault.entries[&id].deleted_at.is_none());
    assert!(vault.entries[&id].updated_at > t - Duration::seconds(1));

    let second = apply_restore(&mut vault, &[id.to_string()], t);
    assert_eq!(second.results[0].action, "already_live");

    // Name collision → usage.
    let mut other = entry("openai", Category::Apikey);
    other.deleted_at = Some(t);
    let other_id = other.id;
    vault.entries.insert(other_id, other);
    let report = apply_restore(&mut vault, &[other_id.to_string()], t);
    assert_eq!(report.failed.len(), 1);
    assert!(matches!(report.error().unwrap(), Error::Usage(_)));
    assert!(vault.entries[&other_id].deleted_at.is_some());
}

// 7. cp / mv
#[test]
fn cp_copies_with_new_id_and_mv_renames_in_place() {
    let mut vault = Vault::default();
    let t = now();
    let original = apply_set(
        &mut vault,
        &set_plan("openai", Some(Category::Apikey), &["credential=sk-1"]),
        t,
    )
    .unwrap()
    .entry;
    let original_id = original.id;

    let copy = apply_cp(&mut vault, "openai", "openai-prod", t).unwrap();
    assert_ne!(copy.id, original_id);
    assert_eq!(vault.entries.len(), 2);
    let source_after = &vault.entries[&original_id];
    assert_eq!(source_after.name, "openai");
    assert_eq!(
        source_after.field("credential").map(|f| f.value()),
        Some("sk-1")
    );
    assert_eq!(
        vault.entries[&copy.id]
            .field("credential")
            .map(|f| f.value()),
        Some("sk-1"),
        "copy carries the values"
    );

    assert!(matches!(
        apply_cp(&mut vault, "openai", "openai-prod", t).unwrap_err(),
        Error::Usage(_)
    ));
    assert!(matches!(
        apply_cp(&mut vault, "ghost", "x", t).unwrap_err(),
        Error::NotFound(_)
    ));
    assert!(matches!(
        apply_cp(&mut vault, "openai", "Bad Name", t).unwrap_err(),
        Error::Usage(_)
    ));

    let moved = apply_mv(&mut vault, &copy.id.to_string(), "openai-staging", t).unwrap();
    assert_eq!(moved.id, copy.id, "mv must keep the ID");
    assert_eq!(vault.entries[&copy.id].name, "openai-staging");
    assert_eq!(vault.entries.len(), 2);

    // Renaming onto a taken name → usage; renaming to itself must not false-alarm.
    assert!(matches!(
        apply_mv(&mut vault, "openai-staging", "openai", t).unwrap_err(),
        Error::Usage(_)
    ));
    assert!(apply_mv(&mut vault, "openai-staging", "openai-staging", t).is_ok());
    assert!(matches!(
        apply_mv(&mut vault, "openai-staging", "Bad Name", t).unwrap_err(),
        Error::Usage(_)
    ));
}

// 8. list filtering and ordering
#[test]
fn list_filters_and_ordering_are_deterministic() {
    let t = now();
    let mut prod = entry("prod-key", Category::Apikey);
    prod.tags = vec!["llm".into(), "prod".into()];
    prod.favorite = true;
    prod.expires_at = Some(t + Duration::days(31));

    let mut dev = entry("dev-key", Category::Login);
    dev.tags = vec!["llm".into()];
    dev.expires_at = Some(t + Duration::days(30));

    let mut soon = entry("soon", Category::Token);
    soon.expires_at = Some(t + Duration::days(3));

    let mut expired = entry("expired", Category::Token);
    expired.expires_at = Some(t - Duration::seconds(1));

    let mut gone = entry("gone", Category::Apikey);
    gone.deleted_at = Some(t);
    gone.tags = vec!["llm".into()];

    let vault = vault_with(vec![dev, prod, soon, expired, gone]);

    let all = select_entries(&vault, &list_args(&[], false, None), t).unwrap();
    let names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["dev-key", "expired", "prod-key", "soon"]);
    assert!(
        !names.contains(&"gone"),
        "soft-deleted entries are hidden by default"
    );

    let with_deleted = select_entries(&vault, &list_args(&[], true, None), t).unwrap();
    assert_eq!(with_deleted.len(), 5);

    // tags are AND semantics.
    let llm_prod = select_entries(&vault, &list_args(&["llm", "prod"], false, None), t).unwrap();
    assert_eq!(llm_prod.len(), 1);
    assert_eq!(llm_prod[0].name, "prod-key");

    // The --expiring boundary: exactly 30 days counts, 31 days does not, already expired does not, no date does not.
    let expiring = select_entries(&vault, &list_args(&[], false, Some("30d")), t).unwrap();
    let names: Vec<&str> = expiring.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["dev-key", "soon"], "boundary must be inclusive");

    let mut favorite = list_args(&[], false, None);
    favorite.favorite = true;
    let favored = select_entries(&vault, &favorite, t).unwrap();
    assert_eq!(favored.len(), 1);
    assert_eq!(favored[0].name, "prod-key");

    let mut category = list_args(&[], false, None);
    category.category = Some(Category::Token);
    let tokens = select_entries(&vault, &category, t).unwrap();
    let names: Vec<&str> = tokens.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["expired", "soon"]);

    assert!(matches!(
        select_entries(&vault, &list_args(&[], false, Some("nonsense")), t).unwrap_err(),
        Error::Usage(_)
    ));
}

// 9. conflicts / resolve
#[test]
fn conflicts_and_resolve_both_sides() {
    let t = now();
    let mut base = entry("openai", Category::Apikey);
    base.fields = vec![Field::new(
        "credential",
        FieldType::Concealed,
        "ours-value".into(),
    )];
    let base_id = base.id;
    let created = base.created_at;

    let mut copy = entry("openai.conflict.9f2a", Category::Apikey);
    copy.fields = vec![
        Field::new("credential", FieldType::Concealed, "theirs-value".into()),
        Field::new("org", FieldType::String, "acme".into()),
    ];
    copy.tags = vec!["conflict".into(), "prod".into()];
    let copy_id = copy.id;

    let views = conflict_views(&vault_with(vec![base.clone(), copy.clone()]));
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].original.as_deref(), Some("openai"));
    assert!(views[0].original_exists);

    // --theirs: the content moves over, ID / created_at stay, the copy goes away, the tag is cleared.
    let mut vault = vault_with(vec![base.clone(), copy.clone()]);
    let outcome = apply_resolve(&mut vault, "openai", Side::Theirs, t).unwrap();
    assert_eq!(outcome.removed, vec!["openai.conflict.9f2a".to_string()]);
    let merged = &vault.entries[&base_id];
    assert_eq!(merged.id, base_id);
    assert_eq!(merged.created_at, created);
    assert_eq!(
        merged.field("credential").map(|f| f.value()),
        Some("theirs-value")
    );
    assert_eq!(merged.field("org").map(|f| f.value()), Some("acme"));
    assert_eq!(
        merged.tags,
        vec!["prod".to_string()],
        "conflict tag cleared"
    );
    assert!(!vault.entries.contains_key(&copy_id));
    assert!(vault.purged.contains_key(&copy_id));
    assert!(conflict_views(&vault).is_empty());

    // --ours: the original-name entry keeps its content, the copy goes away.
    let mut vault = vault_with(vec![base.clone(), copy.clone()]);
    apply_resolve(&mut vault, "openai", Side::Ours, t).unwrap();
    let kept = &vault.entries[&base_id];
    assert_eq!(
        kept.field("credential").map(|f| f.value()),
        Some("ours-value")
    );
    assert!(kept.tags.is_empty());
    assert!(!vault.entries.contains_key(&copy_id));

    // The copy's name also locates the original-name entry.
    let mut vault = vault_with(vec![base.clone(), copy.clone()]);
    assert!(apply_resolve(&mut vault, "openai.conflict.9f2a", Side::Ours, t).is_ok());

    // No copy → usage; no such entry → not_found.
    let mut lonely = vault_with(vec![base.clone()]);
    assert!(matches!(
        apply_resolve(&mut lonely, "openai", Side::Ours, t).unwrap_err(),
        Error::Usage(_)
    ));
    assert!(matches!(
        apply_resolve(&mut lonely, "ghost", Side::Ours, t).unwrap_err(),
        Error::NotFound(_)
    ));
}

#[test]
fn resolve_needs_a_side() {
    let ctx_side = |ours: bool, theirs: bool| match (ours, theirs) {
        (true, false) => Ok(Side::Ours),
        (false, true) => Ok(Side::Theirs),
        _ => Err::<Side, Error>(Error::usage(
            "resolve needs exactly one of --ours or --theirs",
        )),
    };
    assert_eq!(ctx_side(true, false).unwrap(), Side::Ours);
    assert_eq!(ctx_side(false, true).unwrap(), Side::Theirs);
    assert!(ctx_side(false, false).is_err());
    assert!(ctx_side(true, true).is_err());
}

// 10. Plaintext never appears in output
#[test]
fn json_output_never_leaks_field_values() {
    let mut e = entry("openai", Category::Apikey);
    e.fields = vec![
        Field::new("credential", FieldType::Concealed, CANARY.into()),
        Field::new("note", FieldType::Notes, CANARY.into()),
        Field::new("url", FieldType::Url, "https://example.test".into()),
    ];
    e.notes = Some(CANARY.to_string());

    let hidden = serde_json::to_string(&entry_view(&e, false)).unwrap();
    assert!(!hidden.contains(CANARY), "concealed value leaked: {hidden}");
    assert!(hidden.contains(REDACTED));
    assert!(
        hidden.contains("https://example.test"),
        "plain fields stay visible"
    );
    assert!(hidden.contains("akey://default/openai/credential"));

    // The summary (list) does not even carry field values.
    let summary = serde_json::to_string(&EntrySummary::from_entry(&e)).unwrap();
    assert!(!summary.contains(CANARY));
    assert!(!summary.contains("https://example.test"));
    assert!(summary.contains("\"field_count\":3"));

    // The set --dry-run preview likewise shows only the placeholder.
    let mut vault = Vault::default();
    let plan = set_plan("leaky", Some(Category::Apikey), &[]);
    let outcome = apply_set(&mut vault, &plan, now()).unwrap();
    let mut leaky = outcome.entry;
    leaky.fields = vec![Field::new(
        "credential",
        FieldType::Concealed,
        CANARY.into(),
    )];
    let preview = serde_json::to_string(&entry_view(&leaky, false)).unwrap();
    assert!(
        !preview.contains(CANARY),
        "dry-run preview leaked: {preview}"
    );
    assert!(preview.contains(REDACTED));

    // The escape hatch: plaintext only on an explicit reveal.
    assert!(
        serde_json::to_string(&entry_view(&e, true))
            .unwrap()
            .contains(CANARY)
    );
}

#[test]
fn argv_secret_warning_only_fires_for_concealed_fields() {
    let mut e = entry("openai", Category::Apikey);
    e.fields = Category::Apikey
        .builtin_fields()
        .iter()
        .map(|(l, t)| Field::new(l, *t, String::new()))
        .collect();
    let secret = parse_assignment("credential=sk-leak").unwrap();
    let plain = parse_assignment("url=https://example.test").unwrap();
    assert_eq!(
        argv_secret_labels(&e, &[secret.clone(), plain.clone()]),
        vec!["credential".to_string()]
    );
    // An empty value is not a leak.
    let empty = parse_assignment("credential=").unwrap();
    assert!(argv_secret_labels(&e, &[empty]).is_empty());
}

// A token is a read-only credential: every write command must be rejected before it touches the vault.
#[test]
fn write_commands_are_denied_for_capability_tokens() {
    use crate::cli::{Cli, Command};
    use clap::Parser as _;

    let home = tempfile::tempdir().unwrap();
    let home = home.path().to_str().unwrap().to_string();
    // The token value does not matter: the gate only looks at whether `AKEY_TOKEN`/`--token` is present.
    let ctx_for = |extra: &[&str]| {
        let mut argv = vec!["akey", "--home", home.as_str(), "--token", "tok"];
        argv.extend_from_slice(extra);
        let cli = Cli::parse_from(argv);
        let ctx = Ctx::new(&cli).expect("ctx");
        (cli, ctx)
    };
    let denied = |err: Error| {
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert_eq!(err.exit_code(), 7, "{err:?}");
    };

    let (cli, ctx) = ctx_for(&["set", "x"]);
    let Command::Set(args) = cli.command else {
        panic!("expected set")
    };
    denied(set(&ctx, &args).unwrap_err());

    for command in ["edit", "rm", "restore", "cp", "mv", "resolve"] {
        let operands: &[&str] = if matches!(command, "cp" | "mv") {
            &["x", "y"]
        } else {
            &["x"]
        };
        let mut argv = vec![command];
        argv.extend_from_slice(operands);
        let (cli, ctx) = ctx_for(&argv);
        let err = match cli.command {
            Command::Edit(args) => edit(&ctx, &args).unwrap_err(),
            Command::Rm(args) => rm(&ctx, &args).unwrap_err(),
            Command::Restore(args) => restore(&ctx, &args).unwrap_err(),
            Command::Cp(args) => cp(&ctx, &args).unwrap_err(),
            Command::Mv(args) => mv(&ctx, &args).unwrap_err(),
            Command::Resolve(args) => resolve(&ctx, &args).unwrap_err(),
            other => panic!("unexpected command {other:?}"),
        };
        denied(err);
    }
}

#[test]
fn category_template_lists_builtin_fields_with_empty_values() {
    let value = category_template(Category::SshKey);
    assert_eq!(value["category"], "ssh-key");
    let fields = value["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), Category::SshKey.builtin_fields().len());
    assert_eq!(fields[0]["id"], "private-key");
    assert_eq!(fields[0]["type"], "ssh-key");
    assert_eq!(fields[0]["value"], "");

    for category in ALL_CATEGORIES {
        let value = category_template(category);
        assert_eq!(value["category"], category.as_str());
        if !category.builtin_fields().is_empty() {
            assert!(!value["fields"].as_array().unwrap().is_empty());
        }
    }
    assert_eq!(ALL_CATEGORIES.len(), 8);
}

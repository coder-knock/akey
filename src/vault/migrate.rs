//! Forward migrations of `vault.age`. v1 → v2 is currently the only step.

use crate::vault::Vault;

/// v1 → v2 is **purely additive**: the only wire-format change is `version: 1` → `version: 2`.
/// Entries, tokens and purged tombstones carry over unchanged.
pub fn v1_to_v2(mut vault: Vault) -> Vault {
    vault.version = 2;
    vault
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Category, Entry, Field, FieldType, TokenMeta};
    use chrono::{DateTime, Utc};
    use ulid::Ulid;
    use zeroize::Zeroizing;

    fn make_entry(name: &str, value: &str, ts: DateTime<Utc>) -> Entry {
        let mut e = Entry::new(Ulid::generate(), name.to_string(), Category::Apikey, ts);
        e.fields.push(Field::new(
            "credential",
            FieldType::Concealed,
            value.to_string(),
        ));
        e
    }

    #[test]
    fn v1_to_v2_bumps_version() {
        let v = Vault {
            version: 1,
            ..Vault::default()
        };
        let v = v1_to_v2(v);
        assert_eq!(v.version, 2);
    }

    #[test]
    fn v1_to_v2_is_identity_on_entries_tokens_purged() {
        let ts = Utc::now();
        let mut v = Vault {
            version: 1,
            ..Vault::default()
        };
        let e1 = make_entry("a", "v1", ts);
        let e2 = make_entry("b", "v2", ts);
        let id1 = e1.id;
        let id2 = e2.id;
        let token = TokenMeta {
            id: Ulid::generate(),
            name: "ci".into(),
            hash: Zeroizing::new("AAAA".into()),
            allow: None,
            deny_reveal: false,
            expires_at: None,
            created_at: ts,
            last_used_at: None,
            revoked_at: None,
        };
        let token_id = token.id;
        v.entries.insert(id1, e1);
        v.entries.insert(id2, e2);
        v.tokens.insert(token_id, token);
        v.purged.insert(id2, ts);

        let after = v1_to_v2(v);
        assert_eq!(after.version, 2);
        assert_eq!(after.entries.len(), 2);
        assert!(after.entries.contains_key(&id1));
        assert!(after.entries.contains_key(&id2));
        assert_eq!(
            after.entries[&id1].field("credential").unwrap().value(),
            "v1"
        );
        assert_eq!(
            after.entries[&id2].field("credential").unwrap().value(),
            "v2"
        );
        assert_eq!(after.tokens.len(), 1);
        assert!(after.tokens.contains_key(&token_id));
        assert_eq!(after.purged.len(), 1);
        assert!(after.purged.contains_key(&id2));
    }

    #[test]
    fn v1_to_v2_already_v2_is_idempotent() {
        let v = Vault::default(); // already version 1 by default
        let after = v1_to_v2(v1_to_v2(v.clone()));
        assert_eq!(after.version, 2);
        assert_eq!(after.entries.len(), v.entries.len());
    }
}

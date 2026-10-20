//! The one place a plaintext secret is allowed to exist, and the rules that end it.
//!
//! `DESIGN.md` §18.4 / `REQUIREMENTS.md` FR-31. The CLI redacts concealed fields unless
//! `--reveal` was passed, so plaintext only enters the GUI through an explicit user
//! action. Once it is here it must not survive: not in a config file, not in a log, not
//! in a panic message, not in the window title, and not across an entry switch.
//!
//! `Revealed` deliberately does **not** implement `Debug` or `Serialize`. That is the
//! mechanism, not a style choice: a `{:?}` on app state, or a state dump, is exactly how
//! a secret escapes a GUI. Reaching the value requires `.expose()`, whose name is meant
//! to read as deliberate at every call site.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// How long a revealed value survives without interaction. Short enough that leaving the
/// desk is unlikely to leak, long enough to read and copy.
pub const REVEAL_TTL: Duration = Duration::from_secs(30);

/// A plaintext value, bound to the entry it came from.
///
/// Not `Clone`: a copy is a second thing to forget.
pub struct Revealed {
    entry_id: String,
    field_id: String,
    value: Zeroizing<String>,
}

impl Revealed {
    pub fn new(
        entry_id: impl Into<String>,
        field_id: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Revealed {
            entry_id: entry_id.into(),
            field_id: field_id.into(),
            value: Zeroizing::new(value.into()),
        }
    }

    /// The entry this value belongs to. Used to decide whether a value may stay on
    /// screen when the selection moves.
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub fn field_id(&self) -> &str {
        &self.field_id
    }

    /// Read the secret. Deliberately verbose: every caller is a place where the value
    /// might be written somewhere it should not be.
    pub fn expose(&self) -> &str {
        &self.value
    }
}

// NOTE: no `impl Debug`. A `{:?}` on the app state is a leak, so the type makes one
// impossible rather than relying on reviewers to notice.

/// What the UI holds: at most one revealed value, plus when it must die.
#[derive(Default)]
pub struct RevealState {
    current: Option<Revealed>,
    /// Monotonic deadline; `None` alongside a `None` value.
    expires_at: Option<Instant>,
}

impl RevealState {
    pub fn new() -> Self {
        RevealState::default()
    }

    /// Adopt a freshly revealed value and start its clock.
    pub fn reveal(
        &mut self,
        entry_id: impl Into<String>,
        field_id: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.current = Some(Revealed::new(entry_id, field_id, value));
        self.expires_at = Some(Instant::now() + REVEAL_TTL);
    }

    /// Drop the value now — the "hide" button, or leaving the detail view.
    pub fn hide(&mut self) {
        self.current = None;
        self.expires_at = None;
    }

    /// The selection moved. A value survives only if it belongs to the entry now in
    /// focus; anything else is dropped. Returns whether the value was dropped, so the
    /// caller can refresh.
    pub fn on_entry_switch(&mut self, entry_id: &str) -> bool {
        match &self.current {
            Some(revealed) if revealed.entry_id() == entry_id => false,
            Some(_) => {
                self.hide();
                true
            }
            None => false,
        }
    }

    /// The window lost focus. Nothing on screen can be guarded once the user is
    /// elsewhere, so the value goes.
    pub fn on_focus_lost(&mut self) {
        self.hide();
    }

    /// Expire the value if its deadline has passed. Call from the UI's frame callback.
    /// Returns whether anything was dropped.
    pub fn tick(&mut self, now: Instant) -> bool {
        match self.expires_at {
            Some(deadline) if now >= deadline => {
                self.hide();
                true
            }
            _ => false,
        }
    }

    pub fn current(&self) -> Option<&Revealed> {
        self.current.as_ref()
    }

    /// The value for `entry_id`, if that is the entry currently revealed.
    pub fn value_for(&self, entry_id: &str, field_id: &str) -> Option<&str> {
        self.current
            .as_ref()
            .filter(|r| r.entry_id() == entry_id && r.field_id() == field_id)
            .map(|r| r.expose())
    }

    pub fn is_revealed(&self, entry_id: &str, field_id: &str) -> bool {
        self.current
            .as_ref()
            .is_some_and(|r| r.entry_id() == entry_id && r.field_id() == field_id)
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.expires_at
    }
}

impl Drop for RevealState {
    fn drop(&mut self) {
        // `Zeroizing<String>` already wipes on its own drop; this exists so the intent is
        // visible for the container too, and so a future field cannot be added here
        // without someone deciding whether it also needs wiping.
        self.current = None;
        self.expires_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_is_dropped_on_hide() {
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "sk-secret-value");
        assert!(state.is_revealed("01A", "credential"));
        assert_eq!(
            state.value_for("01A", "credential"),
            Some("sk-secret-value")
        );

        state.hide();
        assert!(!state.is_revealed("01A", "credential"));
        assert_eq!(state.value_for("01A", "credential"), None);
        assert!(state.current().is_none());
        assert!(state.deadline().is_none());
    }

    #[test]
    fn value_is_dropped_on_entry_switch() {
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "sk-secret-value");

        // Same entry: nothing to do.
        assert!(!state.on_entry_switch("01A"));
        assert!(state.is_revealed("01A", "credential"));

        // Different entry: the old value must be gone, not merely hidden behind a tab.
        assert!(state.on_entry_switch("01B"));
        assert!(!state.is_revealed("01A", "credential"));
        assert_eq!(state.value_for("01A", "credential"), None);
        assert!(state.current().is_none());
    }

    #[test]
    fn value_is_dropped_on_focus_loss() {
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "sk-secret-value");
        state.on_focus_lost();
        assert_eq!(state.value_for("01A", "credential"), None);
    }

    #[test]
    fn value_is_dropped_after_the_ttl() {
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "sk-secret-value");
        let started = Instant::now();

        // Just before the deadline: still there.
        assert!(!state.tick(started + REVEAL_TTL - Duration::from_millis(1)));
        assert!(state.is_revealed("01A", "credential"));

        // At the deadline: gone.
        assert!(state.tick(started + REVEAL_TTL));
        assert!(!state.is_revealed("01A", "credential"));
        assert_eq!(state.value_for("01A", "credential"), None);
    }

    #[test]
    fn tick_before_the_deadline_is_a_no_op() {
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "sk-secret-value");
        assert!(!state.tick(Instant::now()));
        assert!(state.is_revealed("01A", "credential"));
    }

    #[test]
    fn reveal_replaces_a_previous_value_for_another_entry() {
        // Revealing B while A is on screen must not leave A readable.
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "a-secret");
        state.reveal("01B", "password", "b-secret");
        assert_eq!(state.value_for("01A", "credential"), None);
        assert_eq!(state.value_for("01B", "password"), Some("b-secret"));
    }

    #[test]
    fn value_for_unrelated_entry_is_none() {
        let mut state = RevealState::new();
        state.reveal("01A", "credential", "a-secret");
        assert_eq!(state.value_for("01Z", "credential"), None);
        assert!(!state.is_revealed("01Z", "credential"));
    }

    #[test]
    fn entry_id_is_tracked_with_the_value() {
        let revealed = Revealed::new("01A", "credential", "a-secret");
        assert_eq!(revealed.entry_id(), "01A");
        assert_eq!(revealed.field_id(), "credential");
        assert_eq!(revealed.expose(), "a-secret");
    }

    #[test]
    fn a_reveal_is_bound_to_one_field() {
        let mut state = RevealState::new();
        state.reveal("01A", "password", "secret");
        assert_eq!(state.value_for("01A", "password"), Some("secret"));
        assert_eq!(state.value_for("01A", "otp"), None);
    }
}

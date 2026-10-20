//! The GPUI application: window bootstrap, view state, and every user action.
//!
//! See `DESIGN.md` §18. Rendering lives in [`crate::views`]; this module owns the state
//! those views read and the operations they trigger.
//!
//! **Plaintext never lives on this struct.** A revealed value is held by
//! [`RevealState`], whose lifetime rules drop it on an entry switch, a focus loss, or a
//! 30-second timer (`REQUIREMENTS.md` FR-31). `AkeyApp` deliberately does not derive
//! `Debug` for the same reason.
//!
//! Appearance and language are app state rather than process-wide settings, because both
//! are switchable while the window is open.

use std::fmt::Display;

use gpui::{
    App, Application, Bounds, ClickEvent, Context, FocusHandle, IntoElement, KeyDownEvent,
    MouseButton, Render, SharedString, Subscription, Window, WindowBounds, WindowOptions, div,
    prelude::*, px, size,
};
use zeroize::{Zeroize, Zeroizing};

use crate::i18n::{self, Lang, Msg};
use crate::model::{
    AuditReport, CATEGORIES, Conflicts, DeviceList, Doctor, EntryDetail, EntrySummary,
    RecoveryStatus, TokenList, Whoami,
};
use crate::revealed::RevealState;
use crate::theme::{Theme, ThemeMode};
use crate::verbs::{Akey, ConflictSide, ListFilter, Startup, SyncResult};

/// Which tab is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Entries,
    Sync,
    Devices,
    Tokens,
    Recovery,
    Diagnostics,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Entries,
        Tab::Sync,
        Tab::Devices,
        Tab::Tokens,
        Tab::Recovery,
        Tab::Diagnostics,
    ];

    /// The catalogue entry naming this tab.
    pub fn label(self) -> Msg {
        use i18n::chrome as c;
        match self {
            Tab::Entries => c::TAB_ENTRIES,
            Tab::Sync => c::TAB_SYNC,
            Tab::Devices => c::TAB_DEVICES,
            Tab::Tokens => c::TAB_TOKENS,
            Tab::Recovery => c::TAB_RECOVERY,
            Tab::Diagnostics => c::TAB_DIAGNOSTICS,
        }
    }

    /// Stable identifier for element ids, independent of the display language.
    pub fn slug(self) -> &'static str {
        match self {
            Tab::Entries => "entries",
            Tab::Sync => "sync",
            Tab::Devices => "devices",
            Tab::Tokens => "tokens",
            Tab::Recovery => "recovery",
            Tab::Diagnostics => "diagnostics",
        }
    }
}

/// Every keyboard-reachable control, in tab order.
///
/// UI/UX Pro Max's `ux` database rates a missing visible focus indicator **High** severity:
/// "use a visible focus ring on every interactive control… don't remove the focus outline
/// without replacement". A control is identified here by a `&'static str` (the same string
/// its element id uses), which lets the view decide whether to draw the ring without the
/// app having to thread a flag through every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    ThemeDark,
    ThemeLight,
    ThemeSystem,
    Language,
    Tab(Tab),
    FilterAll,
    FilterFavorite,
    FilterExpiring,
    Refresh,
    List,
    Reveal,
    Favorite,
    RevealPolicy,
    Restore,
    Delete,
    Purge,
    FieldName,
    FieldField,
    FieldValue,
    Generate,
    Passphrase,
    CatPrev,
    CatNext,
    Save,
    ClearFilters,
    TabPrimary,
    TabSecondary,
}

impl Focus {
    /// The stable identifier shared with the element's id.
    pub fn id(self) -> &'static str {
        match self {
            Focus::ThemeDark => "theme-dark",
            Focus::ThemeLight => "theme-light",
            Focus::ThemeSystem => "theme-system",
            Focus::Language => "lang-toggle",
            Focus::Tab(Tab::Entries) => "tab-entries",
            Focus::Tab(Tab::Sync) => "tab-sync",
            Focus::Tab(Tab::Devices) => "tab-devices",
            Focus::Tab(Tab::Tokens) => "tab-tokens",
            Focus::Tab(Tab::Recovery) => "tab-recovery",
            Focus::Tab(Tab::Diagnostics) => "tab-diagnostics",
            Focus::FilterAll => "filter-all",
            Focus::FilterFavorite => "filter-fav",
            Focus::FilterExpiring => "filter-expiring",
            Focus::Refresh => "refresh-all",
            Focus::List => "list",
            Focus::Reveal => "reveal",
            Focus::Favorite => "favorite",
            Focus::RevealPolicy => "policy",
            Focus::Restore => "restore",
            Focus::Delete => "delete",
            Focus::Purge => "purge",
            Focus::FieldName => "draft-name",
            Focus::FieldField => "draft-field",
            Focus::FieldValue => "draft-value",
            Focus::Generate => "gen-default",
            Focus::Passphrase => "gen-pass",
            Focus::CatPrev => "cat-prev",
            Focus::CatNext => "cat-next",
            Focus::Save => "save",
            Focus::ClearFilters => "clear-filters",
            Focus::TabPrimary => "tab-primary",
            Focus::TabSecondary => "tab-secondary",
        }
    }
}

/// Which form field has the keyboard. One root-level `on_key_down` routes keystrokes
/// here, so the app needs no per-field `FocusHandle` bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    None,
    EntryName,
    EntryField,
    EntryValue,
    TokenName,
    TokenTtl,
    Passphrase,
    NewPassphrase,
    MinLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Notice,
    Error,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub text: String,
    pub kind: StatusKind,
}

/// Start the GUI.
///
/// The start-up probe runs **before** the window opens: a machine with no vault gets a
/// window that says so, rather than an empty table and a vague error (`FR-28`).
pub fn run() -> Result<(), String> {
    let backend = crate::Backend::locate().map_err(|e| e.to_string())?;
    let akey = Akey::new(backend);
    let startup = akey.startup().map_err(|e| e.to_string())?;
    let lang = Lang::resolve_lossy(None);
    let theme_mode = ThemeMode::resolve(None);

    Application::new()
        // `Application::new()` installs `()` as the asset source, which returns `None` for
        // every path — so a brand lockup would silently never draw. The GUI serves the
        // repository's `assets/` directory itself.
        .with_assets(crate::assets::BrandAssets::new())
        .run(move |cx: &mut App| {
            let bounds = Bounds::centered(None, size(px(1120.0), px(760.0)), cx);
            if let Err(error) = cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    ..Default::default()
                },
                move |window, cx| {
                    let akey = akey.clone();
                    let startup = startup.clone();
                    let app = cx.new(|cx| AkeyApp::new(akey, startup, lang, theme_mode, cx));
                    app.update(cx, |this, cx| {
                        this.activation_subscription =
                            Some(cx.observe_window_activation(window, |this, window, cx| {
                                if !window.is_window_active() {
                                    this.reveals.on_focus_lost();
                                    this.clear_sensitive_status();
                                    cx.notify();
                                }
                            }));
                    });
                    // Keys are routed by the root element, so it must hold focus from the
                    // start; otherwise the first keystroke goes nowhere.
                    let handle = app.read(cx).focus_handle.clone();
                    window.focus(&handle);
                    app
                },
            ) {
                eprintln!("akey-gui: could not open the main window: {error}");
            }
            cx.activate(true);
        });

    Ok(())
}

pub struct AkeyApp {
    pub akey: Akey,
    pub startup: Startup,
    pub who: Option<Whoami>,
    pub tab: Tab,
    pub focus_handle: FocusHandle,
    pub field: Field,
    pub status: Status,
    activation_subscription: Option<Subscription>,
    pending_confirmation: Option<(String, std::time::Instant)>,
    sensitive_status_deadline: Option<std::time::Instant>,

    /// The keyboard-focused control, or `None` when the keyboard has not been used yet.
    pub focus: Option<Focus>,
    /// Rings appear only once the keyboard has been used, so a mouse user never sees one.
    /// This is the `:focus-visible` behaviour, and it is why the ring is not simply tied to
    /// `focus`.
    pub keyboard_active: bool,

    // ── appearance & language ──
    pub lang: Lang,
    pub theme_mode: ThemeMode,
    /// What the window server last reported. Refreshed every frame, so `ThemeMode::System`
    /// follows the OS setting without the user restarting.
    pub system_is_dark: bool,

    // ── entries ──
    pub entries: Vec<EntrySummary>,
    pub filter: ListFilter,
    pub selected: Option<String>,
    pub detail: Option<EntryDetail>,
    pub reveals: RevealState,

    // ── forms ──
    pub draft_name: String,
    pub draft_field: String,
    pub draft_value: Zeroizing<String>,
    pub draft_category: usize,
    pub token_name: String,
    pub token_ttl: String,
    pub passphrase: Zeroizing<String>,
    pub new_passphrase: Zeroizing<String>,
    pub min_length: String,

    // ── other tabs ──
    pub sync: Option<SyncResult>,
    pub sync_in_flight: bool,
    pub conflicts: Option<Conflicts>,
    pub devices: Option<DeviceList>,
    pub tokens: Option<TokenList>,
    pub recovery: Option<RecoveryStatus>,
    pub doctor: Option<Doctor>,
    pub audit: Option<AuditReport>,
}

impl AkeyApp {
    pub fn new(
        akey: Akey,
        startup: Startup,
        lang: Lang,
        theme_mode: ThemeMode,
        cx: &mut Context<Self>,
    ) -> Self {
        let ready = startup.is_ready();
        let initial_status = match &startup {
            Startup::Ready(_) => Status {
                text: i18n::chrome::READY.text(lang).to_string(),
                kind: StatusKind::Info,
            },
            Startup::Uninitialized { message, .. } => Status {
                text: message.clone(),
                kind: StatusKind::Notice,
            },
            Startup::Locked { message, .. } | Startup::UnsupportedFormat { message } => Status {
                text: message.clone(),
                kind: StatusKind::Error,
            },
        };
        let mut app = AkeyApp {
            who: startup.whoami().cloned(),
            startup,
            akey,
            tab: Tab::Entries,
            focus_handle: cx.focus_handle(),
            field: Field::None,
            focus: None,
            keyboard_active: false,
            status: initial_status,
            activation_subscription: None,
            pending_confirmation: None,
            sensitive_status_deadline: None,
            lang,
            theme_mode,
            system_is_dark: true,
            entries: Vec::new(),
            filter: ListFilter::default(),
            selected: None,
            detail: None,
            reveals: RevealState::new(),
            draft_name: String::new(),
            draft_field: String::new(),
            draft_value: Zeroizing::new(String::new()),
            draft_category: 0,
            token_name: String::new(),
            token_ttl: "30d".to_string(),
            passphrase: Zeroizing::new(String::new()),
            new_passphrase: Zeroizing::new(String::new()),
            min_length: String::new(),
            sync: None,
            sync_in_flight: false,
            conflicts: None,
            devices: None,
            tokens: None,
            recovery: None,
            doctor: None,
            audit: None,
        };
        if ready {
            app.refresh_all(cx);
        }
        app
    }

    // ─────────────────────── appearance & language ───────────────────────

    /// The appearance currently in effect.
    pub fn theme(&self) -> Theme {
        Theme::resolve(self.theme_mode, self.system_is_dark)
    }

    /// Translate a message into the current language.
    pub fn t(&self, msg: Msg) -> &'static str {
        msg.text(self.lang)
    }

    /// Translate and format.
    pub fn tf(&self, msg: Msg, args: &[&dyn Display]) -> String {
        i18n::fill(msg.text(self.lang), args)
    }

    /// Switch to the other appearance. Lands on an explicit mode, so one click from
    /// `System` does not immediately snap back to whatever the OS says.
    pub fn toggle_theme(&mut self, cx: &mut Context<Self>) {
        self.theme_mode = self.theme_mode.flipped(self.system_is_dark);
        cx.notify();
    }

    pub fn toggle_language(&mut self, cx: &mut Context<Self>) {
        self.lang = self.lang.next();
        cx.notify();
    }

    // ─────────────────────── status helpers ───────────────────────

    pub fn note(&mut self, msg: Msg) {
        self.set_status(self.t(msg).to_string(), StatusKind::Info);
    }

    pub fn note_args(&mut self, msg: Msg, args: &[&dyn Display]) {
        self.set_status(self.tf(msg, args), StatusKind::Info);
    }

    pub fn notice(&mut self, msg: Msg) {
        self.set_status(self.t(msg).to_string(), StatusKind::Notice);
    }

    pub fn notice_args(&mut self, msg: Msg, args: &[&dyn Display]) {
        self.set_status(self.tf(msg, args), StatusKind::Notice);
    }

    /// A failure. `detail` is the CLI's own message — already localized by the CLI when it
    /// produced it, and never a value.
    pub fn fail(&mut self, detail: impl Into<String>) {
        self.set_status(detail.into(), StatusKind::Error);
    }

    fn set_status(&mut self, text: String, kind: StatusKind) {
        self.status.text.zeroize();
        self.sensitive_status_deadline = None;
        self.status = Status { text, kind };
    }

    fn clear_sensitive_status(&mut self) {
        if self.sensitive_status_deadline.take().is_some() {
            self.status.text.zeroize();
            self.status = Status {
                text: self.t(i18n::chrome::READY).to_string(),
                kind: StatusKind::Info,
            };
        }
    }

    fn schedule_sensitive_status_expiry(&mut self, cx: &mut Context<Self>) {
        let deadline = std::time::Instant::now() + crate::revealed::REVEAL_TTL;
        self.sensitive_status_deadline = Some(deadline);
        let timer = cx.background_executor().timer(crate::revealed::REVEAL_TTL);
        cx.spawn(async move |this, cx| {
            timer.await;
            let _ = this.update(cx, |this, cx| {
                if this.sensitive_status_deadline == Some(deadline) {
                    this.clear_sensitive_status();
                    cx.notify();
                }
            });
        })
        .detach();
    }

    // ─────────────────────── loading ───────────────────────

    pub fn refresh_all(&mut self, cx: &mut Context<Self>) {
        self.refresh_entries(cx);
        self.refresh_doctor(cx);
        self.refresh_audit(cx);
        self.refresh_devices(cx);
        self.refresh_tokens(cx);
        self.refresh_recovery(cx);
    }

    pub fn refresh_entries(&mut self, cx: &mut Context<Self>) {
        match self.akey.list(&self.filter) {
            Ok(list) => {
                self.entries = list.entries;
                let count = self.entries.len();
                self.note_args(i18n::status::ENTRIES_LOADED, &[&count]);
                // A selection that no longer exists must not keep a revealed value alive.
                if let Some(name) = self.selected.clone()
                    && !self.entries.iter().any(|e| e.name == name)
                {
                    self.selected = None;
                    self.detail = None;
                    self.reveals.hide();
                }
            }
            Err(e) => self.fail(format!("list: {e}")),
        }
        cx.notify();
    }

    /// Reset every filter (`favorite`, `expiring`, `all`) to off, then re-list.
    pub fn clear_filters(&mut self, cx: &mut Context<Self>) {
        self.filter = ListFilter::default();
        self.refresh_entries(cx);
    }

    pub fn cycle_category_filter(&mut self, cx: &mut Context<Self>) {
        self.filter.category = match self.filter.category.as_deref() {
            None => Some(CATEGORIES[0].to_string()),
            Some(current) => CATEGORIES
                .iter()
                .position(|category| *category == current)
                .and_then(|index| CATEGORIES.get(index + 1))
                .map(|category| (*category).to_string()),
        };
        self.refresh_entries(cx);
    }

    pub fn refresh_doctor(&mut self, cx: &mut Context<Self>) {
        match self.akey.doctor() {
            Ok(doctor) => self.doctor = Some(doctor),
            Err(e) => self.fail(format!("doctor: {e}")),
        }
        cx.notify();
    }

    pub fn refresh_audit(&mut self, cx: &mut Context<Self>) {
        match self.akey.audit() {
            Ok(audit) => self.audit = Some(audit),
            Err(e) => self.fail(format!("audit: {e}")),
        }
        cx.notify();
    }

    pub fn refresh_devices(&mut self, cx: &mut Context<Self>) {
        match self.akey.devices() {
            Ok(devices) => self.devices = Some(devices),
            Err(e) => self.fail(format!("devices: {e}")),
        }
        cx.notify();
    }

    pub fn refresh_tokens(&mut self, cx: &mut Context<Self>) {
        match self.akey.tokens() {
            Ok(tokens) => self.tokens = Some(tokens),
            Err(e) => self.fail(format!("tokens: {e}")),
        }
        cx.notify();
    }

    pub fn refresh_recovery(&mut self, cx: &mut Context<Self>) {
        match self.akey.recovery_status() {
            Ok(recovery) => self.recovery = Some(recovery),
            Err(e) => self.fail(format!("recovery: {e}")),
        }
        cx.notify();
    }

    // ─────────────────────── entries ───────────────────────

    /// Select an entry. The old reveal dies here if the entry changed (`FR-31`).
    pub fn select(&mut self, name: &str, cx: &mut Context<Self>) {
        if self.selected.as_deref() != Some(name) {
            self.reveals.on_entry_switch(name);
            self.pending_confirmation = None;
        }
        self.selected = Some(name.to_string());
        self.detail = None;
        match self.akey.detail(name) {
            Ok(detail) => {
                self.detail = Some(detail);
                self.note_args(i18n::status::SHOWING, &[&name]);
            }
            Err(e) => self.fail(format!("get {name}: {e}")),
        }
        cx.notify();
    }

    /// Ask the CLI for plaintext. Whether this succeeds is the CLI's decision — a refusal
    /// arrives as exit 7 and is reported, never worked around (`FR-30`).
    pub fn reveal(&mut self, cx: &mut Context<Self>) {
        let Some(field_id) = self.detail.as_ref().and_then(|detail| {
            detail
                .fields
                .iter()
                .find(|field| field.concealed)
                .map(|field| field.id.clone())
        }) else {
            self.notice(i18n::entries::SELECT_FIRST);
            cx.notify();
            return;
        };
        self.reveal_field(&field_id, cx);
    }

    /// Reveal exactly one field. The revealed response is never assigned to `self.detail`:
    /// that model stays redacted, while plaintext lives only in `RevealState`.
    pub fn reveal_field(&mut self, field_id: &str, cx: &mut Context<Self>) {
        let Some(name) = self.selected.clone() else {
            self.notice(i18n::entries::SELECT_FIRST);
            cx.notify();
            return;
        };
        match self.akey.reveal(&name, field_id) {
            Ok(detail) => {
                let id = detail.id.clone();
                let value = detail
                    .fields
                    .iter()
                    .find(|f| f.id == field_id && f.concealed)
                    .map(|f| f.shown_value().to_string());
                match value {
                    Some(value) => {
                        self.reveals.reveal(id, field_id, value);
                        self.note_args(i18n::status::REVEALED, &[&name]);
                        self.schedule_reveal_expiry(cx);
                    }
                    None => {
                        let msg = self.tf(i18n::entries::NO_CONCEALED_FIELD, &[&name]);
                        self.set_status(msg, StatusKind::Notice);
                    }
                }
            }
            // A policy refusal is an expected outcome, not a crash.
            Err(e) => {
                let msg = self.tf(i18n::entries::REVEAL_REFUSED, &[&e.to_string()]);
                self.set_status(msg, StatusKind::Notice);
            }
        }
        cx.notify();
    }

    fn schedule_reveal_expiry(&self, cx: &mut Context<Self>) {
        let timer = cx.background_executor().timer(crate::revealed::REVEAL_TTL);
        cx.spawn(async move |this, cx| {
            timer.await;
            let _ = this.update(cx, |this, cx| {
                if this.reveals.tick(std::time::Instant::now()) {
                    this.note(i18n::entries::REVEAL_EXPIRED);
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub fn hide_reveal(&mut self, cx: &mut Context<Self>) {
        self.reveals.hide();
        self.note(i18n::status::HIDDEN);
        cx.notify();
    }

    /// Copy the revealed value to the clipboard. Deliberate, and warned about: anything on
    /// the clipboard is readable by every other program the user runs.
    pub fn copy_revealed(&mut self, cx: &mut Context<Self>) {
        let Some(detail) = &self.detail else { return };
        let id = detail.id.clone();
        let Some(field_id) = self
            .reveals
            .current()
            .map(|revealed| revealed.field_id().to_string())
        else {
            self.notice(i18n::entries::SELECT_FIRST);
            cx.notify();
            return;
        };
        match self.reveals.value_for(&id, &field_id) {
            Some(value) => {
                cx.write_to_clipboard(gpui::ClipboardItem::new_string(value.to_string()));
                self.notice(i18n::entries::COPIED_WARNING);
            }
            None => self.notice(i18n::entries::SELECT_FIRST),
        }
        cx.notify();
    }

    pub fn copy_revealed_field(&mut self, field_id: &str, cx: &mut Context<Self>) {
        let Some(detail) = &self.detail else { return };
        match self.reveals.value_for(&detail.id, field_id) {
            Some(value) => {
                cx.write_to_clipboard(gpui::ClipboardItem::new_string(value.to_string()));
                self.notice(i18n::entries::COPIED_WARNING);
            }
            None => self.notice(i18n::entries::SELECT_FIRST),
        }
        cx.notify();
    }

    /// Write a **new** secret. The value goes on the child's stdin; the argv carries only
    /// the field name (`FR-31`).
    pub fn submit_new_entry(&mut self, cx: &mut Context<Self>) {
        let name = self.draft_name.trim().to_string();
        if name.is_empty() {
            self.notice(i18n::entries::NAME_REQUIRED);
            cx.notify();
            return;
        }
        if self.draft_value.is_empty() {
            self.notice(i18n::entries::VALUE_REQUIRED);
            cx.notify();
            return;
        }
        let category = CATEGORIES[self.draft_category.min(CATEGORIES.len() - 1)];
        let field = if self.draft_field.trim().is_empty() {
            None
        } else {
            Some(self.draft_field.trim())
        };
        let value = self.draft_value.clone();
        match self.akey.set_secret(&name, category, field, &value) {
            Ok(_) => {
                // Clear the value immediately: it has served its purpose.
                self.draft_value.zeroize();
                self.reveals.hide();
                self.draft_name.clear();
                self.draft_field.clear();
                self.note_args(i18n::status::WROTE, &[&name]);
                self.refresh_entries(cx);
                self.select(&name, cx);
                self.refresh_audit(cx);
            }
            Err(e) => self.fail(format!("set {name}: {e}")),
        }
        cx.notify();
    }

    /// Fill the draft with a freshly generated password. Local only — no vault involved.
    pub fn generate_into_draft(&mut self, recipe: &str, cx: &mut Context<Self>) {
        match self.akey.generate(recipe) {
            Ok(password) => {
                self.draft_value = Zeroizing::new(password);
                self.note_args(i18n::status::GENERATED, &[&recipe]);
            }
            Err(e) => self.fail(format!("generate: {e}")),
        }
        cx.notify();
    }

    /// Prepare the safe stdin-backed form to replace one existing concealed field.
    /// The current value is deliberately not copied into the draft.
    pub fn begin_field_edit(&mut self, field_id: &str, cx: &mut Context<Self>) {
        let Some(detail) = &self.detail else { return };
        self.draft_name = detail.name.clone();
        self.draft_field = field_id.to_string();
        self.draft_value.zeroize();
        if let Some(index) = CATEGORIES
            .iter()
            .position(|category| *category == detail.category)
        {
            self.draft_category = index;
        }
        self.field = Field::EntryValue;
        cx.notify();
    }

    pub fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let Some(detail) = self.detail.clone() else {
            return;
        };
        let next = !detail.favorite;
        match self.akey.edit_meta(&detail.name, None, None, Some(next)) {
            Ok(_) => {
                let msg = if next {
                    i18n::status::FAVORITED
                } else {
                    i18n::status::UNFAVORITED
                };
                self.note_args(msg, &[&detail.name]);
                self.refresh_entries(cx);
                self.select(&detail.name, cx);
            }
            Err(e) => self.fail(format!("edit: {e}")),
        }
        cx.notify();
    }

    pub fn toggle_reveal_policy(&mut self, cx: &mut Context<Self>) {
        let Some(detail) = self.detail.clone() else {
            return;
        };
        let allow = detail.reveal == "deny";
        match self.akey.set_reveal_policy(&detail.name, allow) {
            Ok(_) => {
                let policy = if allow { "allow" } else { "deny" };
                self.note_args(i18n::status::POLICY_TO, &[&detail.name, &policy]);
                self.select(&detail.name, cx);
            }
            Err(e) => self.fail(format!("edit: {e}")),
        }
        cx.notify();
    }

    pub fn delete_selected(&mut self, purge: bool, cx: &mut Context<Self>) {
        let Some(detail) = self.detail.clone() else {
            return;
        };
        let action = if purge { "purge" } else { "delete" };
        if !self.confirm_destructive(format!("{action}:{}", detail.name), action, cx) {
            return;
        }
        match self.akey.remove(&detail.name, purge) {
            Ok(_) => {
                self.selected = None;
                self.detail = None;
                self.reveals.hide();
                let msg = if purge {
                    i18n::status::PURGED
                } else {
                    i18n::status::DELETED
                };
                self.note_args(msg, &[&detail.name]);
                self.refresh_entries(cx);
                self.refresh_audit(cx);
            }
            Err(e) => self.fail(format!("rm: {e}")),
        }
        cx.notify();
    }

    pub fn restore(&mut self, name: &str, cx: &mut Context<Self>) {
        match self.akey.restore(name) {
            Ok(_) => {
                self.note_args(i18n::status::RESTORED, &[&name]);
                self.refresh_entries(cx);
            }
            Err(e) => self.fail(format!("restore: {e}")),
        }
        cx.notify();
    }

    // ─────────────────────── sync ───────────────────────

    pub fn run_sync(&mut self, cx: &mut Context<Self>) {
        if self.sync_in_flight {
            self.notice(i18n::sync::ALREADY_SYNCING);
            cx.notify();
            return;
        }
        self.sync_in_flight = true;
        self.note(i18n::sync::SYNCING);
        cx.notify();

        let akey = self.akey.clone();
        let filter = self.filter.clone();
        let task = cx.background_executor().spawn(async move {
            let sync = akey.sync();
            let conflicts = sync.as_ref().ok().map(|_| akey.conflicts());
            let entries = sync.as_ref().ok().map(|_| akey.list(&filter));
            (sync, conflicts, entries)
        });
        cx.spawn(async move |this, cx| {
            let (sync, conflicts, entries) = task.await;
            let _ = this.update(cx, |this, cx| {
                this.sync_in_flight = false;
                match sync {
                    Ok(result) => {
                        let summary = result.summary();
                        let pending = result
                            .report
                            .as_ref()
                            .is_some_and(|report| !report.pending_recipients.is_empty());
                        this.sync = Some(result);
                        this.set_status(
                            summary,
                            if pending {
                                StatusKind::Notice
                            } else {
                                StatusKind::Info
                            },
                        );
                        if let Some(Ok(conflicts)) = conflicts {
                            this.conflicts = Some(conflicts);
                        }
                        if let Some(Ok(entries)) = entries {
                            this.entries = entries.entries;
                            if let Some(name) = this.selected.clone()
                                && !this.entries.iter().any(|entry| entry.name == name)
                            {
                                this.selected = None;
                                this.detail = None;
                                this.reveals.hide();
                            }
                        }
                    }
                    Err(error) => this.fail(format!("sync: {error}")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn load_conflicts(&mut self, cx: &mut Context<Self>) {
        match self.akey.conflicts() {
            Ok(conflicts) => self.conflicts = Some(conflicts),
            Err(e) => self.fail(format!("conflicts: {e}")),
        }
        cx.notify();
    }

    pub fn resolve(&mut self, name: &str, side: ConflictSide, cx: &mut Context<Self>) {
        let action = match side {
            ConflictSide::Ours => "keep ours",
            ConflictSide::Theirs => "take theirs",
        };
        if !self.confirm_destructive(format!("resolve:{name}:{action}"), action, cx) {
            return;
        }
        match self.akey.resolve(name, side) {
            Ok(_) => {
                let which = match side {
                    ConflictSide::Ours => self.t(i18n::status::OURS),
                    ConflictSide::Theirs => self.t(i18n::status::THEIRS),
                };
                self.note_args(i18n::status::RESOLVED, &[&name, &which]);
                self.load_conflicts(cx);
                self.refresh_entries(cx);
            }
            Err(e) => self.fail(format!("resolve: {e}")),
        }
        cx.notify();
    }

    // ─────────────────────── devices ───────────────────────

    pub fn trust_device(&mut self, name: &str, cx: &mut Context<Self>) {
        match self.akey.trust_device(name) {
            Ok(_) => {
                self.note_args(i18n::status::TRUSTED, &[&name]);
                self.refresh_devices(cx);
                self.refresh_doctor(cx);
            }
            Err(e) => self.fail(format!("devices trust: {e}")),
        }
        cx.notify();
    }

    pub fn untrust_device(&mut self, name: &str, cx: &mut Context<Self>) {
        if !self.confirm_destructive(format!("untrust:{name}"), "untrust device", cx) {
            return;
        }
        match self.akey.untrust_device(name) {
            Ok(_) => {
                self.note_args(i18n::status::UNTRUSTED, &[&name]);
                self.refresh_devices(cx);
            }
            Err(e) => self.fail(format!("devices untrust: {e}")),
        }
        cx.notify();
    }

    pub fn remove_device(&mut self, name: &str, cx: &mut Context<Self>) {
        if !self.confirm_destructive(format!("revoke-device:{name}"), "revoke device", cx) {
            return;
        }
        match self.akey.remove_device(name) {
            Ok(_) => {
                self.notice_args(i18n::status::REVOKED_AND_REENCRYPTED, &[&name]);
                self.refresh_devices(cx);
                self.refresh_doctor(cx);
            }
            Err(e) => self.fail(format!("devices rm: {e}")),
        }
        cx.notify();
    }

    // ─────────────────────── tokens ───────────────────────

    pub fn issue_token(&mut self, cx: &mut Context<Self>) {
        let name = self.token_name.trim().to_string();
        if name.is_empty() {
            self.notice(i18n::tokens::NAME);
            cx.notify();
            return;
        }
        let ttl = self.token_ttl.trim().to_string();
        match self.akey.create_token(&name, None, true, &ttl) {
            Ok(outcome) => {
                // The plaintext token is shown once, by the CLI. It goes on the status line
                // and nowhere else — it is never stored.
                let shown = outcome
                    .data()
                    .and_then(|d| d.get("token"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                self.token_name.clear();
                self.notice_args(i18n::tokens::ISSUED, &[&name, &shown]);
                self.schedule_sensitive_status_expiry(cx);
                self.refresh_tokens(cx);
            }
            Err(e) => self.fail(format!("token create: {e}")),
        }
        cx.notify();
    }

    pub fn revoke_token(&mut self, name: &str, cx: &mut Context<Self>) {
        if !self.confirm_destructive(format!("revoke-token:{name}"), "revoke token", cx) {
            return;
        }
        match self.akey.revoke_token(name) {
            Ok(_) => {
                self.note_args(i18n::status::TOKEN_REVOKED, &[&name]);
                self.refresh_tokens(cx);
            }
            Err(e) => self.fail(format!("token rm: {e}")),
        }
        cx.notify();
    }

    // ─────────────────────── recovery ───────────────────────

    fn min_len(&self) -> Result<Option<u16>, Msg> {
        let raw = self.min_length.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        raw.parse::<u16>()
            .map(Some)
            .map_err(|_| i18n::recovery::MIN_INVALID)
    }

    pub fn submit_recovery_set(&mut self, cx: &mut Context<Self>) {
        let passphrase = self.passphrase.clone();
        if passphrase.is_empty() {
            self.notice(i18n::recovery::REQUIRED);
            cx.notify();
            return;
        }
        let min_len = match self.min_len() {
            Ok(value) => value,
            Err(msg) => {
                self.notice(msg);
                cx.notify();
                return;
            }
        };
        match self.akey.recovery_set(&passphrase, min_len) {
            Ok(_) => {
                self.passphrase.zeroize();
                self.note(i18n::recovery::SET_DONE);
                self.refresh_recovery(cx);
            }
            Err(e) => self.fail(format!("recovery set: {e}")),
        }
        cx.notify();
    }

    pub fn submit_recovery_unlock(&mut self, cx: &mut Context<Self>) {
        let passphrase = self.passphrase.clone();
        match self.akey.recovery_unlock(&passphrase) {
            Ok(_) => {
                self.passphrase.zeroize();
                self.note(i18n::recovery::VERIFIED);
            }
            Err(e) => {
                // Exit 4 here means "wrong passphrase" — expected input, not a fault.
                let msg = self.tf(i18n::recovery::NOT_VERIFIED, &[&e.to_string()]);
                self.set_status(msg, StatusKind::Notice);
            }
        }
        cx.notify();
    }

    /// Rotate: the old passphrase rides stdin, the new one the CLI's dedicated variable —
    /// one stdin cannot supply two values to a CLI that reads it to EOF.
    pub fn submit_recovery_rotate(&mut self, cx: &mut Context<Self>) {
        let old = self.passphrase.clone();
        let new = self.new_passphrase.clone();
        if old.is_empty() || new.is_empty() {
            self.notice(i18n::recovery::BOTH_REQUIRED);
            cx.notify();
            return;
        }
        let min_len = match self.min_len() {
            Ok(value) => value,
            Err(msg) => {
                self.notice(msg);
                cx.notify();
                return;
            }
        };
        match self.akey.recovery_rotate(&old, &new, min_len) {
            Ok(_) => {
                self.passphrase.zeroize();
                self.new_passphrase.zeroize();
                self.note(i18n::recovery::ROTATED);
                self.refresh_recovery(cx);
            }
            Err(e) => self.fail(format!("recovery rotate: {e}")),
        }
        cx.notify();
    }

    pub fn generate_passphrase_into_draft(&mut self, cx: &mut Context<Self>) {
        match self.akey.generate("passphrase,5") {
            Ok(passphrase) => {
                self.passphrase = Zeroizing::new(passphrase);
                self.note(i18n::recovery::GENERATED);
            }
            Err(e) => self.fail(format!("generate: {e}")),
        }
        cx.notify();
    }

    fn confirm_destructive(&mut self, key: String, action: &str, cx: &mut Context<Self>) -> bool {
        const CONFIRM_TTL: std::time::Duration = std::time::Duration::from_secs(10);
        let now = std::time::Instant::now();
        if self
            .pending_confirmation
            .as_ref()
            .is_some_and(|(pending, deadline)| pending == &key && now <= *deadline)
        {
            self.pending_confirmation = None;
            return true;
        }
        self.pending_confirmation = Some((key, now + CONFIRM_TTL));
        self.notice_args(i18n::entries::CONFIRM_ACTION, &[&action]);
        cx.notify();
        false
    }

    // ─────────────────────── input routing ───────────────────────

    /// One root-level key handler, in three layers: focus movement, then text entry for the
    /// field that has the caret, then activation of whatever the ring is on.
    pub fn on_key(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let key = event.keystroke.key.as_str();
        let shift = event.keystroke.modifiers.shift;

        // Tab moves the ring no matter where the caret is. A text field that swallowed Tab
        // would trap the keyboard, which is the failure the focus-ring rule exists to stop.
        if key == "tab" {
            self.move_focus(if shift { -1 } else { 1 }, cx);
            return;
        }
        if key == "escape" {
            self.field = Field::None;
            cx.notify();
            return;
        }

        if self.field != Field::None {
            match key {
                "backspace" => {
                    if let Some(buffer) = self.buffer_mut() {
                        buffer.pop();
                    }
                }
                "enter" => match self.field {
                    Field::EntryName | Field::EntryField | Field::EntryValue => {
                        self.submit_new_entry(cx)
                    }
                    Field::TokenName | Field::TokenTtl => self.issue_token(cx),
                    Field::Passphrase => self.submit_recovery_set(cx),
                    Field::NewPassphrase => self.submit_recovery_rotate(cx),
                    Field::MinLength | Field::None => {}
                },
                _ => {
                    if let Some(ch) = &event.keystroke.key_char
                        && !ch.is_empty()
                        && let Some(buffer) = self.buffer_mut()
                    {
                        buffer.push_str(ch);
                    }
                }
            }
            cx.notify();
            return;
        }

        // No caret. On the entry list the arrows walk the selection, because that is what
        // the focus is on; everywhere else they walk the ring.
        match (self.focus, key) {
            (Some(Focus::List), "up") => self.select_prev(cx),
            (Some(Focus::List), "down") => self.select_next(cx),
            (_, "up") | (_, "left") => self.step_focus(-1, cx),
            (_, "down") | (_, "right") => self.step_focus(1, cx),
            (_, "enter") | (_, "space") => self.activate(cx),
            _ => {}
        }
        cx.notify();
    }

    fn buffer_mut(&mut self) -> Option<&mut String> {
        match self.field {
            Field::EntryName => Some(&mut self.draft_name),
            Field::EntryField => Some(&mut self.draft_field),
            Field::EntryValue => Some(&mut self.draft_value),
            Field::TokenName => Some(&mut self.token_name),
            Field::TokenTtl => Some(&mut self.token_ttl),
            Field::Passphrase => Some(&mut self.passphrase),
            Field::NewPassphrase => Some(&mut self.new_passphrase),
            Field::MinLength => Some(&mut self.min_length),
            Field::None => None,
        }
    }

    /// Give a draft field the caret. The ring is left alone: a user who tabbed onto a field
    /// and pressed Enter should still see where they are.
    pub fn focus_field(&mut self, field: Field, cx: &mut Context<Self>) {
        self.field = field;
        cx.notify();
    }

    // ─────────────────────── keyboard focus ───────────────────────

    /// Every control the keyboard can reach, in tab order, for the current state.
    ///
    /// The header and the tab rail are always reachable; the rest depends on the visible
    /// tab and on whether this session may write. Rebuilding the list per frame is
    /// deliberate — a stale target list is how a focus ring ends up on a control that is
    /// no longer drawn.
    pub fn focus_targets(&self) -> Vec<Focus> {
        let mut targets = vec![
            Focus::ThemeDark,
            Focus::ThemeLight,
            Focus::ThemeSystem,
            Focus::Language,
        ];
        targets.extend(Tab::ALL.into_iter().map(Focus::Tab));
        match self.tab {
            Tab::Entries => {
                targets.extend([
                    Focus::FilterAll,
                    Focus::FilterFavorite,
                    Focus::FilterExpiring,
                ]);
                targets.push(Focus::Refresh);
                targets.push(Focus::List);
                if self.entries.is_empty() {
                    targets.push(Focus::ClearFilters);
                }
                if self.detail.is_some() {
                    targets.push(Focus::Reveal);
                }
                if !self.is_read_only() {
                    targets.extend([Focus::Favorite, Focus::RevealPolicy]);
                    if self
                        .detail
                        .as_ref()
                        .is_some_and(|d| d.name.contains(".conflict."))
                    {
                        targets.push(Focus::Restore);
                    }
                    targets.extend([
                        Focus::Delete,
                        Focus::Purge,
                        Focus::CatPrev,
                        Focus::CatNext,
                        Focus::FieldName,
                        Focus::FieldField,
                        Focus::FieldValue,
                        Focus::Generate,
                        Focus::Passphrase,
                        Focus::Save,
                    ]);
                }
            }
            // The other tabs have one or two actions each; the ring marks them so a
            // keyboard user can at least see where they are before reaching for the mouse.
            Tab::Sync | Tab::Devices | Tab::Tokens | Tab::Recovery | Tab::Diagnostics => {
                if !self.is_read_only() {
                    targets.push(Focus::TabPrimary);
                }
                targets.push(Focus::TabSecondary);
            }
        }
        targets
    }

    /// Whether the ring should be drawn on `target`.
    pub fn ring_on(&self, target: Focus) -> bool {
        self.keyboard_active && self.focus == Some(target)
    }

    /// Move the ring by `delta` positions, wrapping.
    pub fn move_focus(&mut self, delta: isize, cx: &mut Context<Self>) {
        self.keyboard_active = true;
        let targets = self.focus_targets();
        let current = self
            .focus
            .and_then(|f| targets.iter().position(|t| *t == f));
        if let Some(next) = wrap_index(current, targets.len(), delta) {
            self.focus = Some(targets[next]);
            cx.notify();
        }
    }

    /// Move the highlight one step without wrapping, and stop at the ends.
    fn step_focus(&mut self, delta: isize, cx: &mut Context<Self>) {
        let targets = self.focus_targets();
        let current = self
            .focus
            .and_then(|f| targets.iter().position(|t| *t == f));
        // With no ring yet there is nothing to step from, so start where Tab would.
        if current.is_none() {
            return self.move_focus(delta, cx);
        }
        if let Some(next) = clamp_index(current, targets.len(), delta) {
            self.focus = Some(targets[next]);
            cx.notify();
        }
    }

    /// Activate the focused control. Mirrors what a click on it does.
    pub fn activate(&mut self, cx: &mut Context<Self>) {
        let Some(target) = self.focus else {
            return;
        };
        match target {
            Focus::ThemeDark => self.theme_mode = ThemeMode::Dark,
            Focus::ThemeLight => self.theme_mode = ThemeMode::Light,
            Focus::ThemeSystem => self.theme_mode = ThemeMode::System,
            Focus::Language => return self.toggle_language(cx),
            Focus::Tab(tab) => {
                self.tab = tab;
                if !self.startup.is_ready() {
                    self.focus = Some(Focus::Tab(tab));
                    cx.notify();
                    return;
                }
                match tab {
                    Tab::Sync => self.load_conflicts(cx),
                    Tab::Devices => self.refresh_devices(cx),
                    Tab::Tokens => self.refresh_tokens(cx),
                    Tab::Recovery => self.refresh_recovery(cx),
                    Tab::Diagnostics => {
                        self.refresh_doctor(cx);
                        self.refresh_audit(cx);
                    }
                    Tab::Entries => self.refresh_entries(cx),
                }
                // Following a tab change, put the ring on the first control of the new tab
                // rather than leaving it on the tab it just left.
                self.focus = Some(Focus::Tab(tab));
                cx.notify();
                return;
            }
            Focus::FilterAll => {
                self.filter.all = !self.filter.all;
                return self.refresh_entries(cx);
            }
            Focus::FilterFavorite => {
                self.filter.favorite = !self.filter.favorite;
                return self.refresh_entries(cx);
            }
            Focus::FilterExpiring => {
                self.filter.expiring = match self.filter.expiring {
                    Some(_) => None,
                    None => Some("30d".to_string()),
                };
                return self.refresh_entries(cx);
            }
            Focus::Refresh => return self.refresh_all(cx),
            Focus::List => return self.reveal(cx),
            Focus::Reveal => return self.reveal(cx),
            Focus::Favorite => return self.toggle_favorite(cx),
            Focus::RevealPolicy => return self.toggle_reveal_policy(cx),
            Focus::Restore => {
                if let Some(name) = self.detail.as_ref().map(|d| d.name.clone()) {
                    return self.restore(&name, cx);
                }
                return;
            }
            Focus::Delete => return self.delete_selected(false, cx),
            Focus::Purge => return self.delete_selected(true, cx),
            Focus::FieldName => return self.focus_field(Field::EntryName, cx),
            Focus::FieldField => return self.focus_field(Field::EntryField, cx),
            Focus::FieldValue => return self.focus_field(Field::EntryValue, cx),
            Focus::Generate => return self.generate_into_draft("no-ambiguous,24", cx),
            Focus::Passphrase => return self.generate_into_draft("passphrase,5", cx),
            Focus::CatPrev => {
                self.draft_category = if self.draft_category == 0 {
                    CATEGORIES.len() - 1
                } else {
                    self.draft_category - 1
                };
                return cx.notify();
            }
            Focus::CatNext => {
                self.draft_category = (self.draft_category + 1) % CATEGORIES.len();
                return cx.notify();
            }
            Focus::Save => return self.submit_new_entry(cx),
            Focus::ClearFilters => return self.clear_filters(cx),
            Focus::TabPrimary => return self.activate_tab_primary(cx),
            Focus::TabSecondary => return self.activate_tab_secondary(cx),
        }
        cx.notify();
    }

    /// The focused tab's main action, mirroring its header button.
    fn activate_tab_primary(&mut self, cx: &mut Context<Self>) {
        match self.tab {
            Tab::Sync => self.run_sync(cx),
            Tab::Devices => self.refresh_devices(cx),
            Tab::Tokens => self.issue_token(cx),
            Tab::Recovery => self.submit_recovery_set(cx),
            Tab::Diagnostics => {
                self.refresh_doctor(cx);
                self.refresh_audit(cx);
            }
            Tab::Entries => self.refresh_entries(cx),
        }
    }

    fn activate_tab_secondary(&mut self, cx: &mut Context<Self>) {
        match self.tab {
            Tab::Sync => self.load_conflicts(cx),
            Tab::Recovery => self.submit_recovery_unlock(cx),
            _ => self.refresh_all(cx),
        }
    }

    // ─────────────────────── derived state ───────────────────────

    /// Whether this session holds a capability token. Under one, every write is refused by
    /// the CLI with exit 7, so the UI offers no write affordances.
    pub fn is_read_only(&self) -> bool {
        self.who.as_ref().is_some_and(Whoami::is_token_scoped)
    }

    pub fn doctor_has_errors(&self) -> bool {
        self.doctor
            .as_ref()
            .is_some_and(|d| d.error_checks().count() > 0)
    }

    pub fn audit_total(&self) -> usize {
        self.audit.as_ref().map(AuditReport::total).unwrap_or(0)
    }

    pub fn select_by_index(&mut self, index: usize, cx: &mut Context<Self>) {
        if let Some(entry) = self.entries.get(index) {
            let name = entry.name.clone();
            self.select(&name, cx);
        }
    }

    pub fn select_next(&mut self, cx: &mut Context<Self>) {
        let next = match self
            .selected
            .as_ref()
            .and_then(|name| self.entries.iter().position(|e| &e.name == name))
        {
            Some(ix) => ix + 1,
            None => 0,
        };
        if next < self.entries.len() {
            self.select_by_index(next, cx);
        }
    }

    pub fn select_prev(&mut self, cx: &mut Context<Self>) {
        let prev = match self
            .selected
            .as_ref()
            .and_then(|name| self.entries.iter().position(|e| &e.name == name))
        {
            Some(0) | None => return,
            Some(ix) => ix - 1,
        };
        self.select_by_index(prev, cx);
    }
}

impl Render for AkeyApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Follow the OS appearance, and expire a reveal whose 30 seconds are up, before
        // anything is drawn.
        self.system_is_dark = matches!(
            window.appearance(),
            gpui::WindowAppearance::Dark | gpui::WindowAppearance::VibrantDark
        );
        if self.reveals.tick(std::time::Instant::now()) {
            self.note(i18n::entries::REVEAL_EXPIRED);
        }

        let theme = self.theme();
        div()
            .id("akey-root")
            .size_full()
            .flex()
            .flex_col()
            .bg(gpui::rgb(theme.ground))
            .text_color(gpui::rgb(theme.ink))
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::on_key))
            .child(crate::views::header(self, cx))
            .child(crate::views::tabs(self, cx))
            .child(
                div()
                    .flex_1()
                    .w_full()
                    .overflow_hidden()
                    .child(crate::views::body(self, window, cx)),
            )
            .child(crate::views::status_bar(self))
    }
}

/// Re-exported so a view can name the primary mouse button without importing gpui.
pub const PRIMARY: MouseButton = MouseButton::Left;

/// The window title, so the vault's device is discoverable from the title bar.
pub fn window_title(who: Option<&Whoami>) -> SharedString {
    match who {
        Some(who) => format!("akey — {}", who.device).into(),
        None => "akey".into(),
    }
}

/// Kept for symmetry with [`PRIMARY`]; gpui's `ClickEvent` is the handler argument.
pub type ClickHandler = Box<dyn Fn(&ClickEvent, &mut Window, &mut App) + 'static>;

/// Step `current` by `delta`, wrapping around `len`.
///
/// With no current position the first forward step lands on the first control and the first
/// backward step on the last, so the very first Tab always shows a ring somewhere sensible.
/// Returns `None` when there is nothing to focus.
fn wrap_index(current: Option<usize>, len: usize, delta: isize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    Some(match current {
        Some(ix) => (ix as isize + delta).rem_euclid(len as isize) as usize,
        None if delta > 0 => 0,
        None => len - 1,
    })
}

/// Step `current` by `delta` and stop at the ends, the behaviour arrow keys want.
fn clamp_index(current: Option<usize>, len: usize, delta: isize) -> Option<usize> {
    let ix = current?;
    if len == 0 {
        return None;
    }
    let next = ix as isize + delta;
    (next >= 0 && (next as usize) < len).then_some(next as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every variant, so the id map can be checked exhaustively. A new control that forgets
    /// to appear here fails the first test rather than silently sharing an id at runtime.
    const ALL_FOCUS: &[Focus] = &[
        Focus::ThemeDark,
        Focus::ThemeLight,
        Focus::ThemeSystem,
        Focus::Language,
        Focus::Tab(Tab::Entries),
        Focus::Tab(Tab::Sync),
        Focus::Tab(Tab::Devices),
        Focus::Tab(Tab::Tokens),
        Focus::Tab(Tab::Recovery),
        Focus::Tab(Tab::Diagnostics),
        Focus::FilterAll,
        Focus::FilterFavorite,
        Focus::FilterExpiring,
        Focus::Refresh,
        Focus::List,
        Focus::Reveal,
        Focus::Favorite,
        Focus::RevealPolicy,
        Focus::Restore,
        Focus::Delete,
        Focus::Purge,
        Focus::FieldName,
        Focus::FieldField,
        Focus::FieldValue,
        Focus::Generate,
        Focus::Passphrase,
        Focus::CatPrev,
        Focus::CatNext,
        Focus::Save,
        Focus::TabPrimary,
        Focus::TabSecondary,
    ];

    /// The ring is drawn by matching `Focus::id()` against the element's id. If two targets
    /// shared a string, both controls would light up at once and the keyboard would appear to
    /// be in two places; if a string were empty, nothing would ever light up.
    #[test]
    fn focus_ids_are_distinct_and_non_empty() {
        let ids: HashSet<&str> = ALL_FOCUS.iter().map(|f| f.id()).collect();
        assert_eq!(
            ids.len(),
            ALL_FOCUS.len(),
            "two focus targets share an element id"
        );
        assert!(ALL_FOCUS.iter().all(|f| !f.id().is_empty()));
    }

    /// The variant list above must stay in step with the enum.
    #[test]
    fn every_tab_has_a_focus_target() {
        let targeted: HashSet<Tab> = ALL_FOCUS
            .iter()
            .filter_map(|f| match f {
                Focus::Tab(tab) => Some(*tab),
                _ => None,
            })
            .collect();
        for tab in Tab::ALL {
            assert!(targeted.contains(&tab), "{tab:?} has no focus target");
        }
        assert_eq!(targeted.len(), Tab::ALL.len());
    }

    /// Tab wraps, so the ring never gets stuck at either end of the list.
    #[test]
    fn tab_wraps_in_both_directions() {
        assert_eq!(wrap_index(Some(4), 5, 1), Some(0));
        assert_eq!(wrap_index(Some(0), 5, -1), Some(4));
        assert_eq!(wrap_index(Some(2), 5, 1), Some(3));
    }

    /// The first Tab must reveal a ring rather than landing nowhere.
    #[test]
    fn first_tab_lands_on_a_control() {
        assert_eq!(wrap_index(None, 5, 1), Some(0));
        assert_eq!(wrap_index(None, 5, -1), Some(4));
    }

    /// Arrow keys stop at the ends instead of wrapping, so holding one does not loop.
    #[test]
    fn arrows_stop_at_the_ends() {
        assert_eq!(clamp_index(Some(4), 5, 1), None);
        assert_eq!(clamp_index(Some(0), 5, -1), None);
        assert_eq!(clamp_index(Some(2), 5, 1), Some(3));
        assert_eq!(clamp_index(Some(2), 5, -1), Some(1));
    }

    /// A tab with no reachable control must not panic on Tab.
    #[test]
    fn an_empty_target_list_is_survivable() {
        assert_eq!(wrap_index(None, 0, 1), None);
        assert_eq!(wrap_index(Some(0), 0, 1), None);
        assert_eq!(clamp_index(Some(0), 0, 1), None);
        assert_eq!(clamp_index(None, 3, 1), None);
    }
}

//! Rendering for the six surfaces in `REQUIREMENTS.md` FR-29.
//!
//! Every element here is layout plus an event handler; no policy lives in this file. A
//! button asks [`crate::app::AkeyApp`] to do something, and the app asks the CLI. Whether
//! the operation is permitted is the CLI's answer.
//!
//! # Design
//!
//! **Type scale.** The first pass picked a size per element (10.5, 11, 11.5, 12, 12.5 …)
//! and read as noise. There are now seven steps and everything uses one of them.
//!
//! **Two families, with a job each.** The system grotesque carries the *interface* —
//! titles, tabs, buttons, rows, labels. Monospace carries *data* — a value, a reference, a
//! public key, and the uppercase section labels. The first pass set almost everything in
//! monospace, which reads as a terminal dump rather than a designed application. The
//! contrast between the two families is itself the technical register; there is no need to
//! add glow to get it.
//!
//! **科技感 through precision, not decoration.** The sci-fi reading comes from structure:
//! hairline rules that divide a data grid, tabular alignment with metadata right-aligned in
//! monospace, uppercase micro-labels, a cyan rail marking the selection, and exactly one
//! place where the light-cyan token is spent — the reveal, which is what this product is
//! about. No gradients, no glows, no ornamental icons.

use std::ops::Range;

use gpui::{
    Context, Div, FontWeight, IntoElement, MouseButton, Rgba, SharedString,
    StatefulInteractiveElement, Window, div, img, prelude::*, px, rgb, uniform_list,
};

use crate::app::{AkeyApp, Field, Focus, StatusKind, Tab};
use crate::i18n::{self as t, Msg};
use crate::model::CATEGORIES;
use crate::theme::{Theme, ThemeMode};
use crate::verbs::{ConflictSide, Startup};

// ─────────────────────────────── scales ───────────────────────────────

/// The type scale. Seven steps; an eighth size is a bug, not a judgement call.
mod ts {
    /// Uppercase monospace section labels — the instrument register.
    pub const LABEL: f32 = 11.5;
    /// Secondary metadata beside a primary value.
    pub const META: f32 = 11.5;
    /// Default interface text: tabs, buttons, list rows, status.
    pub const BODY: f32 = 13.0;
    /// Pane and section titles.
    pub const TITLE: f32 = 15.5;
    /// The one large thing on screen: the selected entry's name.
    pub const DISPLAY: f32 = 20.0;
    /// Values and references.
    pub const MONO: f32 = 12.0;
    /// Identifiers inside dense rows.
    pub const MONO_SM: f32 = 11.0;
}

/// The spacing scale. Four steps plus the page gutter — all on the 8/12/16 grid.
mod sp {
    pub const XS: f32 = 4.0;
    pub const SM: f32 = 8.0;
    pub const MD: f32 = 12.0;
    pub const LG: f32 = 16.0;
    pub const GUTTER: f32 = 16.0;
}

const MONO: &str = "JetBrains Mono";

/// The lockups are 1600x480.
const LOGO_ASPECT: f32 = 1600.0 / 480.0;
/// Header lockup height.
///
/// At this size the mark and the `akey` wordmark read clearly; the tagline baked into the
/// lockup below the wordmark is only a few pixels and reads as a faint rule. That is
/// inherent to the asset — the tagline is part of the PNG and
/// `assets/brand/README.md` says not to re-set the lockup's type. Enlarging it to make the
/// tagline legible would let the brand dominate the tool.
const LOGO_HEIGHT: f32 = 24.0;
const LOGO_WIDTH: f32 = LOGO_HEIGHT * LOGO_ASPECT;

const RAIL_WIDTH: f32 = 320.0;

// ─────────────────────────── colour crossing ───────────────────────────

/// Converts the theme's packed hex into gpui colours, once, in one place.
///
/// The theme is deliberately free of any gpui dependency so it can be unit-tested without a
/// GPU toolchain; this shim is the single crossing point.
#[derive(Clone, Copy)]
struct K {
    theme: Theme,
    /// The id of the focused control, if the keyboard is driving.
    focus_id: Option<&'static str>,
    keyboard: bool,
}

impl K {
    /// Build from the app, so every control knows whether it should draw the ring.
    fn for_app(app: &AkeyApp) -> Self {
        K {
            theme: app.theme(),
            focus_id: app.focus.map(Focus::id),
            keyboard: app.keyboard_active,
        }
    }

    /// Whether `id` should draw a focus ring.
    ///
    /// A visible focus indicator on interactive controls is a **High**-severity rule in the
    /// UI/UX Pro Max `ux` database. The ring only appears once the keyboard has been used,
    /// so a mouse user never sees one — the `:focus-visible` behaviour.
    fn ringed(&self, id: &str) -> bool {
        self.keyboard && self.focus_id == Some(id)
    }
    fn ground(&self) -> Rgba {
        rgb(self.theme.ground)
    }
    fn surface(&self) -> Rgba {
        rgb(self.theme.surface)
    }
    fn surface_alt(&self) -> Rgba {
        rgb(self.theme.surface_alt)
    }
    fn line(&self) -> Rgba {
        rgb(self.theme.line)
    }
    fn line_strong(&self) -> Rgba {
        rgb(self.theme.line_strong)
    }
    fn ink(&self) -> Rgba {
        rgb(self.theme.ink)
    }
    fn ink_dim(&self) -> Rgba {
        rgb(self.theme.ink_dim)
    }
    fn ink_faint(&self) -> Rgba {
        rgb(self.theme.ink_faint)
    }
    fn primary(&self) -> Rgba {
        rgb(self.theme.primary)
    }
    fn primary_hover(&self) -> Rgba {
        rgb(self.theme.primary_hover)
    }
    fn primary_text(&self) -> Rgba {
        rgb(self.theme.primary_text)
    }
    fn control_hover(&self) -> Rgba {
        rgb(self.theme.control_hover)
    }
    fn row_hover(&self) -> Rgba {
        rgb(self.theme.row_hover)
    }
    fn accent(&self) -> Rgba {
        rgb(self.theme.accent)
    }
    fn highlight(&self) -> Rgba {
        rgb(self.theme.highlight)
    }
    fn danger(&self) -> Rgba {
        rgb(self.theme.danger)
    }
    fn warn(&self) -> Rgba {
        rgb(self.theme.warn)
    }
    fn ok(&self) -> Rgba {
        rgb(self.theme.ok)
    }
}

// ─────────────────────────────── chrome ───────────────────────────────

pub fn header(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);

    // The status strip: a monospace readout, because every part of it is a value.
    let mut strip = div().flex().flex_row().items_center().gap(px(sp::MD));
    if let Some(who) = &app.who {
        strip = strip
            .child(mono(k, &who.device, ts::MONO_SM, k.ink_dim()))
            .child(sep(k))
            .child(mono(
                k,
                app.tf(t::status::ENTRIES_LOADED, &[&who.entries]),
                ts::MONO_SM,
                k.ink_dim(),
            ))
            .child(sep(k));
        strip = match &who.remote {
            Some(remote) => strip.child(mono(k, remote, ts::MONO_SM, k.ink_faint())),
            None => strip.child(mono(
                k,
                app.t(t::chrome::LOCAL_ONLY),
                ts::MONO_SM,
                k.ink_faint(),
            )),
        };
    }
    if app.is_read_only() {
        strip = strip.child(mono(
            k,
            app.t(t::chrome::TOKEN_SESSION),
            ts::MONO_SM,
            k.warn(),
        ));
    }
    if app.doctor_has_errors() {
        strip = strip.child(mono(
            k,
            app.t(t::chrome::DOCTOR_ERRORS),
            ts::MONO_SM,
            k.danger(),
        ));
    }
    if app.audit_total() > 0 {
        let n = app.audit_total();
        let label = app.tf(t::chrome::AUDIT_COUNT, &[&n]);
        strip = strip.child(mono(k, label, ts::MONO_SM, k.warn()));
    }

    let left = div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(sp::GUTTER))
        .child(
            // The real lockup for this surface. Brand rule 2: never a light-ground asset on
            // a dark page — `logo_asset()` picks per appearance.
            img(SharedString::from(app.theme().logo_asset()))
                .h(px(LOGO_HEIGHT))
                .w(px(LOGO_WIDTH))
                .flex_shrink_0(),
        )
        .child(vrule(k))
        .child(strip);

    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .w_full()
        .px(px(sp::GUTTER))
        .py(px(sp::SM))
        // The header is the **ground**, not a raised surface: the brand lockups have their
        // background baked in (`#0B1220` dark, `#F8FAFC` light), so on any other value the
        // lockup draws as a visible rectangle.
        .bg(k.ground())
        .border_b_1()
        .border_color(k.line())
        .child(left)
        .child(theme_and_language(app, k, cx))
}

/// The appearance and language controls.
///
/// All three theme modes are offered rather than a binary toggle, so "follow the system"
/// stays reachable after the user has tried an explicit one. Values are monospace and
/// uppercase: they are settings, and they read as a small instrument panel.
fn theme_and_language(app: &AkeyApp, k: K, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let mut modes = div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(1.0))
        .rounded(px(3.0))
        .bg(k.surface_alt())
        .p(px(1.0));

    for (ix, mode) in [ThemeMode::Dark, ThemeMode::Light, ThemeMode::System]
        .into_iter()
        .enumerate()
    {
        let active = app.theme_mode == mode;
        let button_id = SharedString::from(format!("theme-{}", mode.code()));
        modes = modes.child(
            div()
                .id(button_id.clone())
                .px(px(sp::SM))
                .py(px(sp::XS))
                .rounded(px(2.0))
                .cursor_pointer()
                .font_family(MONO)
                .text_size(px(ts::MONO_SM))
                .bg(if active { k.primary() } else { k.surface_alt() })
                // Always bordered, so the ring cannot shift the layout. At rest the border
                // matches the fill and disappears.
                .border_1()
                .border_color(if k.ringed(&button_id) {
                    k.accent()
                } else if active {
                    k.primary()
                } else {
                    k.surface_alt()
                })
                .text_color(if active {
                    k.primary_text()
                } else {
                    k.ink_dim()
                })
                .child(mode.label().to_lowercase())
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _ev, _w, cx| {
                        this.theme_mode = mode;
                        cx.notify();
                    }),
                ),
        );
        let _ = ix;
    }

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(sp::SM))
        .child(modes)
        .child(
            div()
                .id("lang-toggle")
                .px(px(sp::SM))
                .py(px(sp::XS))
                .rounded(px(3.0))
                .cursor_pointer()
                .font_family(MONO)
                .text_size(px(ts::MONO_SM))
                .bg(k.surface_alt())
                .text_color(k.ink_dim())
                .border_1()
                .border_color(if k.ringed("lang-toggle") {
                    k.accent()
                } else {
                    k.surface_alt()
                })
                .hover(|s| s.bg(k.control_hover()))
                .child(app.lang.native_name().to_string())
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.toggle_language(cx)),
                ),
        )
}

pub fn tabs(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let mut row = div()
        .flex()
        .flex_row()
        .items_center()
        .w_full()
        .px(px(sp::GUTTER))
        .bg(k.ground())
        .border_b_1()
        .border_color(k.line());

    for tab in Tab::ALL {
        let active = app.tab == tab;
        let tab_id = Focus::Tab(tab).id();
        row = row.child(
            div()
                .id(tab_id)
                .px(px(sp::MD))
                .pt(px(sp::MD))
                .pb(px(sp::SM))
                .cursor_pointer()
                .text_size(px(ts::BODY))
                .font_weight(if active {
                    FontWeight::MEDIUM
                } else {
                    FontWeight::NORMAL
                })
                .text_color(if active { k.ink() } else { k.ink_dim() })
                .child(app.t(tab.label()).to_string())
                // An underline in the structural cyan, not a filled pill: six filled pills
                // would be six competing shapes. Selection (active) and focus (ringed) carry
                // different weights — selection is full accent, focus alone is the strong
                // line — so a focused non-active tab does not look already selected.
                .border_b_2()
                .border_color(if active {
                    k.accent()
                } else if k.ringed(tab_id) {
                    k.line_strong()
                } else {
                    k.ground()
                })
                .hover(|s| s.text_color(k.ink()))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _ev, _w, cx| {
                        this.tab = tab;
                        if !this.startup.is_ready() {
                            cx.notify();
                            return;
                        }
                        match tab {
                            Tab::Sync => this.load_conflicts(cx),
                            Tab::Devices => this.refresh_devices(cx),
                            Tab::Tokens => this.refresh_tokens(cx),
                            Tab::Recovery => this.refresh_recovery(cx),
                            Tab::Diagnostics => {
                                this.refresh_doctor(cx);
                                this.refresh_audit(cx);
                            }
                            Tab::Entries => this.refresh_entries(cx),
                        }
                        cx.notify();
                    }),
                ),
        );
    }
    row.child(div().flex_1())
}

pub fn status_bar(app: &AkeyApp) -> impl IntoElement {
    let k = K::for_app(app);
    let color = match app.status.kind {
        StatusKind::Info => k.ink_dim(),
        StatusKind::Notice => k.warn(),
        StatusKind::Error => k.danger(),
    };
    div()
        .flex()
        .flex_row()
        .items_center()
        .w_full()
        .px(px(sp::GUTTER))
        .py(px(sp::SM))
        .bg(k.surface())
        .border_t_1()
        .border_color(k.line())
        .font_family(MONO)
        .text_size(px(ts::MONO_SM))
        .text_color(color)
        .truncate()
        .child(app.status.text.clone())
}

pub fn body(
    app: &mut AkeyApp,
    _window: &mut Window,
    cx: &mut Context<AkeyApp>,
) -> impl IntoElement {
    // FR-28: an unusable vault gets an explanation, not an empty table. The GUI does not
    // offer to initialise one — that involves a remote and a recovery passphrase, and is
    // the CLI's deliberate, explicit action.
    if !app.startup.is_ready() {
        return not_ready(app).into_any_element();
    }
    match app.tab {
        Tab::Entries => entries_tab(app, cx).into_any_element(),
        Tab::Sync => sync_tab(app, cx).into_any_element(),
        Tab::Devices => devices_tab(app, cx).into_any_element(),
        Tab::Tokens => tokens_tab(app, cx).into_any_element(),
        Tab::Recovery => recovery_tab(app, cx).into_any_element(),
        Tab::Diagnostics => diagnostics_tab(app, cx).into_any_element(),
    }
}

fn not_ready(app: &AkeyApp) -> impl IntoElement {
    let k = K::for_app(app);
    let (headline, detail) = match &app.startup {
        Startup::Ready(_) => (String::new(), String::new()),
        Startup::Uninitialized { .. } => (
            app.t(t::startup::NO_VAULT_TITLE).to_string(),
            app.t(t::startup::NO_VAULT_BODY).to_string(),
        ),
        Startup::Locked { message, hint } => (
            app.t(t::startup::LOCKED_TITLE).to_string(),
            match hint {
                Some(hint) => format!("{message}\n\n{hint}"),
                None => message.clone(),
            },
        ),
        Startup::UnsupportedFormat { message } => {
            (app.t(t::startup::FORMAT_TITLE).to_string(), message.clone())
        }
    };
    div()
        .flex()
        .flex_col()
        .size_full()
        .justify_center()
        .items_center()
        .p(px(48.0))
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap(px(sp::MD))
                .max_w(px(560.0))
                .child(
                    img(SharedString::from(app.theme().logo_asset()))
                        .h(px(38.0))
                        .w(px(38.0 * LOGO_ASPECT))
                        .flex_shrink_0(),
                )
                .child(
                    div()
                        .text_size(px(ts::TITLE))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(k.ink())
                        .child(headline),
                )
                .child(rule(k, 120.0))
                .child(
                    div()
                        .text_size(px(ts::BODY))
                        .line_height(px(ts::BODY * 1.6))
                        .text_color(k.ink_dim())
                        .child(detail),
                ),
        )
}

// ─────────────────────────────── entries ───────────────────────────────

fn entries_tab(app: &mut AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    div()
        .flex()
        .flex_row()
        .size_full()
        .child(
            div()
                .flex()
                .flex_col()
                .w(px(RAIL_WIDTH))
                .h_full()
                .border_r_1()
                .border_color(k.line())
                .child(filter_bar(app, cx))
                .child(entry_list(app, cx)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .h_full()
                .child(detail_panel(app, cx))
                .child(new_entry_form(app, cx)),
        )
}

fn filter_bar(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let expiring = app.filter.expiring.is_some();
    let category = app
        .filter
        .category
        .as_deref()
        .unwrap_or(app.t(t::entries::FILTER_ALL));
    let category_label = format!("{}: {category}", app.t(t::entries::FILTER_CATEGORY));

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(sp::XS))
        .w_full()
        .px(px(sp::MD))
        .py(px(sp::SM))
        .border_b_1()
        .border_color(k.line())
        .child(
            chip(
                k,
                "filter-all",
                app.t(t::entries::FILTER_ALL),
                app.filter.all,
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _ev, _w, cx| {
                    this.filter.all = !this.filter.all;
                    this.refresh_entries(cx);
                }),
            ),
        )
        .child(
            chip(k, "filter-fav", "★", app.filter.favorite).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _ev, _w, cx| {
                    this.filter.favorite = !this.filter.favorite;
                    this.refresh_entries(cx);
                }),
            ),
        )
        .child(
            chip(k, "filter-expiring", app.t(t::entries::EXPIRING), expiring).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _ev, _w, cx| {
                    // The window is interpreted by the CLI; the GUI only toggles it.
                    this.filter.expiring = match this.filter.expiring {
                        Some(_) => None,
                        None => Some("30d".to_string()),
                    };
                    this.refresh_entries(cx);
                }),
            ),
        )
        .child(
            div()
                .id("filter-category")
                .px(px(sp::SM))
                .py(px(3.0))
                .rounded(px(3.0))
                .cursor_pointer()
                .font_family(MONO)
                .text_size(px(ts::MONO_SM))
                .bg(k.surface())
                .text_color(if app.filter.category.is_some() {
                    k.accent()
                } else {
                    k.ink_dim()
                })
                .hover(|style| style.bg(k.control_hover()))
                .child(category_label)
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _window, cx| this.cycle_category_filter(cx)),
                ),
        )
        // Re-read the vault. This belongs at the end of the filter bar, in the same shape as
        // the chips; a bare glyph floating at the right of the tab rail read as a broken
        // overflow menu.
        .child(div().flex_1())
        .child(chip(k, "refresh-all", "↻", false).on_mouse_down(
            MouseButton::Left,
            cx.listener(|this, _ev, _w, cx| this.refresh_all(cx)),
        ))
}

fn entry_list(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let count = app.entries.len();
    if count == 0 {
        return div()
            .id("list")
            .flex_1()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap(px(sp::MD))
            .p(px(sp::LG))
            .child(
                div()
                    .text_size(px(ts::BODY))
                    .text_color(k.ink_dim())
                    .child(app.t(t::entries::NO_MATCHES).to_string()),
            )
            .child(
                // The action: most "no matches" cases are filters set too tight. Surfacing
                // the one recovery step here avoids sending the user back to the filter bar.
                chip(k, "clear-filters", app.t(t::entries::CLEAR_FILTERS), false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.clear_filters(cx)),
                ),
            )
            .into_any_element();
    }
    // `uniform_list` cannot draw a ring, so the list lives inside a container that can.
    // Without this, tabbing onto the list would highlight nothing at all.
    div()
        .id("list")
        .flex_1()
        .w_full()
        .h_full()
        .border_1()
        .border_color(if k.ringed("list") {
            k.accent()
        } else {
            k.ground()
        })
        .child(
            uniform_list(
                "entry-list",
                count,
                cx.processor(move |this, range: Range<usize>, _window, cx| {
                    let k = K::for_app(this);
                    range
                        .filter_map(|ix| this.entries.get(ix).map(|entry| (ix, entry.clone())))
                        .map(|(ix, entry)| {
                            let name = entry.name.clone();
                            let selected = this.selected.as_deref() == Some(name.as_str());

                            // Right-aligned, monospace: the flags are data, and a fixed column
                            // makes a list of them scannable.
                            let mut flags = div()
                                .flex()
                                .flex_row()
                                .items_center()
                                .gap(px(sp::SM))
                                .flex_shrink_0();
                            if entry.is_deleted() {
                                flags = flags.child(mono(
                                    k,
                                    this.t(t::entries::DELETED),
                                    ts::MONO_SM,
                                    k.danger(),
                                ));
                            }
                            if entry.is_expiring_soon() {
                                flags = flags.child(mono(
                                    k,
                                    this.t(t::entries::EXPIRING_SOON),
                                    ts::MONO_SM,
                                    k.warn(),
                                ));
                            }
                            if entry.favorite {
                                flags = flags.child(mono(k, "★", ts::MONO_SM, k.accent()));
                            }
                            flags =
                                flags.child(mono(k, &entry.category, ts::MONO_SM, k.ink_faint()));

                            div()
                                .id(ix)
                                .flex()
                                .flex_row()
                                .items_center()
                                .w_full()
                                .py(px(sp::SM))
                                .pr(px(sp::MD))
                                .cursor_pointer()
                                .bg(if selected {
                                    k.surface_alt()
                                } else {
                                    k.ground()
                                })
                                // A 2px rail in the structural cyan marks the selection: precise,
                                // and it keeps the row itself free of a box.
                                .border_l_2()
                                .border_color(if selected { k.accent() } else { k.ground() })
                                .hover(|s| s.bg(k.row_hover()))
                                .child(
                                    div().flex().flex_1().pl(px(sp::MD)).child(
                                        div()
                                            .text_size(px(ts::BODY))
                                            .font_weight(if selected {
                                                FontWeight::MEDIUM
                                            } else {
                                                FontWeight::NORMAL
                                            })
                                            .text_color(if selected {
                                                k.ink()
                                            } else {
                                                k.ink_dim()
                                            })
                                            .truncate()
                                            .child(name.clone()),
                                    ),
                                )
                                .child(flags)
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |this, _ev, _w, cx| this.select(&name, cx)),
                                )
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .h_full(),
        )
        .into_any_element()
}

fn detail_panel(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let Some(detail) = &app.detail else {
        return div()
            .flex_1()
            .flex()
            .items_center()
            .justify_center()
            .text_size(px(ts::BODY))
            .text_color(k.ink_faint())
            .child(app.t(t::entries::SELECT_AN_ENTRY).to_string())
            .into_any_element();
    };

    let revealed = app
        .reveals
        .current()
        .is_some_and(|value| value.entry_id() == detail.id);

    let mut controls = div().flex().flex_row().items_center().gap(px(sp::SM));
    if revealed {
        controls = controls
            .child(
                action(k, app.t(t::entries::HIDE), "hide", false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.hide_reveal(cx)),
                ),
            )
            .child(
                action(k, app.t(t::entries::COPY), "copy", false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.copy_revealed(cx)),
                ),
            );
    } else {
        controls = controls.child(
            action(k, app.t(t::entries::REVEAL), "reveal", true).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _ev, _w, cx| this.reveal(cx)),
            ),
        );
    }

    let mut panel = div().flex().flex_col().flex_1().overflow_hidden().child(
        div()
            .flex()
            .flex_row()
            .items_start()
            .justify_between()
            .w_full()
            .px(px(sp::LG))
            .pt(px(sp::LG))
            .pb(px(sp::MD))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(sp::XS))
                    .child(
                        div()
                            .text_size(px(ts::DISPLAY))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(k.ink())
                            .child(detail.display_title().to_string()),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap(px(sp::SM))
                            .child(mono(k, &detail.category, ts::MONO_SM, k.ink_faint()))
                            .child(mono(k, &detail.reveal, ts::MONO_SM, k.ink_faint())),
                    ),
            )
            .child(controls),
    );

    if let Some(expires) = &detail.expires_at {
        panel = panel.child(
            div()
                .px(px(sp::LG))
                .pb(px(sp::SM))
                .font_family(MONO)
                .text_size(px(ts::MONO_SM))
                .text_color(k.warn())
                .child(format!("{} {expires}", app.t(t::entries::EXPIRING_SOON))),
        );
    }

    panel = panel.child(section_label(k, "FIELDS", app));

    // A strict three-column grid: label, value, reference. The value column is monospace
    // because a credential is an identifier, and the grid is what makes a set of them
    // scannable rather than a paragraph.
    let mut fields = div().flex().flex_col().px(px(sp::LG));
    for (ix, field) in detail.fields.iter().enumerate() {
        let showing_plaintext = app.reveals.is_revealed(&detail.id, &field.id);
        let shown = if showing_plaintext {
            app.reveals
                .value_for(&detail.id, &field.id)
                .unwrap_or_default()
                .to_string()
        } else {
            field.shown_value().to_string()
        };

        let mut row = div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(sp::MD))
            .py(px(sp::SM))
            .border_b_1()
            .border_color(k.line())
            .child(
                div()
                    .w(px(112.0))
                    .flex_shrink_0()
                    .text_size(px(ts::META))
                    .text_color(k.ink_dim())
                    .child(field.label.clone()),
            )
            .child(
                div()
                    .flex_1()
                    .truncate()
                    .font_family(MONO)
                    .text_size(px(ts::MONO))
                    // The single place the light-cyan token is spent.
                    .text_color(if showing_plaintext {
                        k.highlight()
                    } else {
                        k.ink()
                    })
                    .child(shown),
            );
        if !field.reference.is_empty() {
            row = row.child(mono(k, &field.reference, ts::MONO_SM, k.ink_faint()));
        }
        if field.concealed {
            let field_id = field.id.clone();
            let edit_field_id = field.id.clone();
            let label = if showing_plaintext {
                app.t(t::entries::COPY)
            } else {
                app.t(t::entries::REVEAL)
            };
            row = row.child(
                div()
                    .id(("field-secret-action", ix))
                    .px(px(sp::SM))
                    .py(px(sp::XS))
                    .rounded(px(3.0))
                    .cursor_pointer()
                    .font_family(MONO)
                    .text_size(px(ts::MONO_SM))
                    .bg(k.surface_alt())
                    .text_color(if showing_plaintext {
                        k.highlight()
                    } else {
                        k.ink_dim()
                    })
                    .hover(|style| style.bg(k.control_hover()))
                    .child(label.to_string())
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _ev, _window, cx| {
                            if showing_plaintext {
                                this.copy_revealed_field(&field_id, cx);
                            } else {
                                this.reveal_field(&field_id, cx);
                            }
                        }),
                    ),
            );
            if !app.is_read_only() {
                row = row.child(
                    div()
                        .id(("field-edit-action", ix))
                        .px(px(sp::SM))
                        .py(px(sp::XS))
                        .rounded(px(3.0))
                        .cursor_pointer()
                        .font_family(MONO)
                        .text_size(px(ts::MONO_SM))
                        .bg(k.surface_alt())
                        .text_color(k.ink_dim())
                        .hover(|style| style.bg(k.control_hover()))
                        .child(app.t(t::entries::EDIT).to_string())
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _ev, _window, cx| {
                                this.begin_field_edit(&edit_field_id, cx)
                            }),
                        ),
                );
            }
        }
        fields = fields.child(row);
    }
    panel = panel.child(fields);

    if !app.is_read_only() {
        let name = detail.name.clone();
        let conflict = detail.name.contains(".conflict.");
        let mut ops = div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(sp::SM))
            .px(px(sp::LG))
            .py(px(sp::MD))
            .child(action(k, "★", "favorite", false).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _ev, _w, cx| this.toggle_favorite(cx)),
            ))
            .child(
                action(k, app.t(t::entries::REVEAL_POLICY), "policy", false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.toggle_reveal_policy(cx)),
                ),
            );
        if conflict {
            let restore_name = name.clone();
            ops = ops.child(
                action(k, app.t(t::entries::RESTORE), "restore", false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _ev, _w, cx| this.restore(&restore_name, cx)),
                ),
            );
        }
        ops = ops
            .child(div().flex_1())
            .child(
                action(k, app.t(t::entries::DELETE), "delete", false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.delete_selected(false, cx)),
                ),
            )
            .child(
                action_danger(k, app.t(t::entries::PURGE), "purge").on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.delete_selected(true, cx)),
                ),
            );
        panel = panel.child(ops);
    }
    panel.into_any_element()
}

fn new_entry_form(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    if app.is_read_only() {
        return div()
            .px(px(sp::LG))
            .py(px(sp::MD))
            .border_t_1()
            .border_color(k.line())
            .text_size(px(ts::META))
            .text_color(k.warn())
            .child(app.t(t::entries::READ_ONLY_NOTE).to_string())
            .into_any_element();
    }

    let category = CATEGORIES[app.draft_category.min(CATEGORIES.len() - 1)];

    div()
        .flex()
        .flex_col()
        .gap(px(sp::MD))
        .px(px(sp::LG))
        .py(px(sp::MD))
        // The top hairline separates the form from the list above. There is no panel
        // behind it: a flat form on the page ground reads as part of the same surface,
        // and avoids two stacked rectangles fighting the same edge (better-ui §"Concentric
        // border radius").
        .border_t_1()
        .border_color(k.line())
        .child(section_label(k, "NEW ENTRY", app))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(sp::SM))
                .child(
                    div()
                        .id("cat-prev")
                        .cursor_pointer()
                        .font_family(MONO)
                        .text_size(px(ts::MONO_SM))
                        // No border to spare here, so the ring shows as the accent the
                        // glyph already takes on hover.
                        .text_color(if k.ringed("cat-prev") {
                            k.accent()
                        } else {
                            k.ink_faint()
                        })
                        .hover(|s| s.text_color(k.accent()))
                        .child("‹")
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|this, _ev, _w, cx| {
                                this.draft_category = if this.draft_category == 0 {
                                    CATEGORIES.len() - 1
                                } else {
                                    this.draft_category - 1
                                };
                                cx.notify();
                            }),
                        ),
                )
                .child(mono(k, category, ts::MONO, k.accent()))
                .child(
                    div()
                        .id("cat-next")
                        .cursor_pointer()
                        .font_family(MONO)
                        .text_size(px(ts::MONO_SM))
                        .text_color(if k.ringed("cat-next") {
                            k.accent()
                        } else {
                            k.ink_faint()
                        })
                        .hover(|s| s.text_color(k.accent()))
                        .child("›")
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|this, _ev, _w, cx| {
                                this.draft_category = (this.draft_category + 1) % CATEGORIES.len();
                                cx.notify();
                            }),
                        ),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(sp::MD))
                .child(text_field(
                    k,
                    app,
                    "draft-name",
                    t::entries::FIELD_NAME,
                    &app.draft_name,
                    Field::EntryName,
                    false,
                    cx,
                ))
                .child(text_field(
                    k,
                    app,
                    "draft-field",
                    t::entries::FIELD_FIELD,
                    &app.draft_field,
                    Field::EntryField,
                    false,
                    cx,
                )),
        )
        .child(text_field(
            k,
            app,
            "draft-value",
            t::entries::FIELD_VALUE,
            &app.draft_value,
            Field::EntryValue,
            true,
            cx,
        ))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(sp::SM))
                .child(
                    action(k, app.t(t::entries::GENERATE), "gen-default", false).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _ev, _w, cx| {
                            this.generate_into_draft("no-ambiguous,24", cx)
                        }),
                    ),
                )
                .child(
                    action(k, app.t(t::entries::PASSPHRASE), "gen-pass", false).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _ev, _w, cx| {
                            this.generate_into_draft("passphrase,5", cx)
                        }),
                    ),
                )
                .child(div().flex_1())
                .child(
                    action(k, app.t(t::entries::SAVE), "save", true).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _ev, _w, cx| this.submit_new_entry(cx)),
                    ),
                ),
        )
        .into_any_element()
}

// ─────────────────────────────── sync ───────────────────────────────

fn sync_tab(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let mut panel = div().flex().flex_col().size_full().child(
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(sp::SM))
            .w_full()
            .px(px(sp::LG))
            .py(px(sp::MD))
            .border_b_1()
            .border_color(k.line())
            .child(
                action(k, app.t(t::sync::SYNC_NOW), "sync", true).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.run_sync(cx)),
                ),
            )
            .child(
                action(k, app.t(t::sync::RELOAD), "reload-conflicts", false).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _ev, _w, cx| this.load_conflicts(cx)),
                ),
            ),
    );

    if let Some(result) = &app.sync {
        let mut block = div()
            .flex()
            .flex_col()
            .gap(px(sp::MD))
            .px(px(sp::LG))
            .py(px(sp::MD))
            .child(mono(k, result.summary(), ts::MONO, k.ink()));
        if result.conflicts_pending {
            block = block.child(
                div()
                    .text_size(px(ts::META))
                    .line_height(px(ts::META * 1.6))
                    .text_color(k.warn())
                    .max_w(px(620.0))
                    .child(app.t(t::sync::CONFLICTS_PENDING).to_string()),
            );
        }
        if let Some(report) = &result.report
            && !report.pending_recipients.is_empty()
        {
            let mut pending = div().flex().flex_col().gap(px(sp::SM)).child(
                div()
                    .text_size(px(ts::META))
                    .line_height(px(ts::META * 1.6))
                    .text_color(k.warn())
                    .max_w(px(620.0))
                    .child(app.t(t::sync::PENDING_RECIPIENTS).to_string()),
            );
            for recipient in &report.pending_recipients {
                let name = recipient.name.clone();
                pending = pending.child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap(px(sp::MD))
                        .child(mono(k, &recipient.pubkey, ts::MONO_SM, k.ink_faint()))
                        .child(
                            div()
                                .text_size(px(ts::BODY))
                                .text_color(k.ink())
                                .child(recipient.name.clone()),
                        )
                        .child(
                            action(k, app.t(t::sync::TRUST), "trust-pending", false).on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |this, _ev, _w, cx| this.trust_device(&name, cx)),
                            ),
                        ),
                );
            }
            block = block.child(pending);
        }
        panel = panel.child(block);
    }

    let conflicts = app
        .conflicts
        .as_ref()
        .map(|c| c.conflicts.clone())
        .unwrap_or_default();
    if conflicts.is_empty() {
        panel = panel.child(
            div()
                .px(px(sp::LG))
                .text_size(px(ts::BODY))
                .text_color(k.ink_faint())
                .child(app.t(t::sync::NO_CONFLICTS).to_string()),
        );
    } else {
        let mut list = div().flex().flex_col().px(px(sp::LG));
        for conflict in conflicts {
            let name = conflict.name.clone();
            let ours = name.clone();
            let theirs = name.clone();
            let mut row = div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(sp::MD))
                .py(px(sp::SM))
                .border_b_1()
                .border_color(k.line())
                .child(
                    div()
                        .text_size(px(ts::BODY))
                        .text_color(k.ink())
                        .child(name.clone()),
                );
            if let Some(other) = &conflict.other_device {
                row = row.child(mono(
                    k,
                    app.tf(t::sync::VS, &[other]),
                    ts::MONO_SM,
                    k.ink_faint(),
                ));
            }
            row = row
                .child(div().flex_1())
                .child(
                    action(k, app.t(t::sync::KEEP_OURS), "ours", false).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _ev, _w, cx| {
                            this.resolve(&ours, ConflictSide::Ours, cx)
                        }),
                    ),
                )
                .child(
                    action(k, app.t(t::sync::TAKE_THEIRS), "theirs", false).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _ev, _w, cx| {
                            this.resolve(&theirs, ConflictSide::Theirs, cx)
                        }),
                    ),
                );
            list = list.child(row);
        }
        panel = panel.child(list);
    }
    panel
}

// ─────────────────────────────── devices ───────────────────────────────

fn devices_tab(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let devices = app
        .devices
        .as_ref()
        .map(|d| d.devices.clone())
        .unwrap_or_default();

    let mut panel = div().flex().flex_col().size_full().child(section_header(
        k,
        app.t(t::devices::TITLE),
        app.t(t::devices::RELOAD),
        "reload-devices",
        cx,
        |this, cx| this.refresh_devices(cx),
    ));

    if devices.is_empty() {
        panel = panel.child(empty_note(k, app.t(t::devices::NONE)));
        return panel;
    }

    for device in devices {
        let name = device.name.clone();
        let trust = name.clone();
        let untrust = name.clone();
        let remove = name.clone();
        let mut row = div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(sp::MD))
            .px(px(sp::LG))
            .py(px(sp::MD))
            .border_b_1()
            .border_color(k.line())
            .child(
                div()
                    .w(px(140.0))
                    .text_size(px(ts::BODY))
                    .text_color(k.ink())
                    .truncate()
                    .child(name.clone()),
            )
            .child(mono(k, &device.kind, ts::MONO_SM, k.ink_faint()));

        if device.this_device {
            row = row.child(mono(k, app.t(t::devices::THIS_DEVICE), ts::MONO_SM, k.ok()));
        }
        if !device.active {
            row = row.child(mono(k, app.t(t::devices::REVOKED), ts::MONO_SM, k.danger()));
        }
        row = row
            .child(div().flex_1())
            .child(mono(k, &device.pubkey, ts::MONO_SM, k.ink_faint()));

        if !app.is_read_only() {
            row = row
                .child(
                    action(k, app.t(t::sync::TRUST), "trust-dev", false).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _ev, _w, cx| this.trust_device(&trust, cx)),
                    ),
                )
                .child(
                    action(k, app.t(t::devices::UNTRUST), "untrust-dev", false).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _ev, _w, cx| this.untrust_device(&untrust, cx)),
                    ),
                )
                .child(
                    action_danger(k, app.t(t::devices::REVOKE), "rm-dev").on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _ev, _w, cx| this.remove_device(&remove, cx)),
                    ),
                );
        }
        panel = panel.child(row);
    }
    panel
}

// ─────────────────────────────── tokens ───────────────────────────────

fn tokens_tab(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let tokens = app
        .tokens
        .as_ref()
        .map(|t| t.tokens.clone())
        .unwrap_or_default();

    let mut panel = div().flex().flex_col().size_full().child(section_header(
        k,
        app.t(t::tokens::TITLE),
        app.t(t::tokens::RELOAD),
        "reload-tokens",
        cx,
        |this, cx| this.refresh_tokens(cx),
    ));

    if !app.is_read_only() {
        panel = panel.child(
            div()
                .flex()
                .flex_col()
                .gap(px(sp::MD))
                .px(px(sp::LG))
                .py(px(sp::MD))
                .border_b_1()
                .border_color(k.line())
                .child(
                    div()
                        .text_size(px(ts::META))
                        .line_height(px(ts::META * 1.6))
                        .text_color(k.ink_faint())
                        .max_w(px(560.0))
                        .child(app.t(t::tokens::EXPLAINER).to_string()),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(sp::MD))
                        .child(text_field(
                            k,
                            app,
                            "token-name",
                            t::tokens::NAME,
                            &app.token_name,
                            Field::TokenName,
                            false,
                            cx,
                        ))
                        .child(text_field(
                            k,
                            app,
                            "token-ttl",
                            t::tokens::TTL,
                            &app.token_ttl,
                            Field::TokenTtl,
                            false,
                            cx,
                        )),
                )
                .child(
                    action(k, app.t(t::tokens::ISSUE), "issue-token", true).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _ev, _w, cx| this.issue_token(cx)),
                    ),
                ),
        );
    }

    if tokens.is_empty() {
        panel = panel.child(empty_note(k, app.t(t::tokens::NONE)));
        return panel;
    }

    for token in tokens {
        let name = token.name.clone();
        let revoke = name.clone();
        let mut row = div()
            .flex()
            .flex_row()
            .items_center()
            .gap(px(sp::MD))
            .px(px(sp::LG))
            .py(px(sp::MD))
            .border_b_1()
            .border_color(k.line())
            .child(
                div()
                    .w(px(140.0))
                    .text_size(px(ts::BODY))
                    .text_color(k.ink())
                    .truncate()
                    .child(name.clone()),
            )
            .child(mono(k, token.allow_summary(), ts::MONO_SM, k.ink_faint()));
        if token.deny_reveal {
            row = row.child(mono(k, app.t(t::tokens::DENY_REVEAL), ts::MONO_SM, k.ok()));
        }
        if let Some(expires) = &token.expires_at {
            row = row.child(mono(
                k,
                app.tf(t::tokens::EXPIRES, &[expires]),
                ts::MONO_SM,
                k.ink_faint(),
            ));
        }
        if !token.active {
            row = row.child(mono(k, app.t(t::tokens::INACTIVE), ts::MONO_SM, k.danger()));
        }
        row = row.child(div().flex_1());
        if !app.is_read_only() {
            row = row.child(
                action_danger(k, app.t(t::devices::REVOKE), "rm-token").on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _ev, _w, cx| this.revoke_token(&revoke, cx)),
                ),
            );
        }
        panel = panel.child(row);
    }
    panel
}

// ─────────────────────────────── recovery ───────────────────────────────

fn recovery_tab(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let mut panel = div().flex().flex_col().size_full().child(section_header(
        k,
        app.t(t::recovery::TITLE),
        app.t(t::recovery::VERIFY),
        "unlock-recovery",
        cx,
        |this, cx| this.submit_recovery_unlock(cx),
    ));

    match &app.recovery {
        Some(status) => {
            let mut row = div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(sp::MD))
                .px(px(sp::LG))
                .py(px(sp::MD));
            row = row.child(if status.configured {
                mono(k, app.t(t::recovery::CONFIGURED), ts::MONO_SM, k.ok())
            } else {
                mono(
                    k,
                    app.t(t::recovery::NOT_CONFIGURED),
                    ts::MONO_SM,
                    k.danger(),
                )
            });
            row = row.child(mono(
                k,
                app.tf(t::recovery::MIN_LENGTH, &[&status.min_length]),
                ts::MONO_SM,
                k.ink_faint(),
            ));
            row = row.child(mono(k, &status.strength, ts::MONO_SM, k.ink_faint()));
            panel = panel.child(row);
        }
        None => panel = panel.child(empty_note(k, app.t(t::recovery::STATUS_UNAVAILABLE))),
    }

    if app.is_read_only() {
        panel = panel.child(empty_note(k, app.t(t::recovery::NEEDS_IDENTITY)));
        return panel;
    }

    panel = panel.child(
        div()
            .flex()
            .flex_col()
            .gap(px(sp::MD))
            .px(px(sp::LG))
            .py(px(sp::MD))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap(px(sp::MD))
                    .child(text_field(
                        k,
                        app,
                        "recovery-pass",
                        t::recovery::FIELD_PASSPHRASE,
                        &app.passphrase,
                        Field::Passphrase,
                        true,
                        cx,
                    ))
                    .child(text_field(
                        k,
                        app,
                        "recovery-new",
                        t::recovery::FIELD_NEW,
                        &app.new_passphrase,
                        Field::NewPassphrase,
                        true,
                        cx,
                    ))
                    .child(text_field(
                        k,
                        app,
                        "recovery-min",
                        t::recovery::FIELD_MIN,
                        &app.min_length,
                        Field::MinLength,
                        false,
                        cx,
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(sp::SM))
                    .child(
                        action(k, app.t(t::recovery::GENERATE), "gen-recovery", false)
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _ev, _w, cx| {
                                    this.generate_passphrase_into_draft(cx)
                                }),
                            ),
                    )
                    .child(
                        action(k, app.t(t::recovery::SET), "set-recovery", true).on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|this, _ev, _w, cx| this.submit_recovery_set(cx)),
                        ),
                    )
                    .child(
                        action(k, app.t(t::recovery::ROTATE), "rotate-recovery", false)
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _ev, _w, cx| this.submit_recovery_rotate(cx)),
                            ),
                    ),
            ),
    );
    panel
}

// ─────────────────────────────── diagnostics ───────────────────────────────

fn diagnostics_tab(app: &AkeyApp, cx: &mut Context<AkeyApp>) -> impl IntoElement {
    let k = K::for_app(app);
    let mut panel = div().flex().flex_col().size_full().child(section_header(
        k,
        app.t(t::diagnostics::TITLE),
        app.t(t::diagnostics::RERUN),
        "rerun-diag",
        cx,
        |this, cx| {
            this.refresh_doctor(cx);
            this.refresh_audit(cx);
        },
    ));

    if let Some(doctor) = &app.doctor {
        let mut block = div().flex().flex_col();
        block = block.child(section_label(k, "DOCTOR", app));
        for check in &doctor.checks {
            let color = if check.is_error() {
                k.danger()
            } else if check.is_warning() {
                k.warn()
            } else {
                k.ok()
            };
            block = block.child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(sp::MD))
                    .px(px(sp::LG))
                    .py(px(sp::SM))
                    .border_b_1()
                    .border_color(k.line())
                    // The status is a word in a colour rather than a pill: fifteen pills in
                    // a column is a wall; fifteen words is a list.
                    .child(
                        div()
                            .w(px(64.0))
                            .flex_shrink_0()
                            .font_family(MONO)
                            .text_size(px(ts::MONO_SM))
                            .text_color(color)
                            .child(check.status.clone()),
                    )
                    .child(
                        div()
                            .w(px(190.0))
                            .flex_shrink_0()
                            .font_family(MONO)
                            .text_size(px(ts::MONO_SM))
                            .text_color(k.ink())
                            .child(check.name.clone()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .truncate()
                            .text_size(px(ts::META))
                            .text_color(k.ink_faint())
                            .child(check.detail.clone()),
                    ),
            );
        }
        panel = panel.child(block);
    }

    if let Some(audit) = &app.audit {
        let mut block = div().flex().flex_col();
        block = block.child(section_label(k, "AUDIT", app));
        if audit.is_clean() {
            block = block.child(
                div()
                    .px(px(sp::LG))
                    .py(px(sp::SM))
                    .font_family(MONO)
                    .text_size(px(ts::MONO_SM))
                    .text_color(k.ok())
                    .child(app.t(t::diagnostics::NO_FINDINGS).to_string()),
            );
        }
        for hit in &audit.weak {
            block = block.child(finding(
                k,
                app.t(t::diagnostics::WEAK),
                &format!("{}.{}", hit.name, hit.field),
                &hit.reason,
            ));
        }
        for hit in &audit.reused {
            block = block.child(finding(
                k,
                app.t(t::diagnostics::REUSED),
                &hit.entries.join(", "),
                &hit.field,
            ));
        }
        for hit in &audit.stale {
            let detail = app.tf(
                t::diagnostics::DAYS_SINCE_ROTATION,
                &[&hit.days_since_rotation],
            );
            block = block.child(finding(k, app.t(t::diagnostics::STALE), &hit.name, &detail));
        }
        for hit in &audit.expiring {
            block = block.child(finding(
                k,
                app.t(t::diagnostics::EXPIRING),
                &hit.name,
                &hit.expires_at,
            ));
        }
        panel = panel.child(block);
    }
    panel
}

// ─────────────────────────────── primitives ───────────────────────────────

/// A one-pixel vertical rule: the brand's cyan at low alpha, used for structure.
fn vrule(k: K) -> Div {
    div()
        .w(px(1.0))
        .h(px(16.0))
        .flex_shrink_0()
        .bg(k.line_strong())
}

/// A short horizontal rule, used where a hairline separates rather than divides.
fn rule(k: K, width: f32) -> Div {
    div()
        .w(px(width))
        .h(px(1.0))
        .flex_shrink_0()
        .bg(k.line_strong())
}

/// The separator between values in a dense monospace readout.
fn sep(k: K) -> Div {
    div()
        .font_family(MONO)
        .text_size(px(ts::MONO_SM))
        .text_color(k.line_strong())
        .child("·")
}

/// Monospace text at a chosen step and colour. The data voice.
fn mono(k: K, text: impl AsRef<str>, size: f32, color: Rgba) -> Div {
    let _ = k;
    div()
        .font_family(MONO)
        .text_size(px(size))
        .text_color(color)
        .truncate()
        .child(text.as_ref().to_string())
}

/// An uppercase monospace micro-label. The instrument-panel register, and the reason the
/// section headings read as structure rather than as another line of prose.
fn section_label(k: K, text: &str, _app: &AkeyApp) -> Div {
    div()
        .px(px(sp::LG))
        .pt(px(sp::MD))
        .pb(px(sp::XS))
        .font_family(MONO)
        .text_size(px(ts::LABEL))
        .text_color(k.ink_dim())
        .child(text.to_string())
}

fn empty_note(k: K, text: impl AsRef<str>) -> Div {
    div()
        .px(px(sp::LG))
        .py(px(sp::MD))
        .text_size(px(ts::BODY))
        .text_color(k.ink_faint())
        .child(text.as_ref().to_string())
}

/// A toggle. It holds state, so it is allowed a filled shape; a button is not.
///
/// The return type is opaque and carries `StatefulInteractiveElement`, because that is the
/// trait `on_mouse_down` lives on — `div().id(..)` yields a `Stateful<Div>`, not a `Div`.
fn chip(
    k: K,
    id: &'static str,
    label: &'static str,
    active: bool,
) -> impl StatefulInteractiveElement + IntoElement {
    div()
        .id(id)
        .px(px(sp::SM))
        .py(px(3.0))
        .rounded(px(3.0))
        .cursor_pointer()
        // The chips are boolean data, like every other tabular control; JetBrains Mono
        // at MONO_SM keeps one optical strategy across the header and filter bar.
        .text_size(px(ts::MONO_SM))
        .font_family(MONO)
        .bg(if active { k.primary() } else { k.surface() })
        .text_color(if active {
            k.primary_text()
        } else {
            k.ink_dim()
        })
        .border_1()
        .border_color(if k.ringed(id) {
            k.accent()
        } else if active {
            k.primary()
        } else {
            k.surface()
        })
        .hover(|s| {
            s.bg(if active {
                k.primary_hover()
            } else {
                k.control_hover()
            })
        })
        .child(label.to_string())
}

fn section_header(
    k: K,
    title: &'static str,
    action_label: &'static str,
    action_id: &'static str,
    cx: &mut Context<AkeyApp>,
    on_press: fn(&mut AkeyApp, &mut Context<AkeyApp>),
) -> Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .w_full()
        .px(px(sp::LG))
        .py(px(sp::MD))
        .border_b_1()
        .border_color(k.line())
        .child(
            div()
                .text_size(px(ts::TITLE))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(k.ink())
                .child(title.to_string()),
        )
        .child(action(k, action_label, action_id, false).on_mouse_down(
            MouseButton::Left,
            cx.listener(move |this, _ev, _w, cx| on_press(this, cx)),
        ))
}

fn finding(k: K, group: &'static str, name: &str, detail: impl AsRef<str>) -> Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(sp::MD))
        .px(px(sp::LG))
        .py(px(sp::SM))
        .border_b_1()
        .border_color(k.line())
        .child(
            div()
                .w(px(64.0))
                .flex_shrink_0()
                .font_family(MONO)
                .text_size(px(ts::LABEL))
                .text_color(k.warn())
                .child(group.to_string()),
        )
        .child(
            div()
                .w(px(190.0))
                .flex_shrink_0()
                .truncate()
                .text_size(px(ts::BODY))
                .text_color(k.ink())
                .child(name.to_string()),
        )
        .child(
            div()
                .flex_1()
                .truncate()
                .text_size(px(ts::META))
                .text_color(k.ink_faint())
                .child(detail.as_ref().to_string()),
        )
}

/// A button. `primary` fills with the brand blue; otherwise it is a quiet filled button a
/// step off the surface — deliberately not a box with a border.
fn action(
    k: K,
    label: &'static str,
    id: &'static str,
    primary: bool,
) -> impl StatefulInteractiveElement + IntoElement {
    let base = div()
        .id(id)
        .px(px(sp::MD))
        .py(px(5.0))
        .rounded(px(3.0))
        .cursor_pointer()
        .text_size(px(ts::BODY))
        .font_weight(FontWeight::MEDIUM)
        // The border is always present, so turning the ring on cannot shift the layout by
        // a pixel. At rest it is the button's own fill and therefore invisible.
        .border_1();
    if primary {
        base.bg(k.primary())
            .text_color(k.primary_text())
            .border_color(if k.ringed(id) {
                k.accent()
            } else {
                k.primary()
            })
            .hover(|s| s.bg(k.primary_hover()))
            .child(label.to_string())
    } else {
        base.bg(k.surface_alt())
            .text_color(k.ink_dim())
            .border_color(if k.ringed(id) {
                k.accent()
            } else {
                k.surface_alt()
            })
            .hover(|s| s.bg(k.control_hover()))
            .child(label.to_string())
    }
}

fn action_danger(
    k: K,
    label: &'static str,
    id: &'static str,
) -> impl StatefulInteractiveElement + IntoElement {
    div()
        .id(id)
        .px(px(sp::MD))
        .py(px(5.0))
        .rounded(px(3.0))
        .cursor_pointer()
        .text_size(px(ts::BODY))
        .font_weight(FontWeight::MEDIUM)
        .bg(k.surface_alt())
        .text_color(k.danger())
        .border_1()
        .border_color(if k.ringed(id) {
            k.accent()
        } else {
            k.surface_alt()
        })
        .hover(|s| s.bg(k.control_hover()))
        .child(label.to_string())
}

/// A single-line draft field.
///
/// Not a full text editor: no IME, no selection, no cursor movement. It appends printable
/// characters and pops on backspace, which is enough for entry names, field names, token
/// names and passphrases. A rich editor is the follow-up if this proves insufficient.
#[allow(clippy::too_many_arguments)]
fn text_field(
    k: K,
    app: &AkeyApp,
    id: &'static str,
    label: Msg,
    value: &str,
    field: Field,
    masked: bool,
    cx: &mut Context<AkeyApp>,
) -> Div {
    let focused = app.field == field;
    let shown = if value.is_empty() {
        "—".to_string()
    } else if masked {
        // Masked on screen for the same reason the value is masked in a child's output:
        // shoulder-surfing and screenshots are the threat, not memory.
        "•".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    div()
        .flex()
        .flex_col()
        .gap(px(sp::XS))
        .flex_1()
        .child(
            div()
                .text_size(px(ts::META))
                // `ink_dim` composites above 3:1 (theme test); `ink_faint` is reserved for
                // icons and separator dots. Field labels carry information, not decoration.
                .text_color(k.ink_dim())
                .child(app.t(label).to_string()),
        )
        .child(
            div()
                .id(id)
                .w_full()
                .px(px(sp::SM))
                .py(px(6.0))
                .rounded(px(3.0))
                .cursor_pointer()
                .font_family(MONO)
                .text_size(px(ts::MONO))
                // The form sits on the page ground (no panel behind it, per the audit on
                // `new_entry_form`); the input itself lifts to `surface_alt` so it reads
                // as a raised control on a flat form.
                .bg(k.surface_alt())
                .text_color(if value.is_empty() {
                    k.ink_faint()
                } else {
                    k.ink()
                })
                .border_1()
                // The accent border already marks the field that holds the caret; the ring
                // marks the field the keyboard has reached. Either one lights it.
                .border_color(if focused || k.ringed(id) {
                    k.accent()
                } else {
                    k.line()
                })
                .truncate()
                .child(shown)
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _ev, _w, cx| this.focus_field(field, cx)),
                ),
        )
}

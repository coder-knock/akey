//! Light and dark themes, built from the akey brand tokens rather than invented.
//!
//! `assets/brand/README.md` is the authority: it names the surfaces (`#0B1220` dark,
//! `#F8FAFC` light) and the structural colours (`#2563EB` letterform, `#06B6D4`
//! connections, `#22D3EE` chevron/nodes). The mark "cannot be read without" its keyhole;
//! the UI should be recognisably the same product in either appearance.
//!
//! The idea the two themes share is the brand's own pairing — **navy and light swap
//! roles**:
//!
//! | | ground | ink |
//! |---|---|---|
//! | dark | navy `#0B1220` | light `#F8FAFC` |
//! | light | light `#F8FAFC` | navy `#0B1220` |
//!
//! `#2563EB` and `#06B6D4` are mid-tone and stay put in both. Nothing below is a third
//! palette: every token is a brand value, a translucent form of one, or a severity colour
//! the brand does not define (and which is marked as such).
//!
//! Colours are held as packed `u32` hex — the unit the brand spec is written in, exactly
//! comparable in tests, and free of any GPU dependency. The views convert with `rgb()`
//! when they build an element, so this module compiles and is tested without `gpui`.

/// The brand palette, verbatim from `assets/brand/README.md` → "Colour".
pub mod brand {
    /// Deep navy — the dark background.
    pub const NAVY: u32 = 0x0B1220;
    /// Primary blue — the letterform. Trust, technical.
    pub const BLUE: u32 = 0x2563EB;
    /// Cyan — structure and connections.
    pub const CYAN: u32 = 0x06B6D4;
    /// Light cyan — the chevron and the node ring.
    pub const LIGHT_CYAN: u32 = 0x22D3EE;
    /// Light surface, and the keyhole. Not `#FFFFFF` — keep it that way.
    pub const LIGHT: u32 = 0xF8FAFC;
}

/// Severity colours.
///
/// The brand defines none. Inventing brand-adjacent hues for them would be worse than
/// admitting they are functional: they are the only non-brand colours in the UI, chosen to
/// sit beside the brand's cool tones and to clear a contrast floor on both grounds.
mod severity {
    pub const DANGER_DARK: u32 = 0xF87171;
    pub const DANGER_LIGHT: u32 = 0xB91C1C;
    pub const WARN_DARK: u32 = 0xFBBF24;
    pub const WARN_LIGHT: u32 = 0x92400E;
    pub const OK_DARK: u32 = 0x34D399;
    pub const OK_LIGHT: u32 = 0x047857;
}

/// Which appearance to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    Dark,
    Light,
    /// Follow the window server. The default — a desktop app that ignores the system
    /// setting feels broken.
    #[default]
    System,
}

impl ThemeMode {
    pub fn code(self) -> &'static str {
        match self {
            ThemeMode::Dark => "dark",
            ThemeMode::Light => "light",
            ThemeMode::System => "system",
        }
    }

    /// The mode's own name for the switcher.
    pub fn label(self) -> &'static str {
        match self {
            ThemeMode::Dark => "Dark",
            ThemeMode::Light => "Light",
            ThemeMode::System => "System",
        }
    }

    /// Parse `dark` / `light` / `system`; `auto` is accepted as a synonym for `system`.
    pub fn from_tag(tag: &str) -> Option<ThemeMode> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(ThemeMode::Dark),
            "light" => Some(ThemeMode::Light),
            "system" | "auto" => Some(ThemeMode::System),
            _ => None,
        }
    }

    /// `$AKEY_GUI_THEME`, else `System`.
    pub fn resolve(explicit: Option<&str>) -> ThemeMode {
        explicit
            .and_then(ThemeMode::from_tag)
            .or_else(|| {
                std::env::var("AKEY_GUI_THEME")
                    .ok()
                    .and_then(|tag| ThemeMode::from_tag(&tag))
            })
            .unwrap_or(ThemeMode::System)
    }

    /// The mode actually in effect, given whether the window server reports dark.
    pub fn effective(self, system_is_dark: bool) -> ThemeMode {
        match self {
            ThemeMode::Dark => ThemeMode::Dark,
            ThemeMode::Light => ThemeMode::Light,
            ThemeMode::System if system_is_dark => ThemeMode::Dark,
            ThemeMode::System => ThemeMode::Light,
        }
    }

    /// What the header toggle switches to. Always lands on an explicit mode, so one click
    /// from `System` does not immediately snap back to whatever the system says.
    pub fn flipped(self, system_is_dark: bool) -> ThemeMode {
        match self.effective(system_is_dark) {
            ThemeMode::Dark => ThemeMode::Light,
            _ => ThemeMode::Dark,
        }
    }
}

/// One appearance's resolved colours, as packed `RRGGBB` or `RRGGBBAA` hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// `true` for the dark appearance. Views branch on this only where a colour cannot
    /// express the difference — which logo file to load, mainly.
    pub is_dark: bool,

    pub ground: u32,
    pub surface: u32,
    pub surface_alt: u32,
    /// Hairline dividers: a translucent cyan, not a grey. The brand's "structure and
    /// connections" colour, used for structure.
    pub line: u32,
    /// A stronger divider for the one boundary that matters most on screen.
    pub line_strong: u32,

    pub ink: u32,
    pub ink_dim: u32,
    pub ink_faint: u32,

    pub primary: u32,
    pub primary_hover: u32,
    pub primary_text: u32,

    /// Hover for a filled control resting on `surface_alt`. The UI/UX Pro Max `ux`
    /// database rates a missing hover state Medium severity: "change cursor and add subtle
    /// visual change". A hover value belongs to the palette rather than to a view, so that
    /// every control hovers by the same rule.
    pub control_hover: u32,
    /// Hover for a row resting on `ground` — one step toward the surface.
    pub row_hover: u32,

    /// Cyan — structure.
    pub accent: u32,
    /// Reserved for the reveal: the one moment this product is about.
    pub highlight: u32,
    pub highlight_text: u32,

    pub danger: u32,
    pub warn: u32,
    pub ok: u32,
}

impl Theme {
    /// The dark appearance: navy ground, light ink.
    pub fn dark() -> Theme {
        Theme {
            is_dark: true,

            ground: brand::NAVY,
            // Lifts of navy that stay in the navy family. A lifted tint of the ground
            // reads as the same surface at a different depth; a neutral grey reads as a
            // foreign panel pasted on top.
            surface: 0x121C30,
            surface_alt: 0x18243B,
            line: 0x06B6D426,
            line_strong: 0x06B6D459,

            ink: brand::LIGHT,
            ink_dim: 0xF8FAFC9E,
            ink_faint: 0xF8FAFC59,

            primary: brand::BLUE,
            primary_hover: 0x3B82F6,
            primary_text: brand::LIGHT,

            control_hover: 0x1F2D4A,
            row_hover: 0x111B2E,

            accent: brand::CYAN,
            highlight: brand::LIGHT_CYAN,
            highlight_text: brand::NAVY,

            danger: severity::DANGER_DARK,
            warn: severity::WARN_DARK,
            ok: severity::OK_DARK,
        }
    }

    /// The light appearance: light ground, navy ink. This is the surface the brand's
    /// `-light` assets are drawn for.
    pub fn light() -> Theme {
        Theme {
            is_dark: false,

            ground: brand::LIGHT,
            surface: 0xFFFFFF,
            surface_alt: 0xF1F5F9,
            line: 0x0B12201F,
            line_strong: 0x0B12204D,

            ink: brand::NAVY,
            ink_dim: 0x0B1220A6,
            ink_faint: 0x0B122059,

            primary: brand::BLUE,
            primary_hover: 0x1D4ED8,
            primary_text: brand::LIGHT,

            control_hover: 0xE2E8F0,
            row_hover: 0xEEF2F7,

            accent: brand::CYAN,
            // `#22D3EE` is too pale to carry emphasis on a white ground; the darker cyan
            // keeps the token's identity while meeting the contrast floor.
            highlight: brand::CYAN,
            // Navy on cyan, in both appearances. The light surface `#F8FAFC` on `#06B6D4`
            // is only 2.3:1 — the brand's own navy is the readable choice, and it is what
            // the dark appearance uses too, so the highlight reads the same either way.
            highlight_text: brand::NAVY,

            danger: severity::DANGER_LIGHT,
            warn: severity::WARN_LIGHT,
            ok: severity::OK_LIGHT,
        }
    }

    pub fn resolve(mode: ThemeMode, system_is_dark: bool) -> Theme {
        match mode.effective(system_is_dark) {
            ThemeMode::Light => Theme::light(),
            _ => Theme::dark(),
        }
    }

    /// Which brand lockup belongs on this surface. `assets/brand/README.md` rule 2:
    /// "`-dark` on dark, `-light` on light" — never a light-ground asset on a dark page.
    pub fn logo_asset(&self) -> &'static str {
        if self.is_dark {
            "assets/brand/logo-horizontal-dark-1600x480.png"
        } else {
            "assets/brand/logo-horizontal-light-1600x480.png"
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        Theme::dark()
    }
}

// ─────────────────────────────── colour maths ───────────────────────────────

/// Split packed hex into `(r, g, b, a)`, each `0.0..=1.0`.
///
/// A value at or below `0x00FFFFFF` is read as `RRGGBB` and is **opaque**. That makes
/// "transparent black" inexpressible, because `0x00000000 == 0x000000` — there is no way to
/// tell the two apart from the value alone. Fully transparent is not a colour anyone needs
/// from this palette; the smallest expressible alpha is `0x00000001`.
pub fn unpack(hex: u32) -> (f32, f32, f32, f32) {
    let (r, g, b, a) = if hex > 0x00FF_FFFF {
        (
            (hex >> 24) & 0xFF,
            (hex >> 16) & 0xFF,
            (hex >> 8) & 0xFF,
            hex & 0xFF,
        )
    } else {
        ((hex >> 16) & 0xFF, (hex >> 8) & 0xFF, hex & 0xFF, 0xFF)
    };
    (
        r as f32 / 255.0,
        g as f32 / 255.0,
        b as f32 / 255.0,
        a as f32 / 255.0,
    )
}

/// WCAG relative luminance of an opaque hex.
pub fn luminance(hex: u32) -> f32 {
    let (r, g, b, _) = unpack(hex);
    fn channel(c: f32) -> f32 {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

/// WCAG contrast ratio, `1.0..=21.0`.
pub fn contrast_ratio(a: u32, b: u32) -> f32 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// Composite a possibly-translucent colour over an opaque background, giving the colour the
/// user actually sees. A translucent token's contrast is meaningless until composited, and
/// compositing is what a naive "is this hex dark enough" check misses.
pub fn over(fg: u32, bg: u32) -> u32 {
    let (fr, fg_, fb, fa) = unpack(fg);
    let (br, bg_, bb, _) = unpack(bg);
    let mix = |f: f32, b: f32| ((f * fa + b * (1.0 - fa)) * 255.0).round() as u32;
    (mix(fr, br) << 16) | (mix(fg_, bg_) << 8) | mix(fb, bb)
}

/// Alpha of a packed colour, `0.0..=1.0`. `F8FAFC` (no alpha byte) is fully opaque.
pub fn alpha(hex: u32) -> f32 {
    unpack(hex).3
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───────────── the palette is the brand's, and cannot drift silently ─────────────

    #[test]
    fn dark_theme_uses_the_brand_navy_ground() {
        assert_eq!(Theme::dark().ground, brand::NAVY);
        assert_eq!(Theme::dark().ground, 0x0B1220);
    }

    #[test]
    fn light_theme_uses_the_brand_light_ground() {
        assert_eq!(Theme::light().ground, brand::LIGHT);
        assert_eq!(Theme::light().ground, 0xF8FAFC);
    }

    #[test]
    fn both_appearances_keep_the_two_structural_brand_colours() {
        for theme in [Theme::dark(), Theme::light()] {
            assert_eq!(theme.primary, 0x2563EB, "letterform blue must not drift");
            assert_eq!(theme.accent, 0x06B6D4, "connection cyan must not drift");
        }
    }

    #[test]
    fn dark_uses_the_light_cyan_chevron_token() {
        assert_eq!(Theme::dark().highlight, brand::LIGHT_CYAN);
    }

    #[test]
    fn navy_and_light_swap_roles_between_appearances() {
        let dark = Theme::dark();
        let light = Theme::light();
        assert_eq!(dark.ground, light.ink, "the dark ground is the light ink");
        assert_eq!(dark.ink, light.ground, "the dark ink is the light ground");
    }

    #[test]
    fn dark_and_light_are_actually_different() {
        let (dark, light) = (Theme::dark(), Theme::light());
        assert_ne!(dark.ground, light.ground);
        assert_ne!(dark.surface, light.surface);
        assert!(dark.is_dark && !light.is_dark);
    }

    #[test]
    fn the_light_keyhole_token_is_not_pure_white() {
        // `assets/brand/README.md`: "The keyhole is #F8FAFC, not #FFFFFF. Keep it that way."
        assert_ne!(brand::LIGHT, 0xFFFFFF);
        assert_ne!(Theme::light().ground, 0xFFFFFF);
    }

    // ───────────── surfaces stay in the ground's colour family ─────────────

    /// A raised surface that has drifted toward neutral grey is the classic tell that a
    /// palette was hand-tuned per component instead of derived from one ground.
    #[test]
    fn dark_surfaces_stay_in_the_navy_family() {
        let theme = Theme::dark();
        for (name, hex) in [
            ("surface", theme.surface),
            ("surface_alt", theme.surface_alt),
        ] {
            let (r, g, b, _) = unpack(hex);
            assert!(
                b > r && g > r,
                "{name} {hex:06X} is not blue-dominant like the navy ground"
            );
            assert!(
                luminance(hex) > luminance(theme.ground),
                "{name} must be raised"
            );
        }
    }

    #[test]
    fn light_surfaces_are_near_the_ground_and_all_stay_light() {
        let theme = Theme::light();
        // Raised: the panel surface sits above the ground.
        assert!(luminance(theme.surface) >= luminance(theme.ground));
        // Recessed: the alternate surface is a subtle well — darker, but close enough that
        // it reads as the same material at a different depth rather than a grey slab.
        assert!(luminance(theme.surface_alt) < luminance(theme.ground));
        let ratio = contrast_ratio(theme.surface_alt, theme.ground);
        assert!(
            ratio < 1.2,
            "surface_alt separates too hard from the ground: {ratio:.3}:1"
        );
        // On a light ground, every surface must stay light.
        for hex in [theme.ground, theme.surface, theme.surface_alt] {
            assert!(luminance(hex) > 0.8, "{hex:06X} is not a light surface");
        }
    }

    // ───────────── readability is a property, not a taste ─────────────

    #[test]
    fn body_text_meets_wcag_aa_in_both_appearances() {
        for theme in [Theme::dark(), Theme::light()] {
            let ratio = contrast_ratio(theme.ink, theme.ground);
            assert!(
                ratio >= 4.5,
                "ink on ground is {ratio:.2}:1, below the 4.5:1 AA floor"
            );
        }
    }

    #[test]
    fn secondary_text_stays_above_the_3_to_1_floor_once_composited() {
        for theme in [Theme::dark(), Theme::light()] {
            let seen = over(theme.ink_dim, theme.ground);
            let ratio = contrast_ratio(seen, theme.ground);
            assert!(
                ratio >= 3.0,
                "ink_dim composites to {seen:06X}, only {ratio:.2}:1 on the ground"
            );
        }
    }

    #[test]
    fn severity_colours_are_readable_on_their_own_ground() {
        for theme in [Theme::dark(), Theme::light()] {
            for (name, color) in [
                ("danger", theme.danger),
                ("warn", theme.warn),
                ("ok", theme.ok),
            ] {
                let ratio = contrast_ratio(color, theme.ground);
                assert!(ratio >= 3.0, "{name} is only {ratio:.2}:1 on the ground");
            }
        }
    }

    #[test]
    fn primary_buttons_meet_aa_for_their_label() {
        for theme in [Theme::dark(), Theme::light()] {
            let ratio = contrast_ratio(theme.primary_text, theme.primary);
            assert!(ratio >= 4.5, "button label is {ratio:.2}:1 on the fill");
        }
    }

    #[test]
    fn the_reveal_highlight_is_legible_against_its_own_text() {
        for theme in [Theme::dark(), Theme::light()] {
            let ratio = contrast_ratio(theme.highlight_text, theme.highlight);
            assert!(ratio >= 4.5, "highlight label is {ratio:.2}:1");
        }
    }

    /// The hairline must be visible once composited, and must stay a hairline rather than
    /// becoming a box border.
    #[test]
    fn the_hairline_is_visible_but_not_a_box() {
        for (name, theme) in [("dark", Theme::dark()), ("light", Theme::light())] {
            let a = alpha(theme.line);
            assert!(
                (0.05..=0.35).contains(&a),
                "{name} line alpha {a:.3} is outside the hairline range"
            );
            assert!(
                alpha(theme.line_strong) > a,
                "{name}: the strong line must be stronger than the hairline"
            );
            // Visible: the composited line differs measurably from the ground.
            assert_ne!(over(theme.line, theme.ground), theme.ground, "{name}");
        }
    }

    /// A hover state that is not distinguishable from rest is the same as no hover state,
    /// which the UI/UX Pro Max `ux` database rates a Medium-severity defect.
    #[test]
    fn hover_states_are_distinguishable_from_rest_in_both_appearances() {
        for (name, theme) in [("dark", Theme::dark()), ("light", Theme::light())] {
            assert_ne!(theme.primary_hover, theme.primary, "{name} primary");
            assert_ne!(theme.control_hover, theme.surface_alt, "{name} control");
            assert_ne!(theme.row_hover, theme.ground, "{name} row");
            // Near misses read as a rendering bug rather than as feedback.
            assert!(
                contrast_ratio(theme.control_hover, theme.surface_alt) >= 1.06,
                "{name} control hover is imperceptible"
            );
            assert!(
                contrast_ratio(theme.row_hover, theme.ground) >= 1.04,
                "{name} row hover is imperceptible"
            );
        }
    }

    /// Hover must stay in the ground's colour family, like every other surface.
    #[test]
    fn dark_hover_states_stay_in_the_navy_family() {
        let theme = Theme::dark();
        for (name, hex) in [
            ("control_hover", theme.control_hover),
            ("row_hover", theme.row_hover),
        ] {
            let (r, g, b, _) = unpack(hex);
            assert!(b > r && g > r, "{name} {hex:06X} is not blue-dominant");
        }
    }

    #[test]
    fn colour_maths_matches_known_values() {
        assert!((luminance(0x000000) - 0.0).abs() < 1e-6);
        assert!((luminance(0xFFFFFF) - 1.0).abs() < 1e-6);
        assert!((contrast_ratio(0x000000, 0xFFFFFF) - 21.0).abs() < 1e-4);
        assert!((contrast_ratio(0x123456, 0x123456) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn over_composites_alpha_and_is_identity_for_opaque_colours() {
        assert_eq!(over(0xFF0000FF, 0x000000), 0xFF0000);
        assert_eq!(over(brand::BLUE, brand::LIGHT), brand::BLUE);
        // Half-transparent white over black is mid-grey.
        let mid = over(0xFFFFFF80, 0x000000);
        let (r, _, _, _) = unpack(mid);
        assert!((r - 0.5).abs() < 0.01, "got {mid:06X}");
    }

    #[test]
    fn unpack_handles_both_six_and_eight_digit_hex() {
        assert_eq!(unpack(0x000000), (0.0, 0.0, 0.0, 1.0));
        assert_eq!(unpack(0xFFFFFF).0, 1.0);

        // The threshold, pinned: at or below `0x00FFFFFF` a value is opaque `RRGGBB`.
        // `0x000000` is therefore opaque black — indistinguishable from a would-be
        // "transparent black", which is why that colour is simply not expressible.
        assert!((alpha(0x00FFFFFF) - 1.0).abs() < 1e-6);
        assert!((alpha(0x000000) - 1.0).abs() < 1e-6);
        assert!((alpha(0xF8FAFC) - 1.0).abs() < 1e-6);

        // One above the threshold is `RRGGBBAA`, and the smallest two alphas work.
        assert!(alpha(0x01000000) < 1e-6);
        assert!((alpha(0x01000001) - 1.0 / 255.0).abs() < 0.001);

        // A real token from the palette: cyan at 15% and at 35%.
        assert!((alpha(0x06B6D426) - 0.149).abs() < 0.01);
        assert!((alpha(0xF8FAFC59) - 0.349).abs() < 0.01);
    }

    // ───────────── mode resolution ─────────────

    #[test]
    fn mode_tags_parse_and_reject() {
        assert_eq!(ThemeMode::from_tag("dark"), Some(ThemeMode::Dark));
        assert_eq!(ThemeMode::from_tag("Dark"), Some(ThemeMode::Dark));
        assert_eq!(ThemeMode::from_tag(" light "), Some(ThemeMode::Light));
        assert_eq!(ThemeMode::from_tag("system"), Some(ThemeMode::System));
        assert_eq!(ThemeMode::from_tag("auto"), Some(ThemeMode::System));
        assert_eq!(ThemeMode::from_tag("solarized"), None);
        assert_eq!(ThemeMode::from_tag(""), None);
    }

    #[test]
    fn system_mode_follows_the_window_server() {
        assert_eq!(ThemeMode::System.effective(true), ThemeMode::Dark);
        assert_eq!(ThemeMode::System.effective(false), ThemeMode::Light);
    }

    #[test]
    fn an_explicit_mode_overrides_the_window_server() {
        assert_eq!(ThemeMode::Light.effective(true), ThemeMode::Light);
        assert_eq!(ThemeMode::Dark.effective(false), ThemeMode::Dark);
    }

    #[test]
    fn default_mode_is_system_with_no_env_override() {
        assert_eq!(ThemeMode::default(), ThemeMode::System);
        assert_eq!(ThemeMode::resolve(None), ThemeMode::System);
    }

    #[test]
    fn flipping_moves_to_the_other_effective_mode_and_stays_explicit() {
        assert_eq!(ThemeMode::System.flipped(true), ThemeMode::Light);
        assert_eq!(ThemeMode::System.flipped(false), ThemeMode::Dark);
        assert_eq!(ThemeMode::Dark.flipped(true), ThemeMode::Light);
        assert_eq!(ThemeMode::Light.flipped(false), ThemeMode::Dark);
    }

    #[test]
    fn every_mode_has_a_code_and_a_label() {
        for mode in [ThemeMode::Dark, ThemeMode::Light, ThemeMode::System] {
            assert!(!mode.code().is_empty());
            assert!(!mode.label().is_empty());
            assert_eq!(ThemeMode::from_tag(mode.code()), Some(mode));
        }
    }

    #[test]
    fn resolve_picks_the_right_palette() {
        assert!(Theme::resolve(ThemeMode::Dark, false).is_dark);
        assert!(!Theme::resolve(ThemeMode::Light, true).is_dark);
        assert!(Theme::resolve(ThemeMode::System, true).is_dark);
        assert!(!Theme::resolve(ThemeMode::System, false).is_dark);
    }

    // ───────────── assets follow the surface ─────────────

    #[test]
    fn each_appearance_loads_the_lockup_drawn_for_it() {
        // Brand rule 2: never a light-ground asset on a dark page.
        assert_eq!(
            Theme::dark().logo_asset(),
            "assets/brand/logo-horizontal-dark-1600x480.png"
        );
        assert_eq!(
            Theme::light().logo_asset(),
            "assets/brand/logo-horizontal-light-1600x480.png"
        );
        assert_ne!(Theme::dark().logo_asset(), Theme::light().logo_asset());
        for theme in [Theme::dark(), Theme::light()] {
            assert!(theme.logo_asset().starts_with("assets/brand/"));
            assert!(theme.logo_asset().ends_with(".png"));
        }
    }
}

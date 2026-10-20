//! A filesystem-backed asset source for the brand files.
//!
//! `Application::new()` installs `()` as the asset source, and `()` returns `None` for
//! every path — so `img("assets/brand/…")` silently draws nothing. Branding is not
//! optional here: `assets/brand/README.md` is the source of truth for the identity, and a
//! window with no mark is a window for any product. So the GUI serves the repository's
//! `assets/` directory itself.
//!
//! Read at call time rather than embedded: updating a brand file should not require
//! rebuilding the GUI, and the files are small.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use gpui::{AssetSource, Result, SharedString};

/// The repository root, baked in at compile time.
///
/// `CARGO_MANIFEST_DIR` is `<repo>/gui` and the brand files live at `<repo>/assets`. A
/// relative path would resolve against the process's working directory, which is wherever
/// the binary happened to be launched from — so it would work from the repo and silently
/// fail everywhere else.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub struct BrandAssets {
    root: PathBuf,
}

impl BrandAssets {
    pub fn new() -> Self {
        BrandAssets { root: repo_root() }
    }

    /// The absolute path an asset id resolves to. Exposed so a test can assert the mapping.
    pub fn resolve(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }
}

impl Default for BrandAssets {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetSource for BrandAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        match std::fs::read(self.resolve(path)) {
            Ok(bytes) => Ok(Some(Cow::Owned(bytes))),
            // A missing asset is not an error: GPUI draws nothing, which is the same
            // outcome the default source produces, and a hard error would take the window
            // down over a picture.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn list(&self, _path: &str) -> Result<Vec<SharedString>> {
        // Nothing enumerates assets; the two lockups are named directly.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Theme;

    /// The whole point of this type: the paths the theme asks for must be real files on
    /// disk. Without it `img()` draws nothing and the failure is invisible.
    #[test]
    fn both_lockups_the_theme_asks_for_actually_exist() {
        let assets = BrandAssets::new();
        for theme in [Theme::dark(), Theme::light()] {
            let relative = theme.logo_asset();
            let full = assets.resolve(relative);
            assert!(
                full.is_file(),
                "{} does not resolve to a file ({})",
                relative,
                full.display()
            );
            assert!(
                std::fs::metadata(&full).map(|m| m.len()).unwrap_or(0) > 0,
                "{} is empty",
                full.display()
            );
        }
    }

    #[test]
    fn load_returns_the_bytes_for_a_real_asset() {
        let assets = BrandAssets::new();
        let bytes = assets
            .load(Theme::dark().logo_asset())
            .expect("load must not error")
            .expect("the dark lockup must be present");
        // PNG magic.
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn a_missing_asset_is_none_rather_than_an_error() {
        let assets = BrandAssets::new();
        assert!(
            assets
                .load("assets/brand/nope.png")
                .expect("no error")
                .is_none(),
            "a missing image must not take the window down"
        );
    }

    #[test]
    fn assets_resolve_below_the_repository_root() {
        let assets = BrandAssets::new();
        let full = assets.resolve("assets/brand/logo-dark-1200.png");
        assert!(full.starts_with(assets.root.as_path()));
        assert!(full.ends_with("assets/brand/logo-dark-1200.png"));
    }

    #[test]
    fn listing_is_empty_and_does_not_error() {
        assert!(BrandAssets::new().list("/").unwrap().is_empty());
    }
}

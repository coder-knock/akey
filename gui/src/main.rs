//! `akey-gui` entry point.
//!
//! The binary depends on `gpui`, which is an **optional** feature so that the pure logic
//! (`backend` / `verbs` / `model` / `revealed`) can be built and tested on machines
//! without a GPU toolchain. Building without the feature yields a binary that says so and
//! exits 2 rather than pretending to be a GUI.

#[cfg(feature = "gpui")]
fn main() {
    if let Err(message) = akey_gui::app::run() {
        // Diagnostics go to stderr; stdout stays clean, matching the CLI's discipline.
        eprintln!("akey-gui: {message}");
        std::process::exit(2);
    }
}

#[cfg(not(feature = "gpui"))]
fn main() {
    eprintln!(
        "akey-gui: this binary was built without the `gpui` feature, so it has no window \
         to open.\n\
         Rebuild with: cargo build -p akey-gui --features gpui"
    );
    std::process::exit(2);
}

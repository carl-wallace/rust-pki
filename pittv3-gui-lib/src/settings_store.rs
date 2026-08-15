//! Persistence seam for the shared settings form.
//!
//! [`EditSettings`](crate::gui_settings::EditSettings) is deliberately persistence-free: it takes a
//! model in and hands an edited model back. Where those settings live differs per frontend — a JSON
//! file on desktop and the CLI, browser storage in the wasm app, and a server-side session for a
//! hosted variant — so each frontend supplies a [`SettingsStore`].
//!
//! The trait trades in [`CertificationPathSettings`] rather than
//! [`SettingsModel`](crate::gui_settings_model::SettingsModel) on purpose. That type is the format
//! the CLI's `--settings` argument already reads and the desktop editor already writes, so every
//! frontend stores, exports and imports the same artifact instead of inventing a private encoding.
//! Round-tripping through it also preserves settings the form does not surface (`PS_CERTIFICATES`,
//! for instance), which a model-shaped store would silently drop.
//!
//! This module is Dioxus-free.

use certval::CertificationPathSettings;

/// Where a frontend keeps its settings between runs.
///
/// Implementations are expected to be best-effort: browser storage can be unavailable or full and a
/// file can be unreadable, and in neither case should the form refuse to open. `load` therefore
/// falls back to the certval defaults rather than reporting an error, and `save` reports failure
/// only so the frontend can surface a status line.
pub trait SettingsStore {
    /// Reads the stored settings, yielding the certval defaults when nothing is stored yet or the
    /// stored value cannot be read.
    fn load(&self) -> CertificationPathSettings;

    /// Writes settings back to the store, returning a human-readable message on failure.
    fn save(&self, cps: &CertificationPathSettings) -> Result<(), String>;
}

/// The application's home directory, `.pittv3` beneath the user's home, created if absent. None
/// when there is no home directory to work from.
#[cfg(feature = "std")]
pub fn app_home() -> Option<std::path::PathBuf> {
    let app_home = home::home_dir()?.join(".pittv3");
    if !app_home.exists() {
        let _ = std::fs::create_dir_all(&app_home);
    }
    Some(app_home)
}

/// The default settings file, `settings.json` in [`app_home`].
///
/// Having a default is what lets a file-backed frontend behave like the browser one, where settings
/// are always present because localStorage always answers. Without it the desktop app could only
/// show its settings form once the user had nominated a file, so the same product had settings as
/// *app state* in one frontend and as *a document you open* in the other. The file need not exist:
/// `certval::read_settings` yields an empty settings map for a missing path, which is the same
/// thing as "all defaults".
#[cfg(feature = "std")]
pub fn default_settings_path() -> Option<String> {
    Some(app_home()?.join("settings.json").to_str()?.to_string())
}

/// A [`SettingsStore`] backed by a JSON file holding a [`CertificationPathSettings`] — the format
/// the CLI reads via `--settings` and the desktop app has always written.
#[cfg(feature = "std")]
pub struct FileSettingsStore {
    /// Path to the settings JSON
    pub path: String,
}

#[cfg(feature = "std")]
impl FileSettingsStore {
    /// Creates a store over the settings file at `path`
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(feature = "std")]
impl SettingsStore for FileSettingsStore {
    fn load(&self) -> CertificationPathSettings {
        certval::read_settings(&Some(self.path.clone())).unwrap_or_default()
    }

    fn save(&self, cps: &CertificationPathSettings) -> Result<(), String> {
        use std::io::Write;

        let json =
            serde_json::to_string(cps).map_err(|e| format!("Failed to encode settings: {e}"))?;
        let mut file = std::fs::File::create(&self.path)
            .map_err(|e| format!("Failed to create file to receive settings: {e}"))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to save settings: {e}"))
    }
}

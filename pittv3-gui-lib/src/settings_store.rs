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

/// Resolves a leading `~` in `path` against the user's home directory, returning any other path
/// unchanged.
///
/// Paths reach a GUI by hand at least as often as they do through a file dialog, and a typed
/// `~/settings.json` is not a path the file system understands: `~` is an ordinary directory name
/// to it, so reading such a path yields the defaults for a file that is not there and writing one
/// fails outright for want of a parent directory. A shell expands the tilde before a command line
/// utility ever sees it; a text box has no shell behind it, so the expansion has to happen here.
/// `~user` is left alone, since resolving another user's home directory is a shell feature rather
/// than a file system one.
#[cfg(feature = "std")]
pub fn expand_tilde(path: &str) -> String {
    let Some(after) = path.strip_prefix('~') else {
        return path.to_string();
    };
    let rest = after.trim_start_matches(['/', '\\']);
    if !after.is_empty() && rest.len() == after.len() {
        return path.to_string();
    }
    let Some(home) = home::home_dir() else {
        return path.to_string();
    };
    if rest.is_empty() {
        return home.to_string_lossy().to_string();
    }
    home.join(rest).to_string_lossy().to_string()
}

/// A [`SettingsStore`] backed by a JSON file holding a [`CertificationPathSettings`] — the format
/// the CLI reads via `--settings` and the desktop app has always written.
#[cfg(feature = "std")]
pub struct FileSettingsStore {
    /// Path to the settings JSON, with any leading `~` already resolved
    pub path: String,
}

#[cfg(feature = "std")]
impl FileSettingsStore {
    /// Creates a store over the settings file at `path`, resolving a leading `~` so a path typed
    /// into a text box names the same file a shell would have named
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: expand_tilde(&path.into()),
        }
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_only_where_a_shell_would() {
        let home = home::home_dir().expect("home directory");
        let home_str = home.to_string_lossy().to_string();

        assert_eq!(
            expand_tilde("~/.pittv3.json"),
            home.join(".pittv3.json").to_string_lossy()
        );
        assert_eq!(expand_tilde("~"), home_str);

        // absolute and relative paths, and another user's home, are the shell's business or
        // nobody's
        assert_eq!(expand_tilde("/etc/pittv3.json"), "/etc/pittv3.json");
        assert_eq!(expand_tilde("settings.json"), "settings.json");
        assert_eq!(
            expand_tilde("~someone/settings.json"),
            "~someone/settings.json"
        );
        // a tilde anywhere but the front is a legitimate file name character
        assert_eq!(
            expand_tilde("backup/~settings.json"),
            "backup/~settings.json"
        );
    }

    #[test]
    fn file_store_resolves_a_typed_tilde() {
        let home = home::home_dir().expect("home directory");
        assert_eq!(
            FileSettingsStore::new("~/.pittv3.json").path,
            home.join(".pittv3.json").to_string_lossy()
        );
    }

    #[test]
    fn file_store_round_trips_through_an_expanded_path() {
        let path = std::env::temp_dir().join("pittv3-settings-store-test.json");
        let _ = std::fs::remove_file(&path);

        let store = FileSettingsStore::new(path.to_string_lossy().to_string());
        // a missing file reads as "all defaults" rather than as an error
        assert!(store.load().0.is_empty());

        let mut cps = CertificationPathSettings::new();
        cps.set_check_revocation_status(false);
        store.save(&cps).expect("save");

        assert!(!store.load().get_check_revocation_status());
        let _ = std::fs::remove_file(&path);
    }
}

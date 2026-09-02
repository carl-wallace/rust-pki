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

/// A saved value if there is a usable one, otherwise the default.
///
/// An empty saved value falls through to the default rather than being taken at face value. That is
/// what a text field holds when it has never been filled in, so treating it as a deliberate "no
/// folder" would deny the default to exactly the first-run case it exists for. The consequence
/// worth knowing: a field the user *clears* is honoured for that run — the run form sends `None` —
/// but the default returns the next time the application starts.
#[cfg(feature = "std")]
pub fn saved_or_default(saved: Option<String>, default: impl FnOnce() -> Option<String>) -> String {
    saved
        .filter(|value| !value.is_empty())
        .or_else(default)
        .unwrap_or_default()
}

/// A folder beneath [`app_home`], created if absent. `None` when there is no home directory, or
/// when the path will not round-trip through a `String` — the argument and settings types the
/// folder feeds are string-typed, so a path that cannot be one is no use here.
#[cfg(feature = "std")]
fn app_home_folder(name: &str) -> Option<String> {
    let folder = app_home()?.join(name);
    if !folder.exists() {
        let _ = std::fs::create_dir_all(&folder);
    }
    Some(folder.to_str()?.to_string())
}

/// Default folder for CA certificates, `cas` in [`app_home`].
///
/// Dynamic building needs somewhere to put what it fetches, and with nowhere named the run is
/// refused outright — so on a machine that has never been configured, the first thing the
/// application does is decline to work, over a folder no new user could have known to nominate.
/// These defaults exist to answer that.
///
/// **They are offered to the folder fields rather than resolved behind them**, so what the run will
/// use is on screen and can be changed or cleared. That matters most for the arguments that treat
/// the CA folder as an output: `--cleanup` moves or deletes certificates from it and
/// `--mozilla-csv` writes a report into it, and neither should ever act on a location the person
/// running it cannot see.
#[cfg(feature = "std")]
pub fn default_ca_folder() -> Option<String> {
    app_home_folder("cas")
}

/// Default folder for downloaded certificates, `downloads` in [`app_home`]. See
/// [`default_ca_folder`] for why these are offered rather than resolved.
#[cfg(feature = "std")]
pub fn default_download_folder() -> Option<String> {
    app_home_folder("downloads")
}

/// Default CRL index folder, `crls` in [`app_home`]. See [`default_ca_folder`] for why these are
/// offered rather than resolved.
///
/// Naming one also gives a run somewhere to keep the CRLs it fetches: without a folder no
/// `CrlSource` is registered at all, so a CRL retrieved from a distribution point is used for its
/// determination and then dropped, and anything asking the environment for it afterwards — an
/// artifact export, above all — finds nothing.
#[cfg(feature = "std")]
pub fn default_crl_folder() -> Option<String> {
    app_home_folder("crls")
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

    /// Deliberately exercised with a stub default rather than the real ones: calling those would
    /// make directories in whoever's home is running the suite.
    #[test]
    fn an_empty_saved_value_falls_through_to_the_default() {
        let default = || Some("/default/cas".to_string());

        assert_eq!(saved_or_default(None, default), "/default/cas");
        assert_eq!(
            saved_or_default(Some(String::new()), default),
            "/default/cas"
        );
        // a saved value wins, and is not second-guessed
        assert_eq!(
            saved_or_default(Some("/chosen".to_string()), default),
            "/chosen"
        );
        // no default to offer is still not an error -- the caller's guard reports it
        assert_eq!(saved_or_default(None, || None), "");
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

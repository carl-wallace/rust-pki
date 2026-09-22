//! Logging setup for the desktop application: a log4rs file, and the one appender a file cannot
//! otherwise name.
//!
//! The application logs to three places at once — a rolling file, the Results view, and stdout —
//! and the middle one is a custom appender ([`ChannelAppender`]) rather than anything log4rs ships.
//! log4rs resolves an appender's `kind` through a [`Deserializers`] registry, and the default
//! registry knows nothing of ours, so a configuration file naming `kind: channel` fails to load and
//! a file that omits it silently drops the Run log and leaves Save log with nothing to write.
//!
//! [`deserializers`] registers it, which is what lets the shipped template name all three and lets
//! anyone editing that file keep the in-application log rather than trading it away for a log file.

use std::fs;
use std::path::Path;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Deserialize, Deserializers, Root};
use log4rs::encode::pattern::PatternEncoder;
use pittv3_gui_lib::gui_utils::ChannelAppender;
use pittv3_gui_lib::settings_store::default_log_file;

/// The template written when no configuration file exists, with the log destination substituted.
const TEMPLATE: &str = include_str!("../assets/log.yaml");

/// Placeholder in [`TEMPLATE`] standing in for the rolling file's path.
const LOG_FILE_PLACEHOLDER: &str = "<PITTV3 LOG FILE>";

/// Configuration accepted by the `channel` appender, which is none.
///
/// An empty struct rather than `()`: log4rs hands the deserializer whatever remains of the
/// appender's map once `kind` is taken out, and an empty map deserializes into a fieldless struct
/// where it will not deserialize into a unit.
#[derive(serde::Deserialize)]
struct ChannelAppenderConfig {}

/// Builds a [`ChannelAppender`] for a `kind: channel` entry in a log4rs configuration file.
struct ChannelAppenderDeserializer;

impl Deserialize for ChannelAppenderDeserializer {
    type Trait = dyn Append;
    type Config = ChannelAppenderConfig;

    fn deserialize(
        &self,
        _config: ChannelAppenderConfig,
        _deserializers: &Deserializers,
    ) -> anyhow::Result<Box<dyn Append>> {
        Ok(Box::new(ChannelAppender))
    }
}

/// The log4rs deserializer registry this application loads configuration files with.
///
/// Use this rather than `Default::default()` anywhere a configuration file is read, or `kind:
/// channel` will not resolve.
pub fn deserializers() -> Deserializers {
    let mut deserializers = Deserializers::default();
    deserializers.insert("channel", ChannelAppenderDeserializer);
    deserializers
}

/// Writes the default configuration to `path` if nothing is there, and reports whether a file is
/// present afterwards.
///
/// Only when absent: once written the file belongs to whoever edits it, and overwriting would
/// discard a level or destination they chose. The consequence is that an installed copy stops
/// tracking changes to the template, which is the ordinary cost of a generated configuration and
/// the reason the built-in configuration remains the fallback rather than being deleted.
pub fn ensure_config_file(path: &str, log_file: &str) -> bool {
    if Path::new(path).exists() {
        return true;
    }
    let Some(parent) = Path::new(path).parent() else {
        return false;
    };
    if fs::create_dir_all(parent).is_err() {
        return false;
    }
    fs::write(
        path,
        TEMPLATE.replace(LOG_FILE_PLACEHOLDER, &yaml_escape(log_file)),
    )
    .is_ok()
}

/// Escapes a value for a YAML double-quoted scalar, which is what both substitution sites in
/// [`TEMPLATE`] are.
///
/// A Windows log path is the one value here that YAML will not take as written: inside double
/// quotes, the `\U` of `C:\Users\...` is an escape sequence expecting eight hexadecimal digits, so
/// the default configuration failed to load on every Windows machine. It failed silently, because
/// `init_logging` falls back to the built-in appenders when a file will not parse -- the symptom
/// was an edited `log.yaml` having no effect rather than an error.
///
/// Backslash and double quote are the only characters a double-quoted scalar treats specially.
/// Backslash is replaced first, or the backslash introduced by escaping a quote would itself be
/// doubled. A Windows path cannot contain a double quote and a POSIX one rarely does, but it is
/// escaped rather than reasoned about.
///
/// Escaping rather than single-quoting the template, which would also have handled a backslash and
/// would then have broken on an apostrophe -- and `C:\Users\O'Brien` is a real home directory.
fn yaml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Configures logging for the process, from `logging_config` when it names a usable log4rs file and
/// otherwise from the built-in stdout, Results-view and rolling-file appenders.
///
/// Called once, before the window opens, so anything logged before the first run -- a settings save
/// that fails on leaving a view, say -- has somewhere to go. log4rs can be initialized only once per
/// process, so a different file chosen in Settings takes effect at the next start.
pub fn init_logging(logging_config: Option<&str>) {
    let mut logging_configured = false;

    if let Some(logging_config) = logging_config {
        // Written only when absent, so an edited file is never replaced. Without a
        // destination to substitute there is nothing to write, and the load below fails
        // through to the built-in configuration.
        if let Some(log_file) = default_log_file() {
            ensure_config_file(logging_config, &log_file);
        }
        // `deserializers()` rather than `Default::default()`: the template names the
        // channel appender that feeds the Results view, and the default registry cannot
        // resolve it.
        if let Err(e) = log4rs::init_file(logging_config, deserializers()) {
            println!(
            "ERROR: failed to configure logging using {logging_config} with {e:?}. Continuing without logging."
        );
        } else {
            logging_configured = true;
        }
    }

    if !logging_configured {
        // if there's no config, prepare one using stdout plus the channel appender that
        // streams run output into the Results view
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();

        // A file as well, because the other two do not survive the run: an application
        // launched from the Finder has no stdout to read, and the channel appender feeds a
        // view that is cleared by the next run. Rolling rather than plain -- 5 MB across
        // four files, so a session that logs heavily is bounded at 20 MB and needs no
        // maintenance action of its own. A log4rs file named in the settings replaces all
        // of this, which is what that setting is for.
        let file = default_log_file().and_then(|path| {
            let roll = FixedWindowRoller::builder()
                .build(&format!("{path}.{{}}"), 3)
                .ok()?;
            let policy =
                CompoundPolicy::new(Box::new(SizeTrigger::new(5 * 1024 * 1024)), Box::new(roll));
            RollingFileAppender::builder()
                .encoder(Box::new(PatternEncoder::new("{d} {l} {t} - {m}{n}")))
                .build(&path, Box::new(policy))
                .ok()
        });

        let mut builder = Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .appender(Appender::builder().build("channel", Box::new(ChannelAppender)));
        let mut root = Root::builder().appender("stdout").appender("channel");
        if let Some(file) = file {
            builder = builder.appender(Appender::builder().build("file", Box::new(file)));
            root = root.appender("file");
        }
        match builder.build(root.build(LevelFilter::Info)) {
            Ok(config) => {
                let handle = log4rs::init_config(config);
                if let Err(e) = handle {
                    println!(
                    "ERROR: failed to configure logging for stdout with {e:?}. Continuing without logging."
                );
                }
            }
            Err(e) => {
                println!("ERROR: failed to prepare default logging configuration with {e:?}. Continuing without logging");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The template has to name every appender the application expects, and the substitution has to
    /// leave no placeholder behind — a stray one would be taken as a literal path and the run would
    /// log into a file named for the placeholder.
    #[test]
    fn template_names_the_three_appenders_and_substitutes_cleanly() {
        let filled = TEMPLATE.replace(LOG_FILE_PLACEHOLDER, "/tmp/pittv3.log");
        assert!(
            !filled.contains(LOG_FILE_PLACEHOLDER),
            "placeholder remains"
        );
        assert!(filled.contains("kind: channel"), "no channel appender");
        assert!(filled.contains("kind: rolling_file"), "no file appender");
        assert!(filled.contains("kind: console"), "no stdout appender");
        assert!(filled.contains("/tmp/pittv3.log"), "path not substituted");
    }

    /// The registry has to resolve `channel`, which is the whole reason it exists.
    #[test]
    fn the_template_loads_with_our_deserializers() {
        let dir = std::env::temp_dir().join("pittv3-logging-test");
        // Cleared before, not only after: `ensure_config_file` declines to overwrite, and the
        // cleanup at the end is skipped when the assertion below fails. A file left by a failing
        // run was therefore read by every later one, so the test went on reporting the bug after it
        // was fixed -- and would equally have gone on passing had it been left by a passing run.
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("log.yaml");
        let log_file = dir.join("pittv3.log");
        assert!(ensure_config_file(
            path.to_str().unwrap(),
            log_file.to_str().unwrap()
        ));
        // Loading is what exercises the registry: an unregistered kind fails here.
        let loaded = log4rs::config::load_config_file(&path, deserializers());
        assert!(loaded.is_ok(), "template did not load: {loaded:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The regression this file exists to prevent. Inside a double-quoted YAML scalar the `\U` of
    /// `C:\Users` is an escape expecting eight hexadecimal digits, and the default configuration
    /// would not load on any Windows machine because of it.
    ///
    /// Pinned with a literal path rather than left to `temp_dir`, which yields no backslashes on
    /// the platforms this also runs on -- so only the Windows leg would ever have caught it. The
    /// apostrophe is there because it is the reason the template is escaped rather than
    /// single-quoted: `C:\Users\O'Brien` is a real home directory.
    #[test]
    fn a_windows_path_survives_the_template() {
        let dir = std::env::temp_dir().join("pittv3-logging-windows-path");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("log.yaml");
        // Loading the config builds the appender, which creates the file it names. A bare
        // `C:\Users\...` is one odd filename to a POSIX system rather than a path, so it would be
        // created in whatever directory the test ran from -- and this test left an empty
        // `C:\Users\O'Brien\.pittv3\pittv3.log` in the crate root every time it passed. Joining it
        // onto the temp directory leaves the backslashes and the apostrophe where the escaping is
        // exercised and puts the file where the cleanup below can reach it.
        let log = dir.join(r"C:\Users\O'Brien\.pittv3\pittv3.log");
        assert!(ensure_config_file(
            path.to_str().unwrap(),
            log.to_str().unwrap()
        ));
        let loaded = log4rs::config::load_config_file(&path, deserializers());
        assert!(loaded.is_ok(), "template did not load: {loaded:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Backslash before quote: escaping the quote first would double the backslash it introduces.
    #[test]
    fn yaml_escape_handles_both_special_characters() {
        assert_eq!(yaml_escape(r"C:\Users\carl"), r"C:\\Users\\carl");
        assert_eq!(yaml_escape(r#"a"b"#), r#"a\"b"#);
        // The ordering case: one backslash and one quote must come back as two and an escaped one,
        // not as three.
        assert_eq!(yaml_escape(r#"\""#), r#"\\\""#);
        // A POSIX path is left exactly as it was.
        assert_eq!(
            yaml_escape("/home/carl/.pittv3/pittv3.log"),
            "/home/carl/.pittv3/pittv3.log"
        );
    }

    /// Writing is once only, so an edited file is not replaced on the next run.
    #[test]
    fn an_existing_file_is_left_alone() {
        let dir = std::env::temp_dir().join("pittv3-logging-existing");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("log.yaml");
        fs::write(&path, "mine").unwrap();
        assert!(ensure_config_file(path.to_str().unwrap(), "/tmp/x.log"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "mine");
        let _ = fs::remove_dir_all(&dir);
    }
}

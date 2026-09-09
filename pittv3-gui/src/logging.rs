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

use log4rs::append::Append;
use log4rs::config::{Deserialize, Deserializers};
use pittv3_gui_lib::gui_utils::ChannelAppender;

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
    fs::write(path, TEMPLATE.replace(LOG_FILE_PLACEHOLDER, log_file)).is_ok()
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

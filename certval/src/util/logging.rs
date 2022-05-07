//! Logging support

#[cfg(feature = "std")]
use log::{debug, error, info, warn};

/// Enum that describes level associated with a log message
#[derive(Debug, Eq, PartialEq)]
pub enum PeLogLevels {
    /// Common error logging level
    PeError,
    /// Common info logging level
    PeInfo,
    /// Common warn logging level
    PeWarn,
    /// Common debug logging level
    PeDebug,
}

/// `log_message` provides a logging function that uses log4rs.
#[cfg(feature = "std")]
pub fn log_message(level: &PeLogLevels, message: &str) {
    if &PeLogLevels::PeError == level {
        error!("{}", message);
    } else if &PeLogLevels::PeWarn == level {
        warn!("{}", message);
    } else if &PeLogLevels::PeInfo == level {
        info!("{}", message);
    } else {
        debug!("{}", message);
    }
}

#[cfg(not(feature = "std"))]
/// `log_message` does nothing when std feature gate is not used
pub fn log_message(_level: &PeLogLevels, _message: &str) {}

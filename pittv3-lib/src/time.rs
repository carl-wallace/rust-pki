//! The time a run validates against, from the epoch seconds a caller carries.
//!
//! The command line and both graphical frontends hold the time of interest as a number of seconds,
//! because that is what an argument, a settings file and a form field can each carry. certval holds
//! it as a [`TimeOfInterest`], which wraps a `der::DateTime` and therefore accepts only times a
//! certificate could state. Every conversion between the two can fail, and this module is where the
//! failure is decided once.
//!
//! **A value certval will not take is refused, not replaced.** Every substitute judges certificates
//! against a moment the caller did not choose and says nothing about it: the ceiling validates as of
//! the year 9999, which accepts everything expired; the current time answers a question nobody
//! asked; and [`TimeOfInterest::disabled`] switches validity checking off for the whole path while
//! the form goes on showing the number that was typed. Refusing answers no question at all, which is
//! what an unreadable question deserves.

use alloc::format;
use alloc::string::String;

use certval::TimeOfInterest;

/// The largest value [`TimeOfInterest::from_unix_secs`] accepts, 9999-12-31T23:59:59Z.
///
/// `der` rejects anything later, since ASN.1 has no way to write it.
pub const MAX_TIME_OF_INTEREST_SECS: u64 = 253_402_300_799;

/// Converts epoch seconds into the time a run validates against, refusing a value certval will not
/// take rather than substituting one.
///
/// Zero is a time of interest like any other here: it is the value that means validity checking is
/// off, and a caller that wants that passes it deliberately. What this refuses is a number that
/// states no time at all.
///
/// The message is written for a user to read, and names a cause worth checking when the number
/// looks like one: a value that reads as a plausible time in milliseconds may be milliseconds,
/// which is what `Date.now()` and most other clocks hand out.
pub fn time_of_interest_from_secs(secs: u64) -> Result<TimeOfInterest, String> {
    match TimeOfInterest::from_unix_secs(secs) {
        Ok(toi) => Ok(toi),
        Err(_e) => {
            let mut msg = format!(
                "{secs} is not a time of interest this can use: seconds since the epoch must be at most {MAX_TIME_OF_INTEREST_SECS} (9999-12-31T23:59:59Z)"
            );
            // Only where the number reads as a time in milliseconds. Every value above the ceiling
            // divides into something under it, so the division alone says nothing; what makes the
            // reading plausible is landing this century.
            let as_millis = secs / 1000;
            if (MILLISECOND_READING_FLOOR..=MAX_TIME_OF_INTEREST_SECS).contains(&as_millis) {
                msg.push_str(". A value this large may be milliseconds");
            }
            Err(msg)
        }
    }
}

/// 2000-01-01T00:00:00Z, the earliest a millisecond reading has to land for the hint to be worth
/// offering. Below it the number is out of range for some other reason and milliseconds would be a
/// misleading guess.
const MILLISECOND_READING_FLOOR: u64 = 946_684_800;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_convert_and_zero_is_a_time() {
        let toi = time_of_interest_from_secs(1_647_264_981).expect("in range");
        assert_eq!(toi.as_unix_secs(), 1_647_264_981);
        assert!(time_of_interest_from_secs(0)
            .expect("zero converts")
            .is_disabled());
        assert!(time_of_interest_from_secs(MAX_TIME_OF_INTEREST_SECS).is_ok());
    }

    #[test]
    fn a_millisecond_timestamp_is_refused_and_says_so() {
        // What `Date.now()` hands out, which is the way this is reached in practice.
        let err = time_of_interest_from_secs(1_760_000_000_000).expect_err("out of range");
        assert!(err.contains("may be milliseconds"), "{err}");
        assert!(err.contains("253402300799"), "{err}");
    }

    #[test]
    fn a_value_too_large_to_be_milliseconds_omits_that_hint() {
        let err = time_of_interest_from_secs(u64::MAX).expect_err("out of range");
        assert!(!err.contains("milliseconds"), "{err}");
    }

    #[test]
    fn a_value_just_past_the_ceiling_omits_that_hint() {
        // 1978 read as milliseconds, so milliseconds is not what this is.
        let err =
            time_of_interest_from_secs(MAX_TIME_OF_INTEREST_SECS + 100).expect_err("out of range");
        assert!(!err.contains("milliseconds"), "{err}");
    }
}

//! Utils to define the time of interest when validating certificate

use core::{cmp::Ordering, fmt, ops::Sub, time::Duration};

/// Time of interest for the validation of a certificate or check against revocation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct TimeOfInterest(pub der::DateTime);

impl fmt::Display for TimeOfInterest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TimeOfInterest {
    /// Make [`TimeOfInterest`] where checks are disabled
    pub fn disabled() -> Self {
        TimeOfInterest(
            der::DateTime::from_unix_duration(Duration::ZERO)
                // NOTE(safety): only values before 1970 or values after 9999 would be throwing errors
                .expect("Could not create a DateTime from Unix Epoch"),
        )
    }

    /// Should time checks be disabled?
    pub fn is_disabled(&self) -> bool {
        self.0.unix_duration() == Duration::ZERO
    }

    /// Create a [`TimeOfInterest`] from Unix epoch
    pub fn from_unix_secs(v: u64) -> der::Result<Self> {
        Ok(Self(der::DateTime::from_unix_duration(
            Duration::from_secs(v),
        )?))
    }

    /// Return Unix epoch (in seconds) for this value
    pub fn as_unix_secs(&self) -> u64 {
        self.0.unix_duration().as_secs()
    }
}

#[cfg(not(feature = "std"))]
impl Default for TimeOfInterest {
    fn default() -> Self {
        Self::disabled()
    }
}

impl PartialEq<x509_cert::time::Time> for TimeOfInterest {
    fn eq(&self, other: &x509_cert::time::Time) -> bool {
        self.0.eq(&other.to_date_time())
    }
}

impl PartialOrd<x509_cert::time::Time> for TimeOfInterest {
    fn partial_cmp(&self, other: &x509_cert::time::Time) -> Option<Ordering> {
        self.0.partial_cmp(&other.to_date_time())
    }
}

impl PartialEq<TimeOfInterest> for x509_cert::time::Time {
    fn eq(&self, other: &TimeOfInterest) -> bool {
        self.to_date_time().eq(&other.0)
    }
}

impl PartialOrd<TimeOfInterest> for x509_cert::time::Time {
    fn partial_cmp(&self, other: &TimeOfInterest) -> Option<Ordering> {
        self.to_date_time().partial_cmp(&other.0)
    }
}

impl PartialEq<der::asn1::GeneralizedTime> for TimeOfInterest {
    fn eq(&self, other: &der::asn1::GeneralizedTime) -> bool {
        self.0.eq(&other.to_date_time())
    }
}

impl PartialOrd<der::asn1::GeneralizedTime> for TimeOfInterest {
    fn partial_cmp(&self, other: &der::asn1::GeneralizedTime) -> Option<Ordering> {
        self.0.partial_cmp(&other.to_date_time())
    }
}

impl PartialEq<TimeOfInterest> for der::asn1::GeneralizedTime {
    fn eq(&self, other: &TimeOfInterest) -> bool {
        self.to_date_time().eq(&other.0)
    }
}

impl PartialOrd<TimeOfInterest> for der::asn1::GeneralizedTime {
    fn partial_cmp(&self, other: &TimeOfInterest) -> Option<Ordering> {
        self.to_date_time().partial_cmp(&other.0)
    }
}

impl Sub<TimeOfInterest> for x509_cert::time::Time {
    type Output = u64;
    fn sub(self, other: TimeOfInterest) -> Self::Output {
        self.to_unix_duration().as_secs() - other.as_unix_secs()
    }
}

#[cfg(feature = "std")]
mod std {
    use super::*;
    use serde::{
        de::{self, Deserializer, Visitor},
        ser::Serializer,
        Deserialize, Serialize,
    };

    impl Serialize for TimeOfInterest {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_u64(self.as_unix_secs())
        }
    }

    impl<'de> Deserialize<'de> for TimeOfInterest {
        fn deserialize<D>(deserializer: D) -> Result<TimeOfInterest, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ToiVisitor;

            impl<'de> Visitor<'de> for ToiVisitor {
                type Value = TimeOfInterest;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("an integer between 0 and 2^64")
                }

                fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    TimeOfInterest::from_unix_secs(value)
                        .map_err(|_| E::custom("time of interest out of range: {value}"))
                }
            }

            deserializer.deserialize_u64(ToiVisitor)
        }
    }

    impl TimeOfInterest {
        /// Creates a [`TimeOfInterest`] for today's date
        pub fn now() -> Self {
            Self(der::DateTime::from_system_time(::std::time::SystemTime::now()).unwrap())
        }
    }

    impl Default for TimeOfInterest {
        fn default() -> Self {
            Self::now()
        }
    }
}

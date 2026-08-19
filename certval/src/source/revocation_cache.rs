//! In-memory cache of revocation status determinations
//!
//! This lives apart from the CRL sources because it needs nothing they need. A determination is a
//! status and an expiry held in a map; there is no filesystem and no network in it, so it is
//! available wherever revocation checking is, including targets that take this crate without `std`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use log::{debug, info};

use sha2::{Digest, Sha256};

use der::Encode;

use crate::PathValidationStatus::RevocationStatusNotDetermined;
use crate::{buffer_to_hex, PathValidationStatus, RevocationStatusCache};
use crate::{name_to_string, PDVCertificate, SubjectNameAndKey, TimeOfInterest};

#[cfg(feature = "std")]
type LockImpl<T> = std::sync::RwLock<T>;
#[cfg(not(feature = "std"))]
type LockImpl<T> = spin::RwLock<T>;

/// The cache is shared behind `&self` and [`RevocationStatusCache`] requires `Sync`, so interior
/// mutability has to be a lock rather than a cell -- and `std`'s is unavailable to the targets this
/// module now serves. The two differ in their guard types and in whether locking can fail, so both
/// are reached through closures here and the difference stays in one place.
struct Lock<T>(LockImpl<T>);

impl<T> Lock<T> {
    fn new(value: T) -> Self {
        Lock(LockImpl::new(value))
    }

    // A poisoned lock is recovered rather than treated as a failure: the guarded value is a
    // BTreeMap that a panicking writer leaves structurally intact, and the worst a stale entry can
    // do is expire. Refusing to read would silently disable the cache for the process's remaining
    // life, which is the more damaging failure.
    #[cfg(feature = "std")]
    fn with_read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.0.read().unwrap_or_else(|e| e.into_inner()))
    }
    #[cfg(not(feature = "std"))]
    fn with_read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.0.read())
    }

    #[cfg(feature = "std")]
    fn with_write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.0.write().unwrap_or_else(|e| e.into_inner()))
    }
    #[cfg(not(feature = "std"))]
    fn with_write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.0.write())
    }
}

struct StatusAndTime {
    status: PathValidationStatus, // Valid or Revoked
    time: u64,
}

// Keyed by (issuer name, hex SHA-256 of issuer SPKI, serial). The SPKI hash binds a cached
// determination to the issuing key so issuers sharing a subject name cannot answer for one another.
type CacheMap = BTreeMap<(String, String, String), StatusAndTime>;

/// Provided in-memory revocation status cache
pub struct RevocationCache {
    cache_map: Lock<CacheMap>,
}

impl RevocationCache {
    /// Create new RevocationCache instance
    pub fn new() -> Self {
        RevocationCache {
            cache_map: Lock::new(Default::default()),
        }
    }
}

impl Default for RevocationCache {
    /// Create a new default RevocationCache instance
    fn default() -> Self {
        Self::new()
    }
}

/// Hex SHA-256 of the issuer's DER-encoded SPKI, used to key cached determinations to the issuing
/// key. None when the SPKI cannot be encoded, in which case there is nothing sound to key on.
fn issuer_spki_hash_hex(issuer: &dyn SubjectNameAndKey) -> Option<String> {
    let spki = issuer.spki().to_der().ok()?;
    Some(buffer_to_hex(Sha256::digest(&spki).to_vec().as_slice()))
}

/// Builds the cache key for a certificate under a given issuing key. None when the issuer's SPKI
/// cannot be encoded, which leaves nothing sound to key on.
fn cache_key(
    cert: &PDVCertificate,
    issuer: &dyn SubjectNameAndKey,
) -> Option<(String, String, String)> {
    let name = name_to_string(cert.decoded().tbs_certificate().issuer());
    let issuer_key = issuer_spki_hash_hex(issuer)?;
    let serial = buffer_to_hex(cert.decoded().tbs_certificate().serial_number().as_bytes());
    Some((name, issuer_key, serial))
}

impl RevocationStatusCache for RevocationCache {
    fn get_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus {
        let Some(key) = cache_key(cert, issuer) else {
            return RevocationStatusNotDetermined;
        };

        self.cache_map.with_read(|cache_map| {
            let Some(status_and_time) = cache_map.get(&key) else {
                return RevocationStatusNotDetermined;
            };
            // The determination is good until the nextUpdate of the data behind it, compared
            // against the time being asked about rather than the current time.
            if status_and_time.time <= time_of_interest.as_unix_secs() {
                return RevocationStatusNotDetermined;
            }
            info!("Serviced revocation status check for certificate with serial number {} issued by {} from cache", key.2, key.0);
            status_and_time.status
        })
    }

    fn add_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        next_update: u64,
        status: PathValidationStatus,
    ) {
        // Only settled outcomes are worth keeping. Caching an undetermined status would suppress
        // the retry that might settle it.
        if status != PathValidationStatus::Valid
            && status != PathValidationStatus::CertificateRevoked
        {
            return;
        }

        let Some(key) = cache_key(cert, issuer) else {
            return;
        };

        self.cache_map.with_write(|cache_map| {
            // Keep whichever determination is good longer, so a later CRL does not shorten the life
            // of an answer an earlier one already justified.
            if let Some(old) = cache_map.get(&key) {
                if old.time >= next_update {
                    return;
                }
                debug!("Updating entry in revocation status check for certificate with serial number {} issued by {} in cache", key.2, key.0);
            } else {
                debug!("Adding entry to revocation status check for certificate with serial number {} issued by {} to cache", key.2, key.0);
            }
            cache_map.insert(
                key,
                StatusAndTime {
                    status,
                    time: next_update,
                },
            );
        });
    }
}

/// Lets one cache be shared by several environments. A determination is keyed on the issuing key and
/// bounded by the validity of the data behind it, so it stays sound across a rebuild that changes
/// which certificates are available: adding certificates changes which paths exist, not whether a
/// given certificate was revoked under a given key. What a shared cache does outlive is the settings
/// it was populated under, so a caller that shares one owes it a clear when the time of interest
/// moves backward or the revocation policy changes.
impl RevocationStatusCache for Arc<RevocationCache> {
    fn get_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus {
        (**self).get_status(cert, issuer, time_of_interest)
    }

    fn add_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        next_update: u64,
        status: PathValidationStatus,
    ) {
        (**self).add_status(cert, issuer, next_update, status)
    }
}

impl RevocationCache {
    /// Discards every cached determination. Needed when the time of interest moves backward or the
    /// revocation policy tightens: entries expire against the time being asked about, so moving that
    /// time earlier can bring an expired determination back into range, and an entry vetted under
    /// one policy is not vetted under a stricter one.
    pub fn clear(&self) {
        self.cache_map.with_write(|cache_map| cache_map.clear());
    }
}

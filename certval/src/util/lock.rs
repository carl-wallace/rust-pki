//! One reader-writer lock for the caches, whichever build they are compiled into.
//!
//! The cache traits ([`crate::RevocationStatusCache`],
//! [`crate::environment::pki_environment_traits::SignatureVerificationCache`]) are used behind
//! `&self` and require `Sync`, so interior mutability has to be a lock rather than a cell -- and
//! `std`'s is unavailable on the `no_std` targets these caches now serve. `std::sync::RwLock` is
//! kept wherever it exists rather than using the spin lock everywhere: uncontended the two are
//! comparable, but a spin lock burns CPU while waiting and, worse, keeps spinning when the OS
//! preempts the thread holding it. These caches guard a `BTreeMap`/`BTreeSet` whose critical
//! sections allocate and rebalance, and at least one consumer shares a single cache across a
//! request-handling thread pool, so parking is the right behavior where it is available.
//!
//! The two implementations differ in their guard types and in whether locking can fail, so both are
//! reached through closures and the difference stays here.

#[cfg(feature = "std")]
type LockImpl<T> = std::sync::RwLock<T>;
#[cfg(not(feature = "std"))]
type LockImpl<T> = spin::RwLock<T>;

/// A reader-writer lock over `T`, backed by `std::sync::RwLock` where `std` is available and by
/// `spin::RwLock` otherwise.
pub(crate) struct Lock<T>(LockImpl<T>);

impl<T> Lock<T> {
    /// Wraps `value`.
    pub(crate) fn new(value: T) -> Self {
        Lock(LockImpl::new(value))
    }

    // A poisoned lock is recovered rather than treated as a failure: the guarded value is a
    // collection that a panicking writer leaves structurally intact, and the worst a stale entry
    // can do is expire or be a redundant verification. Refusing to read would silently disable the
    // cache for the process's remaining life, which is the more damaging failure.
    #[cfg(feature = "std")]
    pub(crate) fn with_read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.0.read().unwrap_or_else(|e| e.into_inner()))
    }
    #[cfg(not(feature = "std"))]
    pub(crate) fn with_read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.0.read())
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.0.write().unwrap_or_else(|e| e.into_inner()))
    }
    #[cfg(not(feature = "std"))]
    pub(crate) fn with_write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.0.write())
    }
}

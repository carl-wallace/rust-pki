//! Microsoft CryptoAPI (CAPI) system certificate stores as sources of trust anchors and
//! intermediate CA certificates.
//!
//! This module adapts CAPI stores to the types the rest of the crate already understands. It does
//! not introduce new [`TrustAnchorSource`](crate::TrustAnchorSource) or
//! [`CertificateSource`](crate::CertificateSource) implementations: a CAPI store is read into a
//! [`TaSource`] or [`CertSource`], which brings the existing indexing and path-building machinery
//! along with it. Three shapes are supported:
//!
//! - [`TaSource::new_from_capi`] — read-only trust anchors, typically from `ROOT`.
//! - [`CertSource::new_from_capi`] — read-only intermediate CA certificates, typically from `CA`.
//! - [`CapiCertStore`] — a [`CertVector`] whose `push` writes through to a CAPI store, for use as
//!   the sink of a dynamic build (see [`fetch_to_buffer`](crate::fetch_to_buffer)).
//!
//! Every shape names its store with a [`CapiStore`], which carries both the store name and the
//! [`CapiStoreLocation`] it lives in, so a configuration can mix locations — machine `ROOT` for
//! anchors alongside a user `CA` store for the writable cache.
//!
//! ```no_run
//! # #[cfg(all(windows, feature = "capi"))] {
//! use certval::*;
//! use core::str::FromStr;
//! # fn main() -> certval::Result<()> {
//! // Anchors from the machine root store; note the parse accepts the `Cert:\` provider spelling.
//! let ta_source = TaSource::new_from_capi(&[CapiStore::from_str("LocalMachine\\ROOT")?])?;
//!
//! // Intermediates from the current user's CA store, which is also the default location.
//! let cps = CertificationPathSettings::new();
//! let cert_source = CertSource::new_from_capi(&[CapiStore::from_str("CA")?], &cps)?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Read-only is enforced by API surface, not by the OS — and that costs something
//!
//! The underlying store handles are opened for read *and write*. The read-only shapes are
//! read-only because they never offer a way to add a certificate, not because the handle forbids
//! it. `CERT_STORE_READONLY_FLAG` would make that structural, but it is not reachable through the
//! safe wrapper this module is built on, and reaching past that wrapper would mean giving up the
//! crate's `forbid(unsafe_code)`.
//!
//! The consequence is not cosmetic: because every open asks for write access,
//! [`CapiStoreLocation::LocalMachine`] fails with `PermissionDenied` for an unelevated process
//! **even when only reading**. Windows itself lets any process read the machine stores; it is the
//! write request that is refused. See [`CapiStoreLocation`] for what remains reachable, and
//! [`CapiStore::is_accessible`] for testing it.
//!
//! Lifting this means opening with `CERT_STORE_READONLY_FLAG` on the read paths, which needs either
//! an upstream addition to the wrapper or a direct binding of `CertOpenStore` — and the direct
//! binding would have to carry the enumeration and the enhanced-key-usage query with it, because
//! the wrapper's handle type cannot be constructed from a handle opened elsewhere.
//!
//! # A CAPI root store is not the trust set Windows itself applies
//!
//! Windows narrows individual roots with a per-certificate EKU property, and the certificates read
//! here are the raw contents of the store. Treating them all as unrestricted anchors yields a
//! *more* permissive trust set than the platform uses. [`CapiReadOptions::honor_eku_restrictions`]
//! governs what happens to a restricted root; the default keeps it and logs, so that the choice is
//! visible before it is made. This does not yet account for the `Disallowed` store or for roots
//! disabled through the AuthRoot program.
//!
//! It also runs the other way, and this is the one that surprises. A root store does not hold the
//! whole of the Microsoft root program: Windows ships a subset and fetches the rest on demand,
//! through Automatic Root Certificates Update, when its own chain engine meets a certificate that
//! needs one. So a store holds the roots that machine has happened to need so far, and reading it
//! yields a trust set *narrower* than the platform's — one that grows over time without anything
//! here changing.
//!
//! The practical shape of that: a target can fail to find a path, and then succeed on a later run,
//! because something else on the machine caused the missing root to be fetched in between. This was
//! observed during development — a machine root store went from 53 anchors to 54 mid-session, the
//! new one being exactly the anchor a failing target needed. Closing the gap would mean handing
//! path building to `CertGetCertificateChain`, which is the thing using this crate is instead of.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use log::{debug, error, info, warn};

use schannel::cert_context::{CertContext, HashAlgorithm, ValidUses};
use schannel::cert_store::{CertAdd, CertStore};

use crate::{
    source::cert_source::CertFile, util::error::Error, CertSource, CertVector,
    CertificationPathSettings, Result, TaSource,
};

/// The system store location a [`CapiStore`] lives in.
///
/// The two are not disjoint. Windows composes the current user's view of a store from the
/// machine's entries plus any the user has added, so [`CapiStoreLocation::CurrentUser`] is a
/// superset and selecting [`CapiStoreLocation::LocalMachine`] yields *fewer* certificates, not
/// more — the opposite of what the name suggests. Measured on one Windows 11 installation:
/// `CurrentUser\ROOT` held 60 anchors, `LocalMachine\ROOT` held 53, and all 53 appeared in the
/// user view.
///
/// # LocalMachine requires elevation, for reading as well as writing
///
/// Every open here asks for write access, which an unelevated process is refused on the machine
/// stores; see the module documentation. This is a property of how this module reaches CAPI, not of
/// Windows, which lets any process read them.
///
/// So [`CapiStoreLocation::LocalMachine`] works, but only from an elevated process. An unelevated
/// caller reaches the machine's anchors through the user view that contains them, and what it
/// cannot do is ask for the machine's anchors *to the exclusion of* user-added ones — which is the
/// security-relevant request, since user-added roots are the ones an attacker can install.
///
/// Use [`CapiStore::is_accessible`] to decide whether to offer a machine store rather than
/// presenting one that will fail.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapiStoreLocation {
    /// `CERT_SYSTEM_STORE_CURRENT_USER`. Readable and writable without elevation. Includes the
    /// machine's entries for the same store name.
    #[default]
    CurrentUser,

    /// `CERT_SYSTEM_STORE_LOCAL_MACHINE`. Requires elevation, for reading as well as writing.
    LocalMachine,
}

impl fmt::Display for CapiStoreLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapiStoreLocation::CurrentUser => write!(f, "CurrentUser"),
            CapiStoreLocation::LocalMachine => write!(f, "LocalMachine"),
        }
    }
}

impl FromStr for CapiStoreLocation {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // Accepted case-insensitively because these arrive from a command line or a settings file,
        // where "localmachine" and "LocalMachine" are the same intent.
        match s.to_ascii_lowercase().as_str() {
            "currentuser" | "user" => Ok(CapiStoreLocation::CurrentUser),
            "localmachine" | "machine" => Ok(CapiStoreLocation::LocalMachine),
            _ => {
                error!(
                    "Unrecognized CAPI store location: {s}. Expected CurrentUser or LocalMachine"
                );
                Err(Error::Unrecognized)
            }
        }
    }
}

/// Names a CAPI system certificate store: a location plus a store name.
///
/// The [`FromStr`] implementation accepts the `Location\Name` spelling used by the PowerShell
/// `Cert:\` provider, with `/` accepted in place of `\` for shells that treat the backslash
/// specially. A bare name defaults the location to [`CapiStoreLocation::CurrentUser`].
///
/// ```
/// # #[cfg(all(windows, feature = "capi"))] {
/// use certval::{CapiStore, CapiStoreLocation};
/// use core::str::FromStr;
///
/// let machine_root = CapiStore::from_str("LocalMachine\\ROOT").unwrap();
/// assert_eq!(machine_root.location, CapiStoreLocation::LocalMachine);
/// assert_eq!(machine_root.name, "ROOT");
///
/// // A bare name is a current-user store.
/// let user_ca = CapiStore::from_str("CA").unwrap();
/// assert_eq!(user_ca.location, CapiStoreLocation::CurrentUser);
///
/// // Display round-trips the parse.
/// assert_eq!(machine_root.to_string(), "LocalMachine\\ROOT");
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapiStore {
    /// The system store location.
    pub location: CapiStoreLocation,

    /// The store name, e.g. `ROOT`, `CA`, `MY`, or the name of a custom store.
    pub name: String,
}

impl CapiStore {
    /// Names a store in an explicit location.
    pub fn new(location: CapiStoreLocation, name: impl Into<String>) -> Self {
        CapiStore {
            location,
            name: name.into(),
        }
    }

    /// Names a store in the current user's location.
    pub fn current_user(name: impl Into<String>) -> Self {
        CapiStore::new(CapiStoreLocation::CurrentUser, name)
    }

    /// Names a store in the local machine location.
    pub fn local_machine(name: impl Into<String>) -> Self {
        CapiStore::new(CapiStoreLocation::LocalMachine, name)
    }

    /// Reports whether this store can be opened by the current process.
    ///
    /// Intended for building a list of offerable stores: a caller that presents store choices can
    /// use this to omit or disable the ones that would fail. Because every open here asks for write
    /// access, this answers "can this process use this store" rather than "is this process
    /// elevated" — which is the more useful question, and the more accurate one. It is true for an
    /// unelevated process that has been granted access to a machine store by ACL, where an
    /// elevation check would wrongly say no.
    ///
    /// Opening a store is cheap, but it is not free; a caller rendering a list on every frame
    /// should cache the answer rather than probing repeatedly.
    ///
    /// ```no_run
    /// # #[cfg(all(windows, feature = "capi"))] {
    /// use certval::CapiStore;
    ///
    /// // The machine stores are typically reachable only by an elevated process.
    /// if CapiStore::local_machine("ROOT").is_accessible() {
    ///     // offer it
    /// }
    /// # }
    /// ```
    pub fn is_accessible(&self) -> bool {
        match self.open() {
            Ok(_) => true,
            Err(_e) => {
                // `open` has already logged the reason at error level.
                false
            }
        }
    }

    /// Opens the store.
    ///
    /// The handle is opened for read and write regardless of how the caller intends to use it; see
    /// the module documentation on read-only enforcement.
    fn open(&self) -> Result<CertStore> {
        let r = match self.location {
            CapiStoreLocation::CurrentUser => CertStore::open_current_user(&self.name),
            CapiStoreLocation::LocalMachine => CertStore::open_local_machine(&self.name),
        };
        match r {
            Ok(store) => Ok(store),
            Err(e) => {
                error!("Failed to open CAPI store {self} with: {e}");
                Err(Error::StdIoError(e.kind()))
            }
        }
    }
}

impl fmt::Display for CapiStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\\{}", self.location, self.name)
    }
}

impl FromStr for CapiStore {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            error!("Empty CAPI store specification");
            return Err(Error::Unrecognized);
        }

        // Split on the last separator so a custom store name containing one is not mangled by the
        // location prefix being optional.
        match s.rsplit_once(['\\', '/']) {
            Some((location, name)) if !name.is_empty() => Ok(CapiStore {
                location: CapiStoreLocation::from_str(location)?,
                name: name.to_string(),
            }),
            Some(_) => {
                error!("CAPI store specification {s} has a location but no store name");
                Err(Error::Unrecognized)
            }
            None => Ok(CapiStore::current_user(s)),
        }
    }
}

/// Governs how the read-only shapes treat what they find in a store.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapiReadOptions {
    /// When true, a certificate whose effective enhanced key usage has been narrowed by the store
    /// — via the per-certificate EKU property Windows uses to restrict individual roots — is
    /// skipped rather than read.
    ///
    /// Defaults to false, which reads every certificate in the store and logs a count of those
    /// carrying restrictions. That is the more permissive of the two and is deliberately the noisy
    /// one: it produces a trust set wider than the one Windows itself applies.
    pub honor_eku_restrictions: bool,
}

/// The SHA-1 thumbprint of a certificate context, hex encoded, as CAPI tooling displays it.
///
/// Used for provenance strings and for the write sink's membership set. Falls back to an empty
/// string when the platform declines to hash, which only affects labelling.
fn thumbprint(cx: &CertContext) -> String {
    match cx.fingerprint(HashAlgorithm::sha1()) {
        Ok(fp) => crate::buffer_to_hex(&fp),
        Err(e) => {
            debug!("Failed to compute SHA-1 thumbprint for a CAPI certificate with: {e}");
            String::new()
        }
    }
}

/// Provenance string recorded in [`CertFile::filename`] for a certificate read from a CAPI store.
///
/// Shaped so that a log line naming it identifies the exact store entry it came from, the way a
/// path does for a file-backed certificate.
fn provenance(store: &CapiStore, thumb: &str) -> String {
    format!("capi:{store}\\{thumb}")
}

/// Reads the certificates from a set of CAPI stores into [`CertFile`] buffers, discarding
/// duplicates across stores.
///
/// Certificates are deduplicated by thumbprint, which matters because the locations overlap: the
/// current user's view of a store generally includes the machine's entries, so naming both
/// locations would otherwise read each machine certificate twice.
///
/// [`TaSource::new_from_capi`] and [`CertSource::new_from_capi`] are the usual way in. This is for
/// a caller merging CAPI certificates into a pool it is assembling from several places, which
/// wants the buffers rather than a source built around them — pushing these into an existing
/// [`CertSource`] costs one parse and one indexing pass instead of two.
pub fn certfiles_from_capi(stores: &[CapiStore], opts: &CapiReadOptions) -> Result<Vec<CertFile>> {
    let mut buffers: Vec<CertFile> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut restricted = 0usize;

    for store_spec in stores {
        let store = store_spec.open()?;
        let mut read = 0usize;

        for cx in store.certs() {
            let thumb = thumbprint(&cx);
            if !thumb.is_empty() && !seen.insert(thumb.clone()) {
                debug!("Skipping duplicate certificate {thumb} from CAPI store {store_spec}");
                continue;
            }

            // A narrowed EKU is the store telling us this certificate is not trusted for
            // everything. Whether that is honored is the caller's call; that it is present is
            // always worth saying.
            if let Ok(ValidUses::Oids(oids)) = cx.valid_uses() {
                restricted += 1;
                if opts.honor_eku_restrictions {
                    debug!(
                        "Skipping certificate {thumb} from CAPI store {store_spec}: usage restricted to {oids:?}"
                    );
                    continue;
                }
                debug!(
                    "Certificate {thumb} from CAPI store {store_spec} is restricted to {oids:?}; reading it as unrestricted"
                );
            }

            buffers.push(CertFile {
                filename: provenance(store_spec, &thumb),
                bytes: cx.to_der().to_vec(),
            });
            read += 1;
        }

        info!("Read {read} certificate(s) from CAPI store {store_spec}");
    }

    if restricted > 0 && !opts.honor_eku_restrictions {
        warn!(
            "{restricted} certificate(s) read from CAPI stores carry usage restrictions that were \
             ignored. The resulting trust set is broader than the one Windows applies. Set \
             CapiReadOptions::honor_eku_restrictions to exclude them."
        );
    }

    Ok(buffers)
}

impl TaSource {
    /// Creates a [`TaSource`] from one or more CAPI stores, read-only, with default options.
    ///
    /// The stores are read in the order given and their contents unioned, with duplicates
    /// discarded. See [`CapiReadOptions`] for the treatment of usage-restricted anchors, and the
    /// module documentation for why the result is not identical to the platform's own trust set.
    pub fn new_from_capi(stores: &[CapiStore]) -> Result<Self> {
        TaSource::new_from_capi_with(stores, &CapiReadOptions::default())
    }

    /// Creates a [`TaSource`] from one or more CAPI stores, read-only.
    pub fn new_from_capi_with(stores: &[CapiStore], opts: &CapiReadOptions) -> Result<Self> {
        let buffers = certfiles_from_capi(stores, opts)?;
        let mut ta_source = TaSource::new();
        for cf in buffers {
            ta_source.push(cf);
        }
        ta_source.initialize()?;
        Ok(ta_source)
    }
}

impl CertSource {
    /// Creates a [`CertSource`] from one or more CAPI stores, read-only, with default options.
    ///
    /// The returned instance carries no partial paths. Path building over it searches, exactly as
    /// it does for a [`CertSource`] assembled from a folder of certificates; call
    /// [`find_all_partial_paths`](CertSource::find_all_partial_paths) to precompute the graph.
    pub fn new_from_capi(stores: &[CapiStore], cps: &CertificationPathSettings) -> Result<Self> {
        CertSource::new_from_capi_with(stores, cps, &CapiReadOptions::default())
    }

    /// Creates a [`CertSource`] from one or more CAPI stores, read-only.
    pub fn new_from_capi_with(
        stores: &[CapiStore],
        cps: &CertificationPathSettings,
        opts: &CapiReadOptions,
    ) -> Result<Self> {
        let buffers = certfiles_from_capi(stores, opts)?;
        let mut cert_source = CertSource::new();
        for cf in buffers {
            cert_source.push(cf);
        }
        cert_source.initialize(cps)?;
        Ok(cert_source)
    }
}

/// A CAPI store used as the sink of a dynamic build: a [`CertVector`] whose `push` writes the
/// certificate through to the store.
///
/// This is the write-side counterpart of [`CertSource::new_from_capi`], and is what a caller hands
/// to [`fetch_to_buffer`](crate::fetch_to_buffer) in place of a folder-backed collection.
///
/// The store handle is not retained. Membership is tracked in a thumbprint set snapshotted when
/// the instance is created and updated as certificates are added, and each `push` opens the store
/// for the duration of the add. That keeps the type `Send + Sync` — which the async dynamic-build
/// path wants and a raw `HCERTSTORE` would not give — and avoids holding a machine store open for
/// the length of a run. Pushes are rare and follow a network fetch, so the reopen is not on any
/// path where its cost is visible.
///
/// ```no_run
/// # #[cfg(all(windows, feature = "capi"))] {
/// use certval::*;
/// # fn main() -> certval::Result<()> {
/// let mut sink = CapiCertStore::open_rw(&CapiStore::current_user("CA"))?;
/// // hand `sink` to fetch_to_buffer as the &mut dyn CertVector
/// # Ok(())
/// # }
/// # }
/// ```
///
/// # Write failures surface on the first push, not at open
///
/// Opening a `LocalMachine` store without elevation succeeds; the denial appears when a
/// certificate is added. [`CertVector::push`] cannot report that — it returns nothing — so
/// failures are logged and counted, and [`CapiCertStore::write_failures`] lets a caller report
/// them once the build is done. Failing at open instead would take an elevation check, which is
/// not reachable through the safe wrapper this module is built on.
pub struct CapiCertStore {
    store: CapiStore,
    thumbprints: BTreeSet<String>,
    write_failures: usize,
}

impl CapiCertStore {
    /// Opens a CAPI store for use as a dynamic-build sink, snapshotting what it already holds.
    ///
    /// The snapshot is what [`CertVector::contains`] answers from, so certificates already in the
    /// store are not re-added and, more usefully, are not re-downloaded: the dynamic-building loop
    /// tests whether the pool grew to decide whether to iterate again.
    pub fn open_rw(store: &CapiStore) -> Result<Self> {
        let opened = store.open()?;
        let mut thumbprints = BTreeSet::new();
        for cx in opened.certs() {
            let thumb = thumbprint(&cx);
            if !thumb.is_empty() {
                thumbprints.insert(thumb);
            }
        }
        info!(
            "Opened CAPI store {store} for writing with {} existing certificate(s)",
            thumbprints.len()
        );
        Ok(CapiCertStore {
            store: store.clone(),
            thumbprints,
            write_failures: 0,
        })
    }

    /// The store this instance writes to.
    pub fn store(&self) -> &CapiStore {
        &self.store
    }

    /// The number of certificates that could not be written to the store.
    ///
    /// Non-zero after a dynamic build against a store the process cannot write to. The
    /// certificates are still in the in-memory pool for the run that found them; they are simply
    /// not persisted for the next one.
    pub fn write_failures(&self) -> usize {
        self.write_failures
    }
}

impl CertVector for CapiCertStore {
    fn contains(&self, cert: &CertFile) -> bool {
        // Hashing the DER rather than asking the store keeps this O(log n) on a path the build
        // loop takes for every candidate certificate. The thumbprint is over the same bytes
        // CertFile compares on, so this agrees with CertFile equality.
        match CertContext::new(&cert.bytes) {
            Ok(cx) => {
                let thumb = thumbprint(&cx);
                !thumb.is_empty() && self.thumbprints.contains(&thumb)
            }
            Err(e) => {
                debug!("Failed to read a certificate while testing CAPI store membership: {e}");
                false
            }
        }
    }

    fn push(&mut self, cert: CertFile) {
        let cx = match CertContext::new(&cert.bytes) {
            Ok(cx) => cx,
            Err(e) => {
                error!(
                    "Failed to read the certificate from {} for addition to CAPI store {}: {e}",
                    cert.filename, self.store
                );
                self.write_failures += 1;
                return;
            }
        };

        let thumb = thumbprint(&cx);
        if !thumb.is_empty() && self.thumbprints.contains(&thumb) {
            debug!(
                "Certificate {thumb} is already present in CAPI store {}",
                self.store
            );
            return;
        }

        let mut opened = match self.store.open() {
            Ok(opened) => opened,
            Err(_e) => {
                self.write_failures += 1;
                return;
            }
        };

        match opened.add_cert(&cx, CertAdd::UseExisting) {
            Ok(_) => {
                debug!(
                    "Added certificate {thumb} from {} to CAPI store {}",
                    cert.filename, self.store
                );
                if !thumb.is_empty() {
                    self.thumbprints.insert(thumb);
                }
            }
            Err(e) => {
                error!(
                    "Failed to add the certificate from {} to CAPI store {} with: {e}",
                    cert.filename, self.store
                );
                self.write_failures += 1;
            }
        }
    }

    fn len(&self) -> usize {
        self.thumbprints.len()
    }

    fn is_empty(&self) -> bool {
        self.thumbprints.is_empty()
    }
}

#[test]
fn capi_store_parses_provider_spelling() {
    let machine_root = CapiStore::from_str("LocalMachine\\ROOT").unwrap();
    assert_eq!(machine_root.location, CapiStoreLocation::LocalMachine);
    assert_eq!(machine_root.name, "ROOT");
    assert_eq!(machine_root.to_string(), "LocalMachine\\ROOT");

    // Forward slashes are accepted for shells that treat the backslash specially.
    assert_eq!(CapiStore::from_str("CurrentUser/CA").unwrap().name, "CA");

    // A bare name is a current-user store, and case does not matter in the location.
    assert_eq!(
        CapiStore::from_str("CA").unwrap(),
        CapiStore::from_str("currentuser\\CA").unwrap()
    );

    assert!(CapiStore::from_str("").is_err());
    assert!(CapiStore::from_str("LocalMachine\\").is_err());
    assert!(CapiStore::from_str("Nowhere\\CA").is_err());
}

// Reads the current user's ROOT store, which exists on every Windows installation, and confirms
// the anchors come back indexed and usable rather than merely counted.
#[test]
fn ta_source_from_current_user_root() {
    let src = TaSource::new_from_capi(&[CapiStore::current_user("ROOT")]).unwrap();
    let tas = src.get_tas();
    assert!(
        !tas.is_empty(),
        "current user ROOT store held no certificates"
    );
    assert!(tas
        .iter()
        .all(|cf| cf.filename.starts_with("capi:CurrentUser\\ROOT\\")));
}

// Pins both halves of the LocalMachine situation, since which half applies depends on how the
// test process was launched. Unelevated, the open is refused outright -- that is the limitation
// described on CapiStoreLocation, and this test is what will start failing if it is ever lifted.
// Elevated, the open succeeds and the two locations overlap, so unioning them must not
// double-count the machine anchors that also appear in the user view.
#[test]
fn local_machine_is_refused_unelevated_and_deduplicates_when_not() {
    let user = TaSource::new_from_capi(&[CapiStore::current_user("ROOT")])
        .unwrap()
        .get_tas()
        .len();

    match TaSource::new_from_capi(&[
        CapiStore::current_user("ROOT"),
        CapiStore::local_machine("ROOT"),
    ]) {
        Ok(both) => assert_eq!(
            user,
            both.get_tas().len(),
            "machine roots were counted twice"
        ),
        Err(Error::StdIoError(std::io::ErrorKind::PermissionDenied)) => {
            // Expected when unelevated; nothing further to assert.
        }
        Err(e) => panic!("unexpected error opening LocalMachine\\ROOT: {e:?}"),
    }
}

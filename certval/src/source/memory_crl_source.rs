//! CRLs held in memory for the revocation checker to consult
//!
//! This lives apart from `crl_source` -- named rather than linked, since that module is gated on
//! `std` and the link would not resolve in the builds this one exists for -- for the reason
//! [`revocation_cache`](crate::source::revocation_cache) does: it needs nothing that one needs. A
//! CRL here is a buffer in a vector, with no filesystem and no network behind it, so it is
//! available wherever revocation checking is — including targets that take this crate without
//! `std`, which is where a folder of files cannot follow.
//!
//! That absence is the whole reason this exists. A caller that retrieves CRLs itself — a browser
//! frontend fetching through a relay, a service handed revocation data with the request, a test
//! that wants a CRL in play without writing one to disk — had no `CrlSource` to put them in, and
//! ended up writing this type for itself.

use alloc::sync::Arc;
use alloc::vec::Vec;

use der::Decode;
use x509_cert::certificate::Raw;
use x509_cert::crl::CertificateList;
use x509_cert::name::Name;

use crate::util::lock::Lock;
use crate::{compare_names, CrlSource, Error, PDVCertificate, Result};

/// A CRL and the issuer name it was published under, decoded once when it is added.
struct StoredCrl {
    /// The CRL as retrieved.
    bytes: Vec<u8>,
    /// Issuer name, compared against a certificate's issuer.
    issuer: Name,
}

/// CRLs held in memory, for a caller that obtains revocation data itself.
///
/// **This answers with candidates, not with judgments.** [`get_crls`](CrlSource::get_crls) matches
/// on issuer name alone — deliberately not on scope, validity or signature — because
/// `process_crl` checks all three on everything handed back and tolerates a CRL that turns out not
/// to apply. A superset is therefore correct here and a subset is not, which is what makes the
/// cheap comparison the right one.
///
/// Cloning shares the contents: a clone can be registered on a [`PkiEnvironment`] while the caller
/// keeps one to add to as retrievals complete, so CRLs accumulate without the environment being
/// rebuilt. The same sharing is why the contents sit behind a lock — [`CrlSource::add_crl`] takes
/// `&self`, and a source registered on an environment must be `Send + Sync`.
///
/// [`PkiEnvironment`]: crate::PkiEnvironment
#[derive(Clone)]
pub struct MemoryCrlSource {
    crls: Arc<Lock<Vec<StoredCrl>>>,
}

// Hand-written rather than derived: `Lock` is deliberately not `Default` -- it wraps whichever
// reader-writer lock the target has, and neither spells an empty one the same way.
impl Default for MemoryCrlSource {
    fn default() -> Self {
        MemoryCrlSource {
            crls: Arc::new(Lock::new(Vec::new())),
        }
    }
}

impl MemoryCrlSource {
    /// Returns an empty source.
    pub fn new() -> Self {
        MemoryCrlSource::default()
    }

    /// Adds a retrieved CRL, returning whether it was a CRL at all.
    ///
    /// A body that does not decode is reported rather than stored: a distribution point serving
    /// something else is worth a note in the run, and keeping it would only produce a more
    /// confusing failure later, inside `process_crl`.
    pub fn add(&self, bytes: &[u8]) -> bool {
        let Ok(crl) = CertificateList::<Raw>::from_der(bytes) else {
            return false;
        };
        let stored = StoredCrl {
            bytes: bytes.to_vec(),
            issuer: crl.tbs_cert_list.issuer.clone(),
        };
        self.crls.with_write(|crls| crls.push(stored));
        true
    }

    /// Reports how many CRLs are held.
    pub fn len(&self) -> usize {
        self.crls.with_read(|crls| crls.len())
    }

    /// Reports whether any CRL is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CrlSource for MemoryCrlSource {
    fn get_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .crls
            .with_read(|crls| crls.iter().map(|c| c.bytes.clone()).collect()))
    }

    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        let issuer = cert.decoded().tbs_certificate().issuer();
        Ok(self.crls.with_read(|crls| {
            crls.iter()
                .filter(|c| compare_names(&c.issuer, issuer))
                .map(|c| c.bytes.clone())
                .collect()
        }))
    }

    /// Keeps a CRL the revocation checker retrieved, so a later path in the same process finds it
    /// without going back to the distribution point.
    ///
    /// The URI is not recorded: nothing here is addressed by it, and a store that cannot outlive
    /// the process has no use for the last-modified bookkeeping a folder keeps beside its files.
    fn add_crl(&self, crl_buf: &[u8], _crl: &CertificateList<Raw>, _uri: &str) -> Result<()> {
        match self.add(crl_buf) {
            true => Ok(()),
            false => Err(Error::Unrecognized),
        }
    }
}

/// Shares one source between an environment and the caller adding to it.
impl CrlSource for Arc<MemoryCrlSource> {
    fn get_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        (**self).get_all_crls()
    }

    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        (**self).get_crls(cert)
    }

    fn add_crl(&self, crl_buf: &[u8], crl: &CertificateList<Raw>, uri: &str) -> Result<()> {
        (**self).add_crl(crl_buf, crl, uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_cert;

    /// A CRL published by Amazon Root CA 1, and two certificates: one that root issued, one issued
    /// by somebody else. Real material rather than minted, so the issuer comparison is exercised
    /// against names as they actually encode.
    const AMAZON_CRL: &[u8] = include_bytes!("../../tests/examples/pem_crl/AmazonRootCA1.der.crl");
    const ISSUED_BY_AMAZON: &[u8] = include_bytes!("../../tests/examples/makaan.com/1.der");
    const ISSUED_BY_DIGICERT: &[u8] =
        include_bytes!("../../tests/examples/amazon.com/2-target.der");

    #[test]
    fn a_crl_is_offered_to_certificates_of_its_issuer_and_to_no_others() {
        let source = MemoryCrlSource::new();
        assert!(source.is_empty());
        assert!(source.add(AMAZON_CRL));
        assert_eq!(source.len(), 1);

        let amazon = parse_cert(ISSUED_BY_AMAZON, "1.der").expect("fixture parses");
        let digicert = parse_cert(ISSUED_BY_DIGICERT, "2-target.der").expect("fixture parses");

        assert_eq!(source.get_crls(&amazon).unwrap().len(), 1);
        // Not a judgment that this CRL is wrong for the certificate -- process_crl decides that --
        // but the issuer does not match, so it is not a candidate at all.
        assert!(source.get_crls(&digicert).unwrap().is_empty());
        assert_eq!(source.get_all_crls().unwrap().len(), 1);
    }

    /// The path certval itself drives: the revocation checker hands over a CRL it retrieved, and a
    /// later lookup finds it. This is the whole reason the trait's `add_crl` takes `&self`.
    #[test]
    fn a_crl_added_through_the_trait_is_found_afterwards() {
        let source = MemoryCrlSource::new();
        let crl = CertificateList::<Raw>::from_der(AMAZON_CRL).expect("fixture decodes");
        let amazon = parse_cert(ISSUED_BY_AMAZON, "1.der").expect("fixture parses");
        assert!(source.get_crls(&amazon).unwrap().is_empty());

        source
            .add_crl(AMAZON_CRL, &crl, "http://crl.example/amazon.crl")
            .expect("a decodable CRL is accepted");
        assert_eq!(source.get_crls(&amazon).unwrap().len(), 1);
    }

    /// A distribution point serving something other than a CRL is reported rather than stored, so
    /// the failure lands where the retrieval happened instead of inside path validation later.
    #[test]
    fn a_body_that_is_not_a_crl_is_refused() {
        let source = MemoryCrlSource::new();
        assert!(!source.add(b"this is not a CRL"));
        assert!(
            source.add(ISSUED_BY_AMAZON).eq(&false),
            "nor is a certificate"
        );
        assert!(source.is_empty());
    }

    /// Clones share one set of CRLs: an environment holds one while the caller keeps another to add
    /// to, which is what lets CRLs accumulate without rebuilding the environment.
    #[test]
    fn clones_share_their_contents() {
        let held_by_caller = MemoryCrlSource::new();
        let registered = held_by_caller.clone();
        assert!(held_by_caller.add(AMAZON_CRL));
        assert_eq!(registered.len(), 1);
    }
}

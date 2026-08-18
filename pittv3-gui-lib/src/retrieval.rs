//! The synchronous halves of a retrieving validation run.
//!
//! certval never fetches anything here. What it needs from the outside — an issuer certificate an
//! authority information access URI points at, a CRL, an OCSP response — arrives as bytes the
//! caller obtained. That decomposes a retrieving run into three parts, and only the middle one is
//! asynchronous:
//!
//! 1. **harvest**, synchronously: read URIs out of the certificates in hand ([`harvest_chase_uris`],
//!    [`harvest_revocation_work`]);
//! 2. **fetch**, asynchronously and by whatever means the frontend has — the relay in a browser, a
//!    direct client on a server. Nothing in this crate takes part;
//! 3. **fold**, synchronously: turn a retrieved body into certificates ([`certificates_in`]) or put
//!    a CRL somewhere the revocation checker will look ([`MemoryCrlSource`]).
//!
//! Everything here is therefore feature-free and frontend-free: a browser and a server running the
//! same loop over the same functions cannot reach different conclusions about a certificate, which
//! is the property the tiered design exists to protect.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use certval::{
    collect_crl_dp_uris, collect_ocsp_uris, collect_uris_from_aia_and_sia, compare_names,
    parse_cert, CertificationPath, CertificationPathSettings, CrlSource, Error, PDVCertificate,
    Result, SubjectNameAndKey,
};
// Building an OCSP request needs certval's `ocsp_client`, which exists only under its `revocation`
// feature. Everything else here -- the URI collectors, the CRL source, the response map -- is
// available without it, so only the request half is gated: a build without `revocation` harvests
// the same work minus the OCSP items, which is honest, since such a build could not process a
// response either.
#[cfg(feature = "revocation")]
use certval::build_ocsp_request;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use x509_cert::certificate::Raw;
use x509_cert::crl::CertificateList;

use crate::validate::PreparedValidation;

/// Extracts the certificates from a retrieved body, which by convention is either a single
/// DER-encoded certificate or a certs-only SignedData message, i.e., a `.p7c`. The message form is
/// tried first because both begin with a SEQUENCE and only the message parses as one.
pub fn certificates_in(body: &[u8]) -> Vec<Vec<u8>> {
    if let Ok(ci) = ContentInfo::from_der(body) {
        if let Ok(content) = ci.content.to_der() {
            if let Ok(sd) = SignedData::from_der(content.as_slice()) {
                let mut certs = vec![];
                for set in sd.certificates.iter() {
                    for choice in set.0.iter() {
                        if let Ok(der) = choice.to_der() {
                            certs.push(der);
                        }
                    }
                }
                return certs;
            }
        }
    }
    match body.first() {
        Some(0x30) => vec![body.to_vec()],
        _ => vec![],
    }
}

/// Collects the authority and subject information access URIs carried by `certs`, deduplicated and
/// in the order first seen, for a caller building a path toward material it does not hold.
///
/// A certificate that will not parse is skipped rather than reported: this is called with whatever
/// a retrieval produced, where an unparsable entry is an ordinary outcome and not a fault in the
/// run being made.
pub fn harvest_chase_uris(certs: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut uris = vec![];
    for (name, der) in certs {
        if let Ok(cert) = parse_cert(der, name) {
            collect_uris_from_aia_and_sia(&cert, &mut uris);
        }
    }
    dedup_in_place(&mut uris);
    uris
}

/// What a run would have to retrieve before revocation status could be determined for the
/// certificates on the paths it builds.
///
/// The two halves are shaped differently because the protocols are. A CRL is fetched from a URI and
/// covers every certificate its issuer published it for, so a URI is the whole of the work. An OCSP
/// request is *about* one certificate and has to be built before it can be sent, so the work is a
/// request already assembled, together with the identity of what it asks about.
#[derive(Clone, Debug, Default)]
pub struct RevocationWork {
    /// CRL distribution point URIs, deduplicated.
    pub crl_dp: Vec<String>,
    /// OCSP requests to send, at most one per (certificate, issuer, responder).
    pub ocsp: Vec<OcspRequestItem>,
}

impl RevocationWork {
    /// Reports whether anything at all was found to retrieve.
    pub fn is_empty(&self) -> bool {
        self.crl_dp.is_empty() && self.ocsp.is_empty()
    }
}

/// One OCSP request: where to send it, what to send, and what the answer will be about.
#[derive(Clone, Debug)]
pub struct OcspRequestItem {
    /// Responder named by the certificate's authority information access extension.
    pub uri: String,
    /// The DER-encoded request, already built.
    pub request: Vec<u8>,
    /// Identifies the answer this asks for, so the response can be put back where it belongs.
    pub key: OcspKey,
}

/// Identifies the certificate an OCSP answer concerns, as the pair that an OCSP `CertID` names: the
/// certificate itself and the issuer whose responder answers for it.
///
/// The issuer is part of the identity rather than a detail of the request. A `CertID` is the hash of
/// the *issuer's* name and public key together with the certificate's serial number, so the same
/// certificate reached under a different issuer — which cross-certification makes an ordinary
/// occurrence — is a different question with a different answer.
///
/// Keyed by these rather than by position in a path, so a response survives the path set being
/// rebuilt, which chasing does routinely.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OcspKey {
    /// DER encoding of the certificate the answer is about.
    cert: Vec<u8>,
    /// DER encoding of the issuer's subject public key info.
    issuer_spki: Vec<u8>,
}

impl OcspKey {
    /// Identifies `cert` as issued by `issuer`. `None` when either will not re-encode, which cannot
    /// happen for material that decoded in the first place.
    pub fn new(cert: &PDVCertificate, issuer: &dyn SubjectNameAndKey) -> Option<Self> {
        Some(OcspKey {
            cert: cert.decoded().to_der().ok()?,
            issuer_spki: issuer.spki().to_der().ok()?,
        })
    }
}

/// OCSP responses retrieved for a run.
///
/// Unlike CRLs, these cannot be given to certval as a source — there is no `OcspSource` trait, and
/// a response reaches the checker only through a path's `ocsp_responses` slot, which is indexed by
/// position. This holds them keyed by what they are actually about, and the validation path fills
/// the slots from it each time it builds a path. Cloning shares the contents, so a retrieval that
/// completes after the environment was prepared is still found.
#[derive(Clone, Default)]
pub struct OcspResponses {
    responses: Arc<RwLock<BTreeMap<OcspKey, Vec<u8>>>>,
}

impl OcspResponses {
    /// Returns an empty set.
    pub fn new() -> Self {
        OcspResponses::default()
    }

    /// Records a retrieved response. The bytes are not examined here: certval's
    /// `process_ocsp_response` decides whether they answer anything, and it does so with the path
    /// and the settings in hand, which this has neither of.
    pub fn insert(&self, key: OcspKey, response: Vec<u8>) {
        if let Ok(mut guard) = self.responses.write() {
            guard.insert(key, response);
        }
    }

    /// Returns the response held for `cert` as issued by `issuer`, if any.
    pub fn get(&self, cert: &PDVCertificate, issuer: &dyn SubjectNameAndKey) -> Option<Vec<u8>> {
        let key = OcspKey::new(cert, issuer)?;
        let guard = self.responses.read().ok()?;
        guard.get(&key).cloned()
    }

    /// Reports whether a response is held for this key already, so a run does not ask a second
    /// responder something it has already been told.
    pub fn contains(&self, key: &OcspKey) -> bool {
        self.responses
            .read()
            .map(|g| g.contains_key(key))
            .unwrap_or(false)
    }

    /// Reports how many responses are held.
    pub fn len(&self) -> usize {
        self.responses.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Reports whether any response is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Works out what would have to be retrieved before revocation status could be determined for the
/// certificates on every path the environment builds for `ees`: the CRL distribution points they
/// name, and an OCSP request per certificate built against the issuer that path gives it.
///
/// The paths are built and then dropped, and built again by the validation that follows. That is
/// deliberate rather than wasteful: path *building* runs against a graph that partial-path discovery
/// has already computed and is cheap by comparison, whereas keeping the paths would tie what gets
/// retrieved to one particular path set — and the whole point of retrieving is that the path set
/// changes when the retrieved certificates arrive.
///
/// Trust anchors are skipped: revocation status is not determined for an anchor, so a distribution
/// point one names is not something this run needs.
pub fn harvest_revocation_work(
    prepared: &PreparedValidation,
    cps: &CertificationPathSettings,
    ees: &[(String, Vec<u8>)],
) -> RevocationWork {
    let pe = prepared.environment();
    let toi = cps.get_time_of_interest();
    let mut out = RevocationWork::default();
    // Tracks the (certificate, responder) pairs already queued, so a certificate appearing on
    // several paths is asked about once. Only the OCSP half needs it.
    #[cfg(feature = "revocation")]
    let mut asked: Vec<(OcspKey, String)> = vec![];

    for (name, der) in ees {
        let Ok(target) = parse_cert(der, name) else {
            continue;
        };
        if pe.is_cert_a_trust_anchor(&target).is_ok() {
            continue;
        }
        let mut paths: Vec<CertificationPath> = vec![];
        if pe
            .get_paths_for_target(&target, &mut paths, 0, toi)
            .is_err()
        {
            continue;
        }
        for path in &paths {
            // The order the revocation checker itself uses: the intermediates from the one the
            // trust anchor issued, then the target. Position matters here only for finding each
            // certificate's issuer, which is what an OCSP request has to be built against.
            let chain: Vec<&PDVCertificate> = path
                .intermediates
                .iter()
                .chain(core::iter::once(&path.target))
                .collect();

            for (pos, cert) in chain.iter().enumerate() {
                collect_crl_dp_uris(cert, &mut out.crl_dp);

                let mut responders = vec![];
                collect_ocsp_uris(cert, &mut responders);
                if responders.is_empty() {
                    continue;
                }
                let issuer: &dyn SubjectNameAndKey = match pos {
                    0 => &path.trust_anchor.decoded_ta,
                    _ => chain[pos - 1].as_ref(),
                };
                let Some(key) = OcspKey::new(cert, issuer) else {
                    continue;
                };
                #[cfg(not(feature = "revocation"))]
                let _ = key;
                #[cfg(feature = "revocation")]
                let Ok(request) = build_ocsp_request(cert.decoded(), issuer, None) else {
                    continue;
                };
                #[cfg(feature = "revocation")]
                for uri in responders {
                    // The same certificate appears on several paths under the same issuer, and each
                    // path names the same responders; asking once is enough.
                    if asked.iter().any(|(k, u)| *k == key && *u == uri) {
                        continue;
                    }
                    asked.push((key.clone(), uri.clone()));
                    out.ocsp.push(OcspRequestItem {
                        uri,
                        request: request.clone(),
                        key: key.clone(),
                    });
                }
            }
        }
    }

    dedup_in_place(&mut out.crl_dp);
    out
}

/// Removes repeats while keeping the order in which each value was first seen, so a caller
/// retrieving these fetches the most immediately relevant first.
fn dedup_in_place(uris: &mut Vec<String>) {
    let mut seen: Vec<String> = Vec::with_capacity(uris.len());
    uris.retain(|uri| {
        if seen.contains(uri) {
            return false;
        }
        seen.push(uri.clone());
        true
    });
}

/// CRLs held in memory for the revocation checker to consult.
///
/// certval ships one [`CrlSource`], `CrlSourceFolders`, and it is a directory of files behind
/// `std`. A browser has neither, so this is the same idea over a vector: the frontend retrieves a
/// CRL and puts it here, and `check_revocation` finds it through the environment.
///
/// **This answers with candidates, not with judgments.** `get_crls` matches on issuer name alone —
/// it deliberately does not check scope, validity or signature, because certval's `process_crl`
/// does all three on everything handed back and tolerates a CRL that turns out not to apply. A
/// superset is therefore correct and a subset is not, which is why the cheap comparison is the
/// right one here.
///
/// Cloning shares the contents: a clone is registered on the environment while the frontend keeps
/// one to add to as retrievals complete, which is what lets CRLs accumulate across a run without
/// the environment being rebuilt.
#[derive(Clone, Default)]
pub struct MemoryCrlSource {
    crls: Arc<RwLock<Vec<StoredCrl>>>,
}

/// A CRL and the issuer name it was published under, decoded once when it is added.
struct StoredCrl {
    /// The CRL as retrieved.
    bytes: Vec<u8>,
    /// DER encoding of the issuer name, compared against a certificate's issuer.
    issuer: x509_cert::name::Name,
}

impl MemoryCrlSource {
    /// Returns an empty source.
    pub fn new() -> Self {
        MemoryCrlSource::default()
    }

    /// Adds a retrieved CRL, returning whether it was a CRL at all. A body that does not decode is
    /// reported rather than stored: a distribution point serving something else is worth a note in
    /// the run, and storing it would only produce a confusing failure later inside `process_crl`.
    pub fn add(&self, bytes: &[u8]) -> bool {
        let Ok(crl) = CertificateList::<Raw>::from_der(bytes) else {
            return false;
        };
        let stored = StoredCrl {
            bytes: bytes.to_vec(),
            issuer: crl.tbs_cert_list.issuer.clone(),
        };
        match self.crls.write() {
            Ok(mut guard) => {
                guard.push(stored);
                true
            }
            Err(_) => false,
        }
    }

    /// Reports how many CRLs are held.
    pub fn len(&self) -> usize {
        self.crls.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Reports whether any CRL is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CrlSource for MemoryCrlSource {
    fn get_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        let guard = self.crls.read().map_err(|_| Error::Unrecognized)?;
        Ok(guard.iter().map(|c| c.bytes.clone()).collect())
    }

    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        let issuer = cert.decoded().tbs_certificate().issuer();
        let guard = self.crls.read().map_err(|_| Error::Unrecognized)?;
        Ok(guard
            .iter()
            .filter(|c| compare_names(&c.issuer, issuer))
            .map(|c| c.bytes.clone())
            .collect())
    }

    fn add_crl(&self, crl_buf: &[u8], _crl: &CertificateList<Raw>, _uri: &str) -> Result<()> {
        match self.add(crl_buf) {
            true => Ok(()),
            false => Err(Error::Unrecognized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_that_is_neither_a_certificate_nor_a_message_yields_nothing() {
        assert!(certificates_in(b"not der at all").is_empty());
        assert!(certificates_in(&[]).is_empty());
    }

    #[test]
    fn dedup_keeps_the_first_occurrence_and_its_position() {
        let mut uris = vec![
            "http://b/".to_string(),
            "http://a/".to_string(),
            "http://b/".to_string(),
        ];
        dedup_in_place(&mut uris);
        assert_eq!(uris, vec!["http://b/".to_string(), "http://a/".to_string()]);
    }

    #[test]
    fn a_body_that_is_not_a_crl_is_refused_rather_than_stored() {
        let source = MemoryCrlSource::new();
        assert!(!source.add(b"this is not a CRL"));
        assert!(source.is_empty());
        assert!(source.get_all_crls().unwrap().is_empty());
    }

    /// A clone shares the contents, which is what lets one be registered on the environment while
    /// the frontend adds to another as retrievals complete.
    #[test]
    fn clones_share_their_contents() {
        let source = MemoryCrlSource::new();
        let registered = source.clone();
        assert_eq!(registered.len(), 0);
        // Nothing valid to add without a real CRL to hand; the shared handle is the claim under
        // test, so assert on the pointer the two hold rather than on contents.
        assert!(Arc::ptr_eq(&source.crls, &registered.crls));
    }
}

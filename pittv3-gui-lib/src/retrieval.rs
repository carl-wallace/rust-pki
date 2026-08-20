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
    PathValidationStatus, Result, SubjectNameAndKey,
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
// Only the CertID comparison is generic over the profile, and that exists only with `revocation`.
#[cfg(feature = "revocation")]
use x509_cert::certificate::Profile;
use x509_cert::crl::CertificateList;
#[cfg(feature = "revocation")]
use x509_ocsp::{BasicOcspResponse, CertId, OcspRequest, OcspResponse, OcspResponseStatus};

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

    // Which kinds of revocation data the run is allowed to go and get. This has to be decided here
    // because it cannot be decided later: what a frontend retrieves is handed to the checker as
    // stapled data, and the stapled step is gated on data being present rather than on any setting
    // -- reasonably, since stapled data is normally something the caller chose to supply. A run that
    // retrieves has not chosen anything, so declining to retrieve is the only way its settings are
    // honored. Harvesting an OCSP request for a run configured against OCSP would put a response on
    // a step ahead of the CRLs, and the run would answer by OCSP after being told not to.
    //
    // Retrieving a CRL takes both settings: `check_crldp_http` is permission to fetch from a
    // distribution point, and `check_crls` is whether the checker consults the source the result is
    // put into -- with the latter off, whatever is fetched is never read.
    let fetch_crls = cps.get_check_crls() && cps.get_check_crldp_http();
    let fetch_ocsp = cps.get_check_ocsp_from_aia();
    if !fetch_crls && !fetch_ocsp {
        return out;
    }
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
                let issuer: &dyn SubjectNameAndKey = match pos {
                    0 => &path.trust_anchor.decoded_ta,
                    _ => chain[pos - 1].as_ref(),
                };
                // Nothing has to be retrieved for a certificate whose status is already settled.
                // This is the same lookup the revocation checker makes as its first step, against
                // the same cache, so a determination an earlier run reached -- from a CRL uploaded
                // with the trust material, from a stapled response, or from a retrieval on a
                // previous click -- is not paid for again. The checker re-checks after every source
                // and stops as soon as one answers; a harvest that runs before anything is known
                // cannot do that, so this restores the part of that guard which is knowable in
                // advance. Undetermined statuses are never cached, so this can only skip work that
                // is genuinely unnecessary, and cached answers expire at the nextUpdate of the data
                // behind them.
                if pe.get_status(cert, issuer, toi)
                    != PathValidationStatus::RevocationStatusNotDetermined
                {
                    continue;
                }

                if fetch_crls {
                    collect_crl_dp_uris(cert, &mut out.crl_dp);
                }

                if !fetch_ocsp {
                    continue;
                }
                let mut responders = vec![];
                collect_ocsp_uris(cert, &mut responders);
                if responders.is_empty() {
                    continue;
                }
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

/// Adds a CRL the user supplied by hand, accepting either DER or PEM.
///
/// This is the no-network counterpart to retrieving one: the checker cannot tell the difference,
/// because both end up in the same [`MemoryCrlSource`] and are judged the same way by certval's
/// `process_crl`. Returns whether it was a CRL at all — a file that is not one is reported rather
/// than stored, for the same reason [`MemoryCrlSource::add`] reports it.
pub fn add_uploaded_crl(prepared: &PreparedValidation, bytes: &[u8]) -> bool {
    if prepared.crl_source().add(bytes) {
        return true;
    }
    // PEM is worth a second try rather than a separate button: a CRL saved out of another tool is
    // as likely to be armored as not, and the user should not have to know which they have.
    match pem_rfc7468::decode_vec(bytes) {
        Ok((_label, der)) => prepared.crl_source().add(&der),
        Err(_) => false,
    }
}

/// What offering an uploaded OCSP response to a run came to.
#[derive(Clone, Debug, Default)]
pub struct OcspStapleOutcome {
    /// How many (certificate, issuer) pairs on the paths this run builds the response answers for.
    pub matched: usize,
    /// What happened, in terms a user can act on.
    pub notes: Vec<String>,
}

/// Reads the `CertID`s an OCSP response answers about, or says why it answers about none.
///
/// Split out from [`staple_uploaded_ocsp`] because it is the half that depends only on the bytes:
/// everything it can reject, it rejects without a prepared environment or a path in sight.
#[cfg(feature = "revocation")]
fn answered_cert_ids(bytes: &[u8]) -> core::result::Result<Vec<CertId>, String> {
    let response = OcspResponse::from_der(bytes).map_err(|_| "Not an OCSP response".to_string())?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(format!(
            "OCSP response reports {:?} rather than an answer",
            response.response_status
        ));
    }
    let rb = response
        .response_bytes
        .as_ref()
        .ok_or_else(|| "OCSP response carries no response bytes".to_string())?;
    let basic = BasicOcspResponse::from_der(rb.response.as_bytes())
        .map_err(|_| "OCSP response body could not be read".to_string())?;
    let ids: Vec<CertId> = basic
        .tbs_response_data
        .responses
        .iter()
        .map(|single| single.cert_id.clone())
        .collect();
    match ids.is_empty() {
        true => Err("OCSP response answers about no certificate".to_string()),
        false => Ok(ids),
    }
}

/// Files an OCSP response the user supplied by hand against whichever certificates it answers
/// about, so a no-network run can determine revocation status from it.
///
/// **The response says what it is about, so the user does not have to.** An OCSP `CertID` names the
/// hash of the issuer's name and public key together with the certificate's serial number, which is
/// exactly the identity [`OcspKey`] is built on. So rather than asking which certificate a file
/// concerns, this walks the (certificate, issuer) pairs on the paths the environment builds, asks
/// certval to build the request it *would* have sent for each, and files the response against every
/// pair whose `CertID` the response answers. One response can match more than one pair, and a
/// response matching none is reported rather than stored.
///
/// Building the request rather than re-hashing the issuer here is deliberate: it makes the match
/// certval's own notion of identity by construction, and the hash helpers are private to certval
/// anyway. It also means the comparison inherits certval's SHA-1 `CertID`, so a response built with
/// a different hash algorithm cannot be matched this way — which is reported, not swallowed.
#[cfg(feature = "revocation")]
pub fn staple_uploaded_ocsp(
    prepared: &PreparedValidation,
    cps: &CertificationPathSettings,
    ees: &[(String, Vec<u8>)],
    bytes: &[u8],
) -> OcspStapleOutcome {
    let mut out = OcspStapleOutcome::default();

    let answered = match answered_cert_ids(bytes) {
        Ok(ids) => ids,
        Err(note) => {
            out.notes.push(note);
            return out;
        }
    };

    let pe = prepared.environment();
    let toi = cps.get_time_of_interest();
    let sink = prepared.ocsp_responses();
    // A certificate sits on more than one path, and under the same issuer each time; file once.
    let mut filed: Vec<OcspKey> = vec![];
    // Counted so a miss can say what was looked at. "Examined none" and "examined nine and none
    // matched" are different problems -- the first is a path that did not build, the second a
    // response about something else -- and a note that cannot tell them apart sends the reader to
    // the wrong place.
    let mut examined = 0usize;
    let mut unaskable = 0usize;

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
            let chain: Vec<&PDVCertificate> = path
                .intermediates
                .iter()
                .chain(core::iter::once(&path.target))
                .collect();
            for (pos, cert) in chain.iter().enumerate() {
                let issuer: &dyn SubjectNameAndKey = match pos {
                    0 => &path.trust_anchor.decoded_ta,
                    _ => chain[pos - 1].as_ref(),
                };
                let Some(key) = OcspKey::new(cert, issuer) else {
                    continue;
                };
                if filed.contains(&key) {
                    continue;
                }
                // Decoded under the `Raw` profile because that is the profile certval encoded it
                // with: `build_ocsp_request` takes the serial straight off a `CertificateInner<Raw>`,
                // and `SerialNumber<Rfc5280>` enforces a length constraint `Raw` does not. Reading
                // it back as Rfc5280 would therefore fail for a certificate whose serial is longer
                // than the RFC permits -- and, because the failure was a `continue`, would drop that
                // certificate from consideration without a word. Round-tripping under the profile it
                // was written with cannot fail that way.
                let Ok(request) = build_ocsp_request(cert.decoded(), issuer, None) else {
                    unaskable += 1;
                    continue;
                };
                let Ok(request) = OcspRequest::<Raw>::from_der(&request) else {
                    unaskable += 1;
                    continue;
                };
                let Some(asked) = request.tbs_request.request_list.first() else {
                    unaskable += 1;
                    continue;
                };
                examined += 1;
                if !answered.iter().any(|id| same_cert_id(id, &asked.req_cert)) {
                    continue;
                }
                sink.insert(key.clone(), bytes.to_vec());
                filed.push(key);
                out.matched += 1;
            }
        }
    }

    if out.matched == 0 {
        // Say what the response is about and what was asked, so a mismatch identifies itself. The
        // serial is the discriminating field -- two CertIDs over the same issuer differ only there
        // -- and the hash OID is named because certval asks with SHA-1 and a response built with a
        // different one cannot match however right it otherwise is.
        let about = answered
            .iter()
            .map(|id| hex(id.serial_number.as_bytes()))
            .collect::<Vec<String>>()
            .join(", ");
        let algs = answered
            .iter()
            .map(|id| id.hash_algorithm.oid.to_string())
            .collect::<Vec<String>>();
        let non_sha1 = algs.iter().any(|oid| oid != SHA1_OID);
        let mut note = format!(
            "OCSP response answers about serial(s) {about}; examined {examined} certificate(s) on \
             the paths built for the loaded certificates and none is that certificate."
        );
        if examined == 0 {
            note.push_str(
                " No certificate was examined at all, so no path was built -- check the trust \
                 anchor and intermediates before the response.",
            );
        }
        if non_sha1 {
            note.push_str(&format!(
                " The response uses CertID hash {}, while the comparison is made with SHA-1 \
                 ({SHA1_OID}), so it cannot be matched this way.",
                algs.join(", ")
            ));
        }
        if unaskable > 0 {
            note.push_str(&format!(
                " {unaskable} certificate(s) could not have a request built for them and were not \
                 compared."
            ));
        }
        out.notes.push(note);
    }
    out
}

/// The OID certval builds a `CertID` with, named so a miss can report a response that used another.
#[cfg(feature = "revocation")]
const SHA1_OID: &str = "1.3.14.3.2.26";

/// Lowercase hex, for naming a serial in a note.
#[cfg(feature = "revocation")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Compares two `CertID`s on the four things that identify a certificate to a responder.
///
/// The hash algorithm is compared **by OID alone**, deliberately. An `AlgorithmIdentifier` carries
/// optional parameters, and absent-versus-NULL is a split real implementations sit on both sides
/// of; a derived equality would therefore reject a response that answers exactly the question that
/// was asked. The three values that follow are what actually identify the certificate.
///
/// Generic over the two profiles because the two sides arrive under different ones: the response is
/// read as `Rfc5280`, the request certval built is read back as `Raw`. The comparison is on the
/// encoded values, which are profile-independent, so this is a widening rather than a loosening.
#[cfg(feature = "revocation")]
fn same_cert_id<A: Profile, B: Profile>(a: &CertId<A>, b: &CertId<B>) -> bool {
    a.hash_algorithm.oid == b.hash_algorithm.oid
        && a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number.as_bytes() == b.serial_number.as_bytes()
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

    #[test]
    fn an_uploaded_file_that_is_not_a_crl_is_refused_in_either_encoding() {
        // Exercises both arms of add_uploaded_crl's DER-then-PEM attempt without needing a
        // prepared environment: neither encoding yields a CRL, so neither stores one.
        let source = MemoryCrlSource::new();
        assert!(!source.add(b"neither DER nor PEM"));
        assert!(!source.add(b"-----BEGIN X509 CRL-----\nbm90IGEgY3Js\n-----END X509 CRL-----\n"));
        assert!(source.is_empty());
    }

    #[cfg(feature = "revocation")]
    #[test]
    fn a_file_that_is_not_an_ocsp_response_is_named_as_such() {
        assert_eq!(
            answered_cert_ids(b"not an ocsp response"),
            Err("Not an OCSP response".to_string())
        );
        assert_eq!(
            answered_cert_ids(&[]),
            Err("Not an OCSP response".to_string())
        );
    }

    /// An unsuccessful response is a different thing from an unreadable one, and the difference is
    /// what a user needs: the file is fine, the responder declined to answer.
    #[cfg(feature = "revocation")]
    #[test]
    fn a_response_reporting_failure_is_distinguished_from_an_unreadable_one() {
        // OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus } with status
        // malformedRequest(1) and no responseBytes -- the shortest well-formed refusal.
        let refusal = [0x30u8, 0x03, 0x0A, 0x01, 0x01];
        let err = answered_cert_ids(&refusal).unwrap_err();
        assert!(
            err.contains("rather than an answer"),
            "unexpected note: {err}"
        );
    }

    /// The end-to-end claim: a real OCSP response, handed over as a file, is matched to the
    /// certificate it answers about and filed where the validation path will find it.
    ///
    /// Uses certval's own amazon.com capture — the same fixtures its `stapled_ocsp` test uses, and
    /// the same `<n>-ocsp.ocspResp` naming `pitt_log` writes when a run exports what it consulted,
    /// so this is the export-then-reload round trip the upload buttons exist for.
    ///
    /// The **intermediate** is the target here, deliberately, and not for convenience:
    /// `1-ocsp.ocspResp` is the response *about* the intermediate (its CertID serial is the
    /// intermediate's), so this asks the question the fixture can answer. It also sidesteps a
    /// separate finding — with uploads and no baked store, a path builds to an uploaded
    /// intermediate but not to an end entity beneath it — which would otherwise make this test red
    /// for a reason that has nothing to do with matching a response.
    #[cfg(feature = "revocation")]
    #[test]
    fn a_real_ocsp_response_is_matched_to_the_certificate_it_answers_about() {
        use crate::validate::prepare_validation;
        use certval::TimeOfInterest;

        let ta = include_bytes!("../../certval/tests/examples/amazon.com/0-ta.der").to_vec();
        let ca = include_bytes!("../../certval/tests/examples/amazon.com/1.der").to_vec();
        let ca_ocsp =
            include_bytes!("../../certval/tests/examples/amazon.com/1-ocsp.ocspResp").to_vec();

        let mut cps = CertificationPathSettings::default();
        // Inside the captured chain's validity window; the capture is from 2021-2022.
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1640995200).unwrap());

        let (prepared, _notes) =
            prepare_validation(None, &[("0-ta.der".to_string(), ta)], &[], &cps, None)
                .expect("the amazon.com trust anchor should prepare an environment");

        let targets = vec![("1.der".to_string(), ca)];
        let outcome = staple_uploaded_ocsp(&prepared, &cps, &targets, &ca_ocsp);

        assert!(
            outcome.matched > 0,
            "the intermediate's own OCSP response matched nothing; notes: {:?}",
            outcome.notes
        );
        assert!(
            !prepared.ocsp_responses().is_empty(),
            "matched but nothing was filed for the validation path to find"
        );
    }

    /// A response that is genuinely about something else is refused rather than filed, which is the
    /// property that makes matching worth doing at all — otherwise stapling everything everywhere
    /// would do just as well.
    #[cfg(feature = "revocation")]
    #[test]
    fn an_ocsp_response_about_a_different_pki_matches_nothing() {
        use crate::validate::prepare_validation;
        use certval::TimeOfInterest;

        let ta = include_bytes!("../../certval/tests/examples/amazon.com/0-ta.der").to_vec();
        let ca = include_bytes!("../../certval/tests/examples/amazon.com/1.der").to_vec();
        // A response from an unrelated capture: right shape, wrong certificates.
        let foreign =
            include_bytes!("../../certval/tests/examples/harvard.edu/1-ocsp.ocspResp").to_vec();

        let mut cps = CertificationPathSettings::default();
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1640995200).unwrap());

        let (prepared, _notes) =
            prepare_validation(None, &[("0-ta.der".to_string(), ta)], &[], &cps, None)
                .expect("the amazon.com trust anchor should prepare an environment");

        let targets = vec![("1.der".to_string(), ca)];
        let outcome = staple_uploaded_ocsp(&prepared, &cps, &targets, &foreign);

        assert_eq!(outcome.matched, 0);
        assert!(prepared.ocsp_responses().is_empty());
        // The note must identify the response rather than merely report failure: the serial it
        // answers about is what tells the reader it is the wrong file, and the count tells them a
        // path was built and searched rather than nothing having been looked at.
        let note = outcome.notes.first().expect("a miss must be explained");
        assert!(
            note.contains("137D539CAA7C31A9A433701968847A8D"),
            "the note should name the serial the response answers about; got {note}"
        );
        assert!(
            note.contains("examined 1 certificate(s)"),
            "the note should say how many candidates were compared; got {note}"
        );
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

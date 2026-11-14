//! Candidate target certificates for path building, including alternate certificates per
//! draft-davidben-lamps-turducken-certs-00 when the `turducken` feature is enabled.
//!
//! An outer certificate carries each alternate certificate as an AlternateIssuerInfo in its embedded
//! SCT extension. Each alternate certifies the same subject and key via a different issuer, so the
//! relying party rebuilds each one (Section 5.1) and builds paths for it as another target. Which
//! candidate yields a valid path is decided by the trust anchors in use; nothing here prefers one.
//!
//! [`get_paths_for_candidates`] is the one place path building for an input target happens, and
//! [`chase_candidates`] the one place the certificates whose AIA and SIA are followed are chosen, so
//! the command line, desktop and browser frontends treat candidates identically. Without the
//! `turducken` feature, the only candidate is the input certificate itself.

use alloc::{string::String, vec::Vec};

use certval::{
    CertificationPath, CertificationPathSettings, PDVCertificate, PkiEnvironment, Result,
    TimeOfInterest,
};

/// Builds paths for `target` and, when the `turducken` feature is enabled, for each alternate
/// certificate it carries, appending all of them to `paths`. Returns the candidates, which name the
/// candidate each path was built from, and notes describing alternates that were found, ignored or
/// could not be rebuilt.
///
/// The result is `Ok` when any candidate yielded a path. Otherwise it is the first error that
/// rejected a candidate during path building (a [`certval::Error::PathValidation`]), so the reason
/// a candidate was rejected is not lost to another candidate having no issuer in the environment,
/// and failing that, the outer certificate's result.
pub fn get_paths_for_candidates(
    pe: &PkiEnvironment,
    target: &PDVCertificate,
    paths: &mut Vec<CertificationPath>,
    threshold: usize,
    time_of_interest: TimeOfInterest,
) -> (Result<()>, Candidates, Vec<String>) {
    let outer = pe.get_paths_for_target(target, paths, threshold, time_of_interest);

    #[cfg(feature = "turducken")]
    {
        use alloc::format;
        use certval::Error;
        let (alternates, mut notes) = turducken::alternates(target.as_bytes());
        let mut rejection = match outer {
            Err(e @ Error::PathValidation(_)) => Some(e),
            _ => None,
        };
        let mut kept = Vec::with_capacity(alternates.len());
        for alternate in alternates {
            // Located where the input was, so output keyed by the target's location (e.g., a
            // results folder) stays with the input rather than with the alternate's label, which
            // alternates from the same issuer share
            let locator = target.locator().unwrap_or(&alternate.label);
            let cert = match certval::parse_cert(&alternate.der, locator) {
                Ok(cert) => cert,
                Err(e) => {
                    notes.push(format!(
                        "Ignoring {}: it did not parse ({e:?})",
                        alternate.label
                    ));
                    continue;
                }
            };
            let before = paths.len();
            match pe.get_paths_for_target(&cert, paths, threshold, time_of_interest) {
                Ok(()) => notes.push(format!(
                    "{}: {} path(s) found",
                    alternate.label,
                    paths.len() - before
                )),
                Err(e @ Error::PathValidation(_)) => {
                    notes.push(format!(
                        "{}: rejected during path building ({e:?})",
                        alternate.label
                    ));
                    rejection.get_or_insert(e);
                }
                Err(_) => notes.push(format!("{}: no paths found", alternate.label)),
            }
            kept.push(alternate);
        }
        let result = match (paths.is_empty(), rejection) {
            (false, _) => Ok(()),
            (true, Some(e)) => Err(e),
            (true, None) => outer,
        };
        (result, Candidates { alternates: kept }, notes)
    }

    #[cfg(not(feature = "turducken"))]
    (outer, Candidates::default(), Vec::new())
}

/// The candidate targets expanded from one input certificate.
#[derive(Clone, Debug, Default)]
pub struct Candidates {
    #[cfg(feature = "turducken")]
    alternates: Vec<turducken::Alternate>,
}

impl Candidates {
    /// Names the candidate `path` was built from, or `None` when it was built from the input
    /// certificate itself.
    pub fn label_for(&self, path: &CertificationPath) -> Option<String> {
        #[cfg(feature = "turducken")]
        {
            let target = path.target.as_bytes();
            self.alternates
                .iter()
                .find(|a| a.der.as_slice() == target)
                .map(|a| a.label.clone())
        }
        #[cfg(not(feature = "turducken"))]
        {
            let _ = path;
            None
        }
    }
}

/// Returns the certificates whose AIA and SIA URIs are worth following to find issuers for `target`:
/// the target itself and, when the `turducken` feature is enabled, each alternate certificate it
/// carries, leaving out any of these whose own signature algorithm `cps` does not permit. A path for
/// such a candidate would fail validation however its issuers were found, so fetching them is wasted
/// effort, e.g., following a classical outer certificate's AIA when only post-quantum signatures are
/// permitted. A target that carries no alternates is returned as it is, whatever its signature
/// algorithm, so chasing for it is unchanged. Alternates are located where the target is, as for
/// [`get_paths_for_candidates`].
pub fn chase_candidates(
    cps: &CertificationPathSettings,
    target: &PDVCertificate,
) -> Vec<PDVCertificate> {
    #[cfg(feature = "turducken")]
    {
        let (alternates, _) = turducken::alternates(target.as_bytes());
        if alternates.is_empty() {
            return alloc::vec![target.clone()];
        }
        let permitted = cps
            .get_permitted_signature_algorithms_as_oid_set()
            .filter(|p| !p.is_empty());
        let allowed =
            |alg: &const_oid::ObjectIdentifier| permitted.as_ref().is_none_or(|p| p.contains(alg));
        let mut candidates = Vec::with_capacity(alternates.len() + 1);
        if allowed(&target.decoded().signature_algorithm().oid) {
            candidates.push(target.clone());
        }
        for alternate in alternates {
            if !allowed(&alternate.signature_algorithm) {
                continue;
            }
            let locator = target.locator().unwrap_or(&alternate.label);
            if let Ok(cert) = certval::parse_cert(&alternate.der, locator) {
                candidates.push(cert);
            }
        }
        candidates
    }
    #[cfg(not(feature = "turducken"))]
    {
        let _ = cps;
        alloc::vec![target.clone()]
    }
}

/// Returns `ders` with the certificates each one includes by reference (byInclusion) following it,
/// for a caller taking in CA certificates. A CA certificate's referenced certificate is another CA
/// certificate, so it joins the pool paths are built through, as the members of a certs-only PKCS
/// #7 message do. Included certificates are not expanded in turn, and duplicates are dropped.
/// Without the `certdiscovery` feature, `ders` is returned unchanged.
pub fn fold_referenced(ders: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    #[cfg(feature = "certdiscovery")]
    {
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(ders.len());
        for der in ders {
            let included = certdiscovery::included(&der);
            if !out.contains(&der) {
                out.push(der);
            }
            for inc in included {
                if !out.contains(&inc) {
                    out.push(inc);
                }
            }
        }
        out
    }
    #[cfg(not(feature = "certdiscovery"))]
    ders
}

/// Returns the certificates an end entity certificate in `der` includes by reference (byInclusion).
/// Each certifies another key, so a frontend validates each as a target of its own, as Section 6 of
/// draft-ietf-lamps-certdiscovery-06 has a referenced certificate validated, rather than as a
/// candidate for `der`: an end entity input that includes another is taken as the members of a
/// certs-only PKCS #7 message of end entities would be. Empty for a CA certificate, whose included certificates are CA certificates
/// ([`fold_referenced`]), and without the `certdiscovery` feature.
pub fn included_referenced(der: &[u8]) -> Vec<Vec<u8>> {
    #[cfg(feature = "certdiscovery")]
    {
        if certdiscovery::is_ca(der) {
            return Vec::new();
        }
        certdiscovery::included(der)
    }
    #[cfg(not(feature = "certdiscovery"))]
    {
        let _ = der;
        Vec::new()
    }
}

/// Returns the URIs of the referenced certificates the certificate in `der` names by URI (byUri),
/// when it is a CA certificate and `ca` is set or an end entity certificate and `ca` is not, leaving
/// out any whose descriptor names a signature algorithm `cps` does not permit (Section 3.2 of
/// draft-ietf-lamps-certdiscovery-06).
///
/// A CA's referenced certificates are retrieved as its issuers are and join the CA certificates.
/// An end entity's certify another key, so what one means for the end entity that named it is for
/// the application to decide; Section 6 has a retrieved one validated as if it had been provided as
/// the target, which is how a frontend that retrieves one treats it.
/// Empty without the `certdiscovery` feature.
pub fn referenced_uris(
    cps: Option<&CertificationPathSettings>,
    der: &[u8],
    ca: bool,
) -> Vec<String> {
    #[cfg(feature = "certdiscovery")]
    {
        if certdiscovery::is_ca(der) != ca {
            return Vec::new();
        }
        certdiscovery::descriptors(der)
            .into_iter()
            .filter(|d| match (cps, &d.signature_algorithm) {
                (Some(cps), Some(alg)) => cps
                    .get_permitted_signature_algorithms_as_oid_set()
                    .filter(|p| !p.is_empty())
                    .is_none_or(|p| p.contains(&alg.oid)),
                _ => true,
            })
            .filter_map(|d| d.uri().map(String::from))
            .collect()
    }
    #[cfg(not(feature = "certdiscovery"))]
    {
        let _ = (cps, der, ca);
        Vec::new()
    }
}

/// Checks a certificate retrieved from `uri` against the byUri descriptors naming `uri` among the
/// certificates in `pool`, as Section 3.1.1 of draft-ietf-lamps-certdiscovery-06 requires: a
/// signature algorithm, public key algorithm or certificate hash that does not match means the
/// retrieval failed. `Ok` when nothing in `pool` names `uri` this way, or without the
/// `certdiscovery` feature.
pub fn accept_referenced(
    pool: &[(String, Vec<u8>)],
    uri: &str,
    der: &[u8],
) -> core::result::Result<(), String> {
    #[cfg(feature = "certdiscovery")]
    for (_, bytes) in pool {
        for d in certdiscovery::descriptors(bytes) {
            if d.uri() == Some(uri) {
                d.check(der)?;
            }
        }
    }
    #[cfg(not(feature = "certdiscovery"))]
    let _ = (pool, uri, der);
    Ok(())
}

#[cfg(feature = "turducken")]
pub mod turducken {
    //! Rebuilds alternate certificates from an outer certificate per Sections 5, 5.1 and 5.2 of
    //! draft-davidben-lamps-turducken-certs-00.

    use alloc::{format, string::String, vec, vec::Vec};

    use const_oid::{
        db::{rfc5280, rfc6962::CT_PRECERT_SCTS, DB},
        ObjectIdentifier,
    };
    use der::{
        asn1::{BitString, OctetString},
        Decode, Encode, Sequence,
    };
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::{
        certificate::Raw, ext::Extension, name::Name, serial_number::SerialNumber, time::Validity,
        Version,
    };

    /// Placeholder for TBD3, the `alternate_issuer_info` VersionedTransType: the first value in
    /// the Experimental Use range of the RFC 9162 VersionedTransTypes registry.
    pub const ALTERNATE_ISSUER_INFO_TYPE: u16 = 0xE000;

    /// Placeholder for TBD2, id-pe-outerCertificateBinding.
    pub const ID_PE_OUTER_CERTIFICATE_BINDING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.99");

    /// The most alternates processed for one outer certificate (Section 5 asks for a limit, since
    /// an unverified outer certificate can carry arbitrarily many).
    pub const MAX_ALTERNATES: usize = 8;

    /// id-CABFOrganizationIdentifier
    const ID_CABF_ORGANIZATION_IDENTIFIER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.23.140.3.1");

    /// Extensions Section 4.1 forbids among issuer-specific extensions, rejected per Section 5.2.
    const FORBIDDEN_ISSUER_EXTENSIONS: [ObjectIdentifier; 9] = [
        rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        rfc5280::ID_CE_KEY_USAGE,
        rfc5280::ID_CE_SUBJECT_ALT_NAME,
        rfc5280::ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES,
        rfc5280::ID_CE_BASIC_CONSTRAINTS,
        rfc5280::ID_CE_NAME_CONSTRAINTS,
        rfc5280::ID_CE_EXT_KEY_USAGE,
        rfc5280::ID_PE_SUBJECT_INFO_ACCESS,
        ID_CABF_ORGANIZATION_IDENTIFIER,
    ];

    /// ```text
    /// AlternateIssuerInfo ::= SEQUENCE {
    ///     serialNumber         CertificateSerialNumber,
    ///     signatureAlgorithm   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
    ///                              {SignatureAlgorithms}},
    ///     issuer               Name,
    ///     commonExtensionCount INTEGER (0..MAX),
    ///     issuerExtensions     SEQUENCE OF Extension{{CertExtensions}},
    ///     signatureValue       BIT STRING
    /// }
    /// ```
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    #[allow(missing_docs)]
    pub struct AlternateIssuerInfo {
        pub serial_number: SerialNumber<Raw>,
        pub signature_algorithm: AlgorithmIdentifierOwned,
        pub issuer: Name,
        pub common_extension_count: u32,
        pub issuer_extensions: Vec<Extension>,
        pub signature_value: BitString,
    }

    /// ```text
    /// OuterCertificateBinding ::= SEQUENCE {
    ///     serialNumber         CertificateSerialNumber,
    ///     signatureAlgorithm   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
    ///                             {SignatureAlgorithms}},
    ///     issuer               Name,
    ///     commonExtensionCount INTEGER (0..MAX),
    ///     issuerExtensions     SEQUENCE OF Extension{{CertExtensions}}
    /// }
    /// ```
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    #[allow(missing_docs)]
    pub struct OuterCertificateBinding {
        pub serial_number: SerialNumber<Raw>,
        pub signature_algorithm: AlgorithmIdentifierOwned,
        pub issuer: Name,
        pub common_extension_count: u32,
        pub issuer_extensions: Vec<Extension>,
    }

    /// TBSCertificate with fields that can be replaced, which x509-cert's type does not allow.
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct Tbs {
        #[asn1(context_specific = "0", default = "Default::default")]
        version: Version,
        serial_number: SerialNumber<Raw>,
        signature: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity<Raw>,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfoOwned,
        #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
        issuer_unique_id: Option<BitString>,
        #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
        subject_unique_id: Option<BitString>,
        #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
        extensions: Option<Vec<Extension>>,
    }

    /// Certificate with fields that can be replaced, which x509-cert's type does not allow.
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct Cert {
        tbs_certificate: Tbs,
        signature_algorithm: AlgorithmIdentifierOwned,
        signature: BitString,
    }

    /// An alternate certificate rebuilt from an outer certificate.
    #[derive(Clone, Debug)]
    pub struct Alternate {
        /// Describes the alternate for display, e.g., `alternate 1 (ML-DSA-65 from CN=...)`
        pub label: String,
        /// DER encoding of the rebuilt certificate
        pub der: Vec<u8>,
        /// The rebuilt certificate's signature algorithm
        pub signature_algorithm: ObjectIdentifier,
    }

    /// Returns whether `oid` identifies a post-quantum or composite public key algorithm: ML-DSA,
    /// SLH-DSA and their pre-hash forms (2.16.840.1.101.3.4.3.17-46), ML-KEM
    /// (2.16.840.1.101.3.4.4.1-3) or a composite (1.3.6.1.5.5.7.6.37 and above).
    fn is_post_quantum(oid: &ObjectIdentifier) -> bool {
        const NIST_SIGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3");
        const NIST_KEMS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4");
        const COMPOSITES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6");
        let (Some(parent), Some(last)) = (oid.parent(), oid.arcs().last()) else {
            return false;
        };
        (parent == NIST_SIGS && (17..=46).contains(&last))
            || (parent == NIST_KEMS && (1..=3).contains(&last))
            || (parent == COMPOSITES && last >= 37)
    }

    /// Reads the AlternateIssuerInfos from the contents of an embedded SCT extension, whose
    /// extnValue holds a DER-encoded OCTET STRING containing a TLS-encoded
    /// SignedCertificateTimestampList. Entries of other types, such as v1 SCTs, are skipped.
    fn read_alternate_issuer_infos(
        extn_value: &[u8],
        notes: &mut Vec<String>,
    ) -> Vec<AlternateIssuerInfo> {
        let mut infos = vec![];
        let list = match OctetString::from_der(extn_value) {
            Ok(os) => os.into_bytes(),
            Err(e) => {
                notes.push(format!("Ignoring the embedded SCT extension: {e:?}"));
                return infos;
            }
        };
        let Some((sct_list, rest)) = split_u16_prefixed(&list) else {
            notes.push("Ignoring the embedded SCT extension: malformed list".into());
            return infos;
        };
        if !rest.is_empty() {
            notes.push("Ignoring the embedded SCT extension: trailing data".into());
            return infos;
        }
        let mut remaining = sct_list;
        while !remaining.is_empty() {
            let Some((item, rest)) = split_u16_prefixed(remaining) else {
                notes.push("Ignoring the rest of the embedded SCT list: malformed entry".into());
                break;
            };
            remaining = rest;
            // A v1 SCT starts with its one-byte version, 0, which no VersionedTransType starts with
            if item.len() < 2
                || u16::from_be_bytes([item[0], item[1]]) != ALTERNATE_ISSUER_INFO_TYPE
            {
                continue;
            }
            let contents = match split_u16_prefixed(&item[2..]) {
                Some((contents, [])) => contents,
                _ => {
                    notes.push("Ignoring a malformed alternate_issuer_info entry".into());
                    continue;
                }
            };
            match AlternateIssuerInfo::from_der(contents) {
                Ok(info) => infos.push(info),
                Err(e) => notes.push(format!("Ignoring an AlternateIssuerInfo: {e:?}")),
            }
        }
        infos
    }

    /// Splits a value with a two-byte big-endian length prefix from what follows it.
    fn split_u16_prefixed(buf: &[u8]) -> Option<(&[u8], &[u8])> {
        let len = usize::from(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]));
        let body = buf.get(2..2 + len)?;
        Some((body, &buf[2 + len..]))
    }

    /// Returns the first extension in `exts` that Section 4.1 forbids as issuer-specific.
    fn forbidden(exts: &[Extension]) -> Option<ObjectIdentifier> {
        exts.iter()
            .map(|e| e.extn_id)
            .find(|id| FORBIDDEN_ISSUER_EXTENSIONS.contains(id))
    }

    /// Names `oid` for display, falling back to its dotted form.
    fn name_of(oid: &ObjectIdentifier) -> String {
        DB.by_oid(oid)
            .map(String::from)
            .unwrap_or_else(|| oid.to_string())
    }

    /// Rebuilds the alternate certificates carried by the outer certificate in `outer_der`, along
    /// with notes describing alternates that were ignored or could not be rebuilt. A certificate
    /// whose final extension is not an embedded SCT extension carries none, and yields no notes.
    pub fn alternates(outer_der: &[u8]) -> (Vec<Alternate>, Vec<String>) {
        let mut notes = vec![];
        let Ok(outer) = Cert::from_der(outer_der) else {
            return (vec![], notes);
        };
        let exts = outer
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default();
        let Some(last) = exts.last().filter(|e| e.extn_id == CT_PRECERT_SCTS) else {
            return (vec![], notes);
        };
        let mut infos = read_alternate_issuer_infos(last.extn_value.as_bytes(), &mut notes);
        if infos.is_empty() {
            return (vec![], notes);
        }

        // Section 6.1: a post-quantum end-entity key has no need of this mechanism
        let key_alg = outer.tbs_certificate.subject_public_key_info.algorithm.oid;
        if is_post_quantum(&key_alg) {
            notes.push(format!(
                "Ignoring {} alternate(s): the subject key ({}) is post-quantum",
                infos.len(),
                name_of(&key_alg)
            ));
            return (vec![], notes);
        }
        if infos.len() > MAX_ALTERNATES {
            notes.push(format!(
                "Processing the first {MAX_ALTERNATES} of {} alternates",
                infos.len()
            ));
            infos.truncate(MAX_ALTERNATES);
        }

        // Section 5.1 step 1, apart from the extension count, which depends on each alternate
        let tbs = &outer.tbs_certificate;
        let reason = if tbs.version != Version::V3 {
            Some("the outer certificate is not v3")
        } else if outer.signature_algorithm != tbs.signature {
            Some("the outer certificate's two signature algorithm fields differ")
        } else if tbs.issuer_unique_id.is_some() || tbs.subject_unique_id.is_some() {
            Some("the outer certificate has a unique identifier")
        } else {
            None
        };
        if let Some(reason) = reason {
            notes.push(format!("Ignoring {} alternate(s): {reason}", infos.len()));
            return (vec![], notes);
        }

        let mut alternates = vec![];
        for (i, info) in infos.into_iter().enumerate() {
            let label = format!(
                "alternate {} ({} from {})",
                i + 1,
                name_of(&info.signature_algorithm.oid),
                info.issuer
            );
            let signature_algorithm = info.signature_algorithm.oid;
            match rebuild(&outer, info) {
                Ok(der) => alternates.push(Alternate {
                    label,
                    der,
                    signature_algorithm,
                }),
                Err(reason) => notes.push(format!("Could not rebuild {label}: {reason}")),
            }
        }
        (alternates, notes)
    }

    /// Section 5.1 steps 2 through 11 for one AlternateIssuerInfo.
    fn rebuild(outer: &Cert, info: AlternateIssuerInfo) -> Result<Vec<u8>, String> {
        let outer_exts = outer
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default();
        let common = usize::try_from(info.common_extension_count).map_err(|e| format!("{e}"))?;
        if outer_exts.len() < common + 1 {
            return Err(format!(
                "commonExtensionCount ({common}) leaves no room for the final extension among {} extensions",
                outer_exts.len()
            ));
        }
        // steps 6 and 7
        let outer_issuer_extensions = &outer_exts[common..outer_exts.len() - 1];
        // step 8
        if let Some(id) = forbidden(outer_issuer_extensions) {
            return Err(format!(
                "the outer certificate's issuer-specific extensions include {}",
                name_of(&id)
            ));
        }
        if let Some(id) = forbidden(&info.issuer_extensions) {
            return Err(format!("issuerExtensions includes {}", name_of(&id)));
        }

        // steps 2 through 5
        let mut tbs = outer.tbs_certificate.clone();
        let outer_serial_number = core::mem::replace(&mut tbs.serial_number, info.serial_number);
        let outer_signature_algorithm =
            core::mem::replace(&mut tbs.signature, info.signature_algorithm.clone());
        let outer_issuer = core::mem::replace(&mut tbs.issuer, info.issuer);

        // steps 9 and 10
        let binding = OuterCertificateBinding {
            serial_number: outer_serial_number,
            signature_algorithm: outer_signature_algorithm,
            issuer: outer_issuer,
            common_extension_count: info.common_extension_count,
            issuer_extensions: outer_issuer_extensions.to_vec(),
        };
        let binding_der = binding.to_der().map_err(|e| format!("{e:?}"))?;
        let mut extensions = outer_exts[..common].to_vec();
        extensions.extend(info.issuer_extensions);
        extensions.push(Extension {
            extn_id: ID_PE_OUTER_CERTIFICATE_BINDING,
            critical: false,
            extn_value: OctetString::new(binding_der).map_err(|e| format!("{e:?}"))?,
        });
        tbs.extensions = Some(extensions);

        // step 11
        Cert {
            tbs_certificate: tbs,
            signature_algorithm: info.signature_algorithm,
            signature: info.signature_value,
        }
        .to_der()
        .map_err(|e| format!("{e:?}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::candidates::chase_candidates;
        use certval::{collect_uris_from_aia_and_sia, parse_cert, CertificationPathSettings};
        use const_oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_PE_AUTHORITY_INFO_ACCESS};
        use der::asn1::Ia5String;
        use x509_cert::ext::pkix::{
            name::GeneralName, AccessDescription, AuthorityInfoAccessSyntax,
        };

        /// A PKITS outer certificate, re-signed by the RSA CA, carrying an ML-DSA-65 alternate
        const OUTER: &[u8] = include_bytes!(
            "../../pittv3-gui-lib/tests/examples/turducken/ValidCertificatePathTest1EE.der"
        );
        /// The same PKITS certificate as issued, which carries no alternates
        const ORDINARY: &[u8] =
            include_bytes!("../../certval/tests/examples/ValidCertificatePathTest1EE.crt");
        const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
        const ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
        const CA_ISSUERS: &str = "http://example.test/alternate-ca.p7c";

        fn settings(permitted: &[&str]) -> CertificationPathSettings {
            let mut cps = CertificationPathSettings::new();
            cps.set_permitted_signature_algorithms(
                permitted.iter().map(|s| String::from(*s)).collect(),
            );
            cps
        }

        /// The signature algorithms of the candidates chosen for the certificate in `der`
        fn algorithms(cps: &CertificationPathSettings, der: &[u8]) -> Vec<String> {
            chase_candidates(cps, &parse_cert(der, "ee").unwrap())
                .iter()
                .map(|c| c.decoded().signature_algorithm().oid.to_string())
                .collect()
        }

        /// Returns `OUTER` with an AIA caIssuers URI added to its alternate's issuer-specific
        /// extensions, so the URI is reachable only through the rebuilt alternate. The outer's
        /// signature no longer verifies, which does not matter for harvesting URIs.
        fn outer_with_alternate_aia() -> Vec<u8> {
            let mut outer = Cert::from_der(OUTER).unwrap();
            let exts = outer.tbs_certificate.extensions.as_mut().unwrap();
            let last = exts.last_mut().unwrap();
            let mut notes = vec![];
            let mut info =
                read_alternate_issuer_infos(last.extn_value.as_bytes(), &mut notes).remove(0);
            let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
                access_method: ID_AD_CA_ISSUERS,
                access_location: GeneralName::UniformResourceIdentifier(
                    Ia5String::new(CA_ISSUERS).unwrap(),
                ),
            }]);
            info.issuer_extensions.push(Extension {
                extn_id: ID_PE_AUTHORITY_INFO_ACCESS,
                critical: false,
                extn_value: OctetString::new(aia.to_der().unwrap()).unwrap(),
            });
            let contents = info.to_der().unwrap();
            let mut item = ALTERNATE_ISSUER_INFO_TYPE.to_be_bytes().to_vec();
            item.extend_from_slice(&(contents.len() as u16).to_be_bytes());
            item.extend_from_slice(&contents);
            let mut list = ((item.len() + 2) as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&(item.len() as u16).to_be_bytes());
            list.extend_from_slice(&item);
            last.extn_value =
                OctetString::new(OctetString::new(list).unwrap().to_der().unwrap()).unwrap();
            outer.to_der().unwrap()
        }

        /// The AIA and SIA URIs of the candidates chosen for the certificate in `der`
        fn harvested(cps: &CertificationPathSettings, der: &[u8]) -> Vec<String> {
            let mut uris = vec![];
            for candidate in chase_candidates(cps, &parse_cert(der, "ee").unwrap()) {
                collect_uris_from_aia_and_sia(&candidate, &mut uris);
            }
            uris
        }

        #[test]
        fn chase_candidates_follow_the_permitted_signature_algorithms() {
            let all = algorithms(&CertificationPathSettings::new(), OUTER);
            assert_eq!(all, [SHA256_WITH_RSA, ML_DSA_65]);
            assert_eq!(algorithms(&settings(&[ML_DSA_65]), OUTER), [ML_DSA_65]);
            assert_eq!(
                algorithms(&settings(&[SHA256_WITH_RSA]), OUTER),
                [SHA256_WITH_RSA]
            );

            // A certificate without alternates is chased as before, whatever the policy
            assert_eq!(
                algorithms(&settings(&[ML_DSA_65]), ORDINARY),
                [SHA256_WITH_RSA]
            );
        }

        #[test]
        fn an_alternates_aia_is_harvested_when_its_algorithm_is_permitted() {
            let outer = outer_with_alternate_aia();
            assert_eq!(
                harvested(&CertificationPathSettings::new(), &outer),
                [CA_ISSUERS]
            );
            assert_eq!(harvested(&settings(&[ML_DSA_65]), &outer), [CA_ISSUERS]);
            let uris = harvested(&settings(&[SHA256_WITH_RSA]), &outer);
            assert!(uris.is_empty(), "{uris:?}");
        }
    }
}

#[cfg(feature = "certdiscovery")]
pub mod certdiscovery {
    //! Referenced certificates per draft-ietf-lamps-certdiscovery-06: SIA access descriptions whose
    //! access method is id-ad-certDiscovery and whose location is an otherName carrying a
    //! RelatedCertificateDescriptor.

    use alloc::{format, string::String, vec, vec::Vec};

    use const_oid::{
        db::{
            rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_PE_SUBJECT_INFO_ACCESS},
            rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512},
            DB,
        },
        ObjectIdentifier,
    };
    use der::{
        asn1::{Ia5String, Null, OctetString},
        Any, Choice, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader,
        Sequence, Tag, Writer,
    };
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::{
        ext::pkix::{name::GeneralName, BasicConstraints, SubjectInfoAccessSyntax},
        Certificate,
    };

    /// Placeholder for TBD2, id-ad-certDiscovery.
    pub const ID_AD_CERT_DISCOVERY: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.99");

    /// Placeholder for TBD4, id-ad-certDiscoverySelfLocation.
    pub const ID_AD_CERT_DISCOVERY_SELF_LOCATION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.98");

    /// Placeholder for TBD3, id-on-relatedCertificateDescriptor.
    pub const ID_ON_RELATED_CERTIFICATE_DESCRIPTOR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.99");

    /// The most referenced certificates processed for one certificate. The draft sets no limit, but
    /// the certificate carrying them is unverified when they are read.
    pub const MAX_REFERENCED: usize = 8;

    /// ```text
    /// RelatedCertificateDescriptor ::= SEQUENCE {
    ///   method CertDiscoveryMethod,
    ///   signatureAlgorithm [0] AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}}
    ///                          OPTIONAL,
    ///   publicKeyAlgorithm [1] AlgorithmIdentifier{PUBLIC-KEY, {...}} OPTIONAL,
    ///   certHash [2] RelatedCertificate OPTIONAL
    /// }
    /// ```
    ///
    /// The module uses EXPLICIT TAGS.
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    #[allow(missing_docs)]
    pub struct RelatedCertificateDescriptor {
        pub method: CertDiscoveryMethod,
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
        pub signature_algorithm: Option<AlgorithmIdentifierOwned>,
        #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
        pub public_key_algorithm: Option<AlgorithmIdentifierOwned>,
        #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
        pub cert_hash: Option<RelatedCertificate>,
    }

    /// ```text
    /// CertDiscoveryMethod ::= CHOICE {
    ///   byUri IA5String,
    ///   byInclusion Certificate,
    ///   byLocalPolicy NULL,
    ///   byOther [0] INSTANCE OF OTHER-DISCOVERY-METHOD
    /// }
    /// ```
    #[derive(Clone, Debug, Eq, PartialEq, Choice)]
    #[allow(missing_docs)]
    pub enum CertDiscoveryMethod {
        ByUri(Ia5String),
        ByInclusion(EncodedCertificate),
        ByLocalPolicy(Null),
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
        ByOther(Any),
    }

    /// ```text
    /// RelatedCertificate ::= SEQUENCE {
    ///   hashAlgorithm DigestAlgorithmIdentifier,
    ///   hashValue     OCTET STRING
    /// }
    /// ```
    ///
    /// From RFC 9763: the hash of the DER encoding of the referenced certificate.
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    #[allow(missing_docs)]
    pub struct RelatedCertificate {
        pub hash_algorithm: AlgorithmIdentifierOwned,
        pub hash_value: OctetString,
    }

    /// A certificate kept as the DER it arrived in. Decoding and re-encoding it could change the
    /// bytes its signature covers.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct EncodedCertificate(pub Vec<u8>);

    impl FixedTag for EncodedCertificate {
        const TAG: Tag = Tag::Sequence;
    }

    impl<'a> DecodeValue<'a> for EncodedCertificate {
        type Error = der::Error;

        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
            let mut der = header.to_der()?;
            der.extend(reader.read_vec(header.length())?);
            Ok(Self(der))
        }
    }

    impl EncodeValue for EncodedCertificate {
        fn value_len(&self) -> der::Result<Length> {
            let header = Header::from_der(&self.0)?;
            Ok(header.length())
        }

        fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
            let header = Header::from_der(&self.0)?;
            let start = usize::try_from(header.encoded_len()?)?;
            writer.write(&self.0[start..])
        }
    }

    impl RelatedCertificateDescriptor {
        /// The URI a byUri descriptor names.
        pub fn uri(&self) -> Option<&str> {
            match &self.method {
                CertDiscoveryMethod::ByUri(uri) => Some(uri.as_str()),
                _ => None,
            }
        }

        /// Checks the certificate in `der` against the signature algorithm, public key algorithm
        /// and certificate hash this descriptor carries, any of which may be absent (Sections 3.2
        /// and 3.3).
        pub fn check(&self, der: &[u8]) -> Result<(), String> {
            let cert = Certificate::from_der(der).map_err(|e| format!("it did not parse ({e})"))?;
            if let Some(alg) = &self.signature_algorithm {
                if alg != cert.signature_algorithm() {
                    return Err(format!(
                        "its signature algorithm is {}, not {}",
                        name_of(&cert.signature_algorithm().oid),
                        name_of(&alg.oid)
                    ));
                }
            }
            if let Some(alg) = &self.public_key_algorithm {
                let key = &cert.tbs_certificate().subject_public_key_info().algorithm;
                if alg != key {
                    return Err(format!(
                        "its public key algorithm is {}, not {}",
                        name_of(&key.oid),
                        name_of(&alg.oid)
                    ));
                }
            }
            if let Some(hash) = &self.cert_hash {
                let digest = match hash.hash_algorithm.oid {
                    ID_SHA_256 => Sha256::digest(der).to_vec(),
                    ID_SHA_384 => Sha384::digest(der).to_vec(),
                    ID_SHA_512 => Sha512::digest(der).to_vec(),
                    other => return Err(format!("certHash uses {}", name_of(&other))),
                };
                if digest != hash.hash_value.as_bytes() {
                    return Err("its hash does not match certHash".into());
                }
            }
            Ok(())
        }
    }

    /// Names `oid` for display, falling back to its dotted form.
    fn name_of(oid: &ObjectIdentifier) -> String {
        DB.by_oid(oid)
            .map(String::from)
            .unwrap_or_else(|| oid.to_string())
    }

    /// Returns the RelatedCertificateDescriptors in the SIA extension of the certificate in `der`,
    /// skipping any that do not decode.
    pub fn descriptors(der: &[u8]) -> Vec<RelatedCertificateDescriptor> {
        let Ok(cert) = Certificate::from_der(der) else {
            return vec![];
        };
        let Some(sia) = cert
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.extn_id == ID_PE_SUBJECT_INFO_ACCESS)
        else {
            return vec![];
        };
        let Ok(sia) = SubjectInfoAccessSyntax::from_der(sia.extn_value.as_bytes()) else {
            return vec![];
        };
        sia.0
            .iter()
            .filter(|ad| ad.access_method == ID_AD_CERT_DISCOVERY)
            .filter_map(|ad| match &ad.access_location {
                GeneralName::OtherName(on)
                    if on.type_id == ID_ON_RELATED_CERTIFICATE_DESCRIPTOR =>
                {
                    on.value.decode_as().ok()
                }
                _ => None,
            })
            .collect()
    }

    /// Whether the certificate in `der` asserts cA in its basic constraints.
    pub fn is_ca(der: &[u8]) -> bool {
        let Ok(cert) = Certificate::from_der(der) else {
            return false;
        };
        cert.tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .and_then(|e| BasicConstraints::from_der(e.extn_value.as_bytes()).ok())
            .is_some_and(|bc| bc.ca)
    }

    /// Returns the certificates the certificate in `der` includes by reference (byInclusion).
    pub fn included(der: &[u8]) -> Vec<Vec<u8>> {
        descriptors(der)
            .into_iter()
            .take(MAX_REFERENCED)
            .filter_map(|d| match d.method {
                CertDiscoveryMethod::ByInclusion(cert) => Some(cert.0),
                _ => None,
            })
            .collect()
    }
}

//! The [`SubjectNameAndKey`] trait exposes the subject identity — a name and public key, plus the
//! key usage and trust status needed alongside them — of either a full certificate or a trust anchor.
//! Revocation checking is its first consumer: it lets a trust anchor expressed as a name plus public
//! key (e.g. a webpki root that carries no wrapped certificate) act as a CRL/OCSP issuer alongside a
//! full certificate.
//!
//! Before this abstraction, revocation checking demanded a `CertificateInner` for the issuer and
//! obtained it via `get_certificate_from_trust_anchor`, which returns `None` for a name+SPKI trust
//! anchor — so revocation hard-failed with `Error::Unrecognized` on such anchors. Implementing the
//! trait for both `CertificateInner<Raw>` and `TrustAnchorChoice<Raw>` lets the same code path accept
//! either.

use const_oid::db::rfc5912::ID_CE_KEY_USAGE;
use der::Decode;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::{
    anchor::TrustAnchorChoice,
    certificate::{CertificateInner, Raw},
    ext::pkix::KeyUsage,
    name::Name,
};

use crate::source::ta_source::{
    get_certificate_from_trust_anchor, get_subject_public_key_info_from_trust_anchor,
};
use crate::validator::pdv_trust_anchor::get_trust_anchor_name;
use crate::Result;

/// A subject identity — name and public key — with the key usage and trust status that accompany it.
/// Implemented for both a full certificate and a [`TrustAnchorChoice`], so a name+SPKI trust anchor
/// can stand in wherever a certificate's identity is expected (e.g. as a CRL/OCSP issuer).
///
/// `Send + Sync` are required so that `&dyn SubjectNameAndKey` can be held across await points in the
/// async revocation path and keep those futures `Send` (both implementors are plain DER data).
pub trait SubjectNameAndKey: Send + Sync {
    /// Subject public key info; used to verify CRL and OCSP signatures.
    fn spki(&self) -> &SubjectPublicKeyInfoOwned;

    /// Subject name; used to build OCSP `CertID`s and to match delegated responders.
    fn subject_name(&self) -> Result<&Name>;

    /// The key usage extension, if the subject carries one. `None` covers both a genuinely absent
    /// extension and one that fails to parse.
    fn key_usage(&self) -> Option<KeyUsage>;

    /// True for a trust anchor. A trust anchor is implicitly trusted to issue CRLs even without a
    /// key usage extension asserting `cRLSign`, whereas an ordinary certificate lacking one is
    /// rejected (RFC 5280 6.3.3(f), fail-closed).
    fn is_implicitly_trusted(&self) -> bool;
}

/// Extracts the key usage extension from a certificate, if present and parseable.
fn key_usage_from_cert(cert: &CertificateInner<Raw>) -> Option<KeyUsage> {
    let exts = cert.tbs_certificate().extensions()?;
    for ext in exts.as_slice() {
        if ext.extn_id == ID_CE_KEY_USAGE {
            return KeyUsage::from_der(ext.extn_value.as_bytes()).ok();
        }
    }
    None
}

impl SubjectNameAndKey for CertificateInner<Raw> {
    fn spki(&self) -> &SubjectPublicKeyInfoOwned {
        self.tbs_certificate().subject_public_key_info()
    }
    fn subject_name(&self) -> Result<&Name> {
        Ok(self.tbs_certificate().subject())
    }
    fn key_usage(&self) -> Option<KeyUsage> {
        key_usage_from_cert(self)
    }
    fn is_implicitly_trusted(&self) -> bool {
        false
    }
}

impl SubjectNameAndKey for TrustAnchorChoice<Raw> {
    fn spki(&self) -> &SubjectPublicKeyInfoOwned {
        get_subject_public_key_info_from_trust_anchor(self)
    }
    fn subject_name(&self) -> Result<&Name> {
        get_trust_anchor_name(self)
    }
    fn key_usage(&self) -> Option<KeyUsage> {
        // A trust anchor with a wrapped certificate can still assert key usage; a bare name+SPKI
        // TaInfo has none, which is fine because it is implicitly trusted.
        get_certificate_from_trust_anchor(self).and_then(key_usage_from_cert)
    }
    fn is_implicitly_trusted(&self) -> bool {
        true
    }
}

//! X.509 OCSP CertID

use der::{asn1::OctetString, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    certificate::{Profile, Rfc5280},
    serial_number::SerialNumber,
};

/// CertID structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// CertID ::= SEQUENCE {
///    hashAlgorithm           AlgorithmIdentifier,
///    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
///    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
///    serialNumber            CertificateSerialNumber }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertId<P: Profile + 'static = Rfc5280> {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: SerialNumber<P>,
}

impl From<&CertId> for CertId {
    /// Clones the referenced `CertID`
    fn from(other: &CertId) -> Self {
        other.clone()
    }
}

//! A partially decoded CRL, with the revoked certificate entries left undecoded

use der::asn1::{BitStringRef, SequenceRef};
use der::{
    DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Result, Sequence, Tag, Writer,
};
use x509_cert::{ext::Extensions, name::Name, spki::AlgorithmIdentifierOwned, time::Time, Version};

/// `CertificateList` as defined in [RFC 5280 Section 5.1], with `tbsCertList` decoded as a
/// [`TbsCertListHeader`].
///
/// Decoding one costs the issuer name, the dates and the CRL extensions, whatever the number of
/// revoked certificates, so a store can index or order CRLs without decoding their entries. The
/// signature is not verified and the entries are not checked; use
/// [`x509_cert::crl::CertificateList`] to process a CRL.
///
/// ```text
/// CertificateList  ::=  SEQUENCE  {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertificateListHeader<'a> {
    /// The signed portion of the CRL, with its entries undecoded.
    pub tbs_cert_list: TbsCertListHeader<'a>,
    /// Algorithm used to sign the CRL.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// Signature over `tbs_cert_list`.
    pub signature: BitStringRef<'a>,
}

/// `TBSCertList` as defined in [RFC 5280 Section 5.1], with `revokedCertificates` held as the
/// undecoded `SEQUENCE`.
///
/// ```text
/// TBSCertList  ::=  SEQUENCE  {
///      version                 Version OPTIONAL, -- if present, MUST be v2
///      signature               AlgorithmIdentifier,
///      issuer                  Name,
///      thisUpdate              Time,
///      nextUpdate              Time OPTIONAL,
///      revokedCertificates     SEQUENCE OF SEQUENCE  { ... }  OPTIONAL,
///      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL -- if present, version MUST be v2
/// }
/// ```
///
/// The fields other than `revoked_certificates` decode as in [`x509_cert::crl::TbsCertList`], except
/// that a missing `version` decodes as [`Version::V1`], since RFC 5280 makes the field optional
/// (x509-cert 0.3.0 requires it).
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertListHeader<'a> {
    /// CRL format version. Absent in a v1 CRL, where it decodes as [`Version::V1`]; `V1` is omitted
    /// when encoding, so a v1 CRL re-encodes to the same bytes.
    #[asn1(default = "Default::default")]
    pub version: Version,
    /// Algorithm used to sign the CRL, which must match `signature_algorithm` in the
    /// [`CertificateListHeader`].
    pub signature: AlgorithmIdentifierOwned,
    /// Name of the CRL issuer.
    pub issuer: Name,
    /// Time the CRL was issued.
    pub this_update: Time,
    /// Time by which the next CRL will be issued.
    pub next_update: Option<Time>,
    /// The revoked certificate entries, undecoded. Absent when no certificate is listed.
    pub revoked_certificates: Option<RevokedCertificatesRef<'a>>,
    /// CRL extensions.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub crl_extensions: Option<Extensions>,
}

/// The `revokedCertificates` field of a [`TbsCertListHeader`]: the `SEQUENCE OF` revoked certificate
/// entries, undecoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokedCertificatesRef<'a>(pub &'a SequenceRef);

impl FixedTag for RevokedCertificatesRef<'_> {
    const TAG: Tag = Tag::Sequence;
}

impl<'a> DecodeValue<'a> for RevokedCertificatesRef<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        <&'a SequenceRef>::decode_value(reader, header).map(Self)
    }
}

impl EncodeValue for RevokedCertificatesRef<'_> {
    fn value_len(&self) -> Result<Length> {
        self.0.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        self.0.encode_value(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    /// A v1 CRL, with no version field: TBSCertList { sha256WithRSAEncryption, CN=test,
    /// thisUpdate 260101000000Z }, as reported in RustCrypto/formats#2544.
    const V1_CRL: &[u8] = &hex_literal::hex!(
        "3044" "302f" "300d06092a864886f70d01010b0500"
        "300f310d300b06035504030c0474657374" "170d3236303130313030303030305a"
        "300d06092a864886f70d01010b0500" "03020000"
    );

    #[test]
    fn a_v1_crl_without_a_version_decodes_as_v1() {
        let crl = CertificateListHeader::from_der(V1_CRL).unwrap();
        assert_eq!(crl.tbs_cert_list.version, Version::V1);
        assert_eq!(crl.to_der().unwrap(), V1_CRL);
        #[cfg(feature = "revocation")]
        {
            let info = crate::get_crl_info_from_header(&crl).unwrap();
            assert_eq!(info.issuer_name, "CN=test");
        }
    }

    #[test]
    fn a_v2_crl_keeps_its_version() {
        let der = include_bytes!("../../tests/examples/makaan.com/crls/2-crl.crl");
        let crl = CertificateListHeader::from_der(der).unwrap();
        assert_eq!(crl.tbs_cert_list.version, Version::V2);
        assert_eq!(crl.to_der().unwrap(), der.as_slice());
    }
}

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
/// The fields other than `revoked_certificates` decode as in [`x509_cert::crl::TbsCertList`].
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertListHeader<'a> {
    /// CRL format version.
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

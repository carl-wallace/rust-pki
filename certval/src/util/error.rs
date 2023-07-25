//! Error types

use core::fmt;

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PathValidationStatus {
    /// No errors were encountered while validating certification path
    Valid,
    /// NameChainingFailure occurs when a CertificationPath features certificates for which the subject
    /// name of a superior certificate does not match the issuer name of the immediately subordinate certificate.
    NameChainingFailure,
    /// SignatureVerificationFailure occurs when a CertificationPath features certificates for which the subject
    /// public key of a superior certificate does not verify the signature of the immediately subordinate certificate.
    SignatureVerificationFailure,
    /// InvalidNotBeforeDate occurs when a CertificationPath features a certificate that contains a notBefore
    /// date that is after the time of interest used for a certification path validation operation.
    InvalidNotBeforeDate,
    /// InvalidNotAfterDate occurs when a CertificationPath features a certificate that contains a notAfter
    /// date that is before the time of interest used for a certification path validation operation.
    InvalidNotAfterDate,
    /// MissingBasicConstraints occurs when a CertificationPath features an intermediate CA certificate that
    /// does not contain a basicConstraints extension.
    MissingBasicConstraints,
    /// InvalidBasicConstraints occurs when a CertificationPath features an intermediate CA certificate that
    /// contains a basicConstraints extension with the cA field set to false.
    InvalidBasicConstraints,
    /// InvalidPathLength occurs when a CertificationPath has more certificates than allowed by either an
    /// initial path length configuration or a constraint asserted in an intermediate CA certificate present
    /// in the certification path.
    InvalidPathLength,
    /// InvalidKeyUsage occurs when an intermediate CA certificate lacks keyCertSign (or keyCrlSign when process
    /// CRLs) or when a target certificate does not include bits from PS_KEY_USAGE value in a
    /// CertificationPathSettings instance.
    InvalidKeyUsage,
    /// NullPolicySet occurs when the valid_policy_tree becomes NULL when processing an intermediate CA
    /// certificate or when processing a target certificate and requireExplicitPolicy is operative.
    NullPolicySet,
    /// NameConstraintsViolation occurs when a name constraint is violated.
    NameConstraintsViolation,
    /// UnprocessedCriticalExtension occurs when a certificate features a critical extension that was not
    /// processed during certification path validation.
    UnprocessedCriticalExtension,
    /// MissingTrustAnchor occurs when a CertificationPath has no trust anchor.
    MissingTrustAnchor,
    /// MissingTrustAnchorName occurs when a TrustAnchorChoice object features a TaInfo field that
    /// has not CertPathControls or that has a CertPathControls that does not assert a name or wrap
    /// a Certificate.
    MissingTrustAnchorName,
    /// ProhibitedAlg occurs when an algorithm constraint is violated.
    ProhibitedAlg,
    /// ProhibitedKeySize occurs when a key size constraint is violated.
    ProhibitedKeySize,
    /// EncodingError occurs when an object cannot be parsed (though this is more likely to manifest
    /// as an Asn1Error).
    EncodingError,
    /// MissingCertificate occurs when the certification path is missing a target certificate.
    MissingCertificate,
    /// NoPathsFounds occurs when the certification path builder fails to find any candidate paths.
    NoPathsFound,
    /// CountryCodeViolation occurs when a target certificate is not compliant with operative PS_PERM_COUNTRIES
    /// or PS_EXCL_COUNTRIES items in a CertificationPathSettings instance.
    CountryCodeViolation,
    /// CertificateRevoked occurs when a CertificationPath contains a certificate that has been revoked.
    CertificateRevoked,
    /// CertificateRevokedEndEntity occurs when a CertificationPath contains an end entity certificate that has been revoked.
    CertificateRevokedEndEntity,
    /// CertificateRevokedIntermediateCa occurs when a CertificationPath contains an intermediate CA certificate that has been revoked.
    CertificateRevokedIntermediateCa,
    /// RevocationStatusNotDetermined occurs when a CertificationPath contains a certificate for which
    /// revocation status could not be determined.
    RevocationStatusNotDetermined,
    /// CertificateOnHold relates to use of the on hold revocation status, which is seldom used.
    CertificateOnHold,
    /// CertificateBlocklisted occurs when a certificate has essentially been manually revoked using a
    /// blocklist in the configuration used during certification path processing.
    CertificateBlocklisted,
    /// StatusCheckReliedOnStaleCrl occurs when revocation status was determined but required use of a
    /// stale CRL to do so.
    StatusCheckReliedOnStaleCrl,
    /// RevocationStatusNotAvailable is similar to RevocationStatusNotDetermined.
    RevocationStatusNotAvailable,
    /// A configuration error was detected. See textual log output for more details.
    Misconfiguration,
}

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// PathValidationError encountered
    PathValidation(PathValidationStatus),
    /// NotFound occurs when an action failed because a necessary artifact was not found.
    NotFound,
    /// Unrecognized occurs when an error conditions does not match anything else here.
    Unrecognized,
    /// A URI scheme was encountered that was no valid in given context, i.e., ldap URI presented to OCSP
    InvalidUriScheme,
    /// An artifact did not conform to length requirements
    LengthError,
    /// An artifact could not be parsed
    ParseError,
    /// No error was observed
    Success,
    /// A CRL was found to be incompatible with certificate whose revocation status is sought.
    CrlIncompatible,
    /// An indirect CRL was found. Indirect CRLs are not supported.
    UnsupportedIndirectCrl,
    /// A CRL was ignored due to an invalid extension.
    UnsupportedCrlExtension,
    /// A CRL entry was ignored due to an invalid extension.
    UnsupportedCrlEntryExtension,
    /// A networking issue occurred.
    NetworkError,
    /// An error occurred processing an OCSP response
    OcspResponseError,
    /// Asn1Error is used to propagate error information from the x509 crate.
    Asn1Error(der::Error),
    /// A URI was rejected due to presence on blocklist
    UriOnBlocklist,
    /// A resource was not retrieved due to no change since saved last modified time
    ResourceUnchanged,
    /// Error encapsulates an error derived from [std::io::ErrorKind]
    #[cfg(feature = "std")]
    StdIoError(std::io::ErrorKind),
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1Error(err)
    }
}

impl fmt::Display for PathValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathValidationStatus::Valid => write!(f, "Valid"),
            PathValidationStatus::NameChainingFailure => write!(f, "Name chaining failure"),
            PathValidationStatus::SignatureVerificationFailure => {
                write!(f, "Signature verification failure")
            }
            PathValidationStatus::InvalidNotBeforeDate => write!(f, "InvalidNotBeforeDate"),
            PathValidationStatus::InvalidNotAfterDate => write!(f, "InvalidNotAfterDate"),
            PathValidationStatus::MissingBasicConstraints => write!(f, "MissingBasicConstraints"),
            PathValidationStatus::InvalidBasicConstraints => write!(f, "InvalidBasicConstraints"),
            PathValidationStatus::InvalidPathLength => write!(f, "InvalidPathLength"),
            PathValidationStatus::InvalidKeyUsage => write!(f, "InvalidKeyUsage"),
            PathValidationStatus::NullPolicySet => write!(f, "NullPolicySet"),
            PathValidationStatus::NameConstraintsViolation => write!(f, "NameConstraintsViolation"),
            PathValidationStatus::UnprocessedCriticalExtension => {
                write!(f, "UnprocessedCriticalExtension")
            }
            PathValidationStatus::MissingTrustAnchor => write!(f, "MissingTrustAnchor"),
            PathValidationStatus::MissingTrustAnchorName => write!(f, "MissingTrustAnchorName"),
            PathValidationStatus::ProhibitedAlg => write!(f, "ProhibitedAlg"),
            PathValidationStatus::ProhibitedKeySize => write!(f, "ProhibitedKeySize"),
            PathValidationStatus::EncodingError => write!(f, "EncodingError"),
            PathValidationStatus::MissingCertificate => write!(f, "MissingCertificate"),
            PathValidationStatus::NoPathsFound => write!(f, "NoPathsFound"),
            PathValidationStatus::CountryCodeViolation => write!(f, "CountryCodeViolation"),
            PathValidationStatus::CertificateRevoked => write!(f, "CertificateRevoked"),
            PathValidationStatus::CertificateRevokedEndEntity => {
                write!(f, "CertificateRevokedEndEntity")
            }
            PathValidationStatus::CertificateRevokedIntermediateCa => {
                write!(f, "CertificateRevokedIntermediateCa")
            }
            PathValidationStatus::RevocationStatusNotDetermined => {
                write!(f, "RevocationStatusNotDetermined")
            }
            PathValidationStatus::CertificateOnHold => write!(f, "CertificateOnHold"),
            PathValidationStatus::CertificateBlocklisted => write!(f, "CertificateBlocklisted"),
            PathValidationStatus::StatusCheckReliedOnStaleCrl => {
                write!(f, "StatusCheckReliedOnStaleCrl")
            }
            PathValidationStatus::RevocationStatusNotAvailable => {
                write!(f, "RevocationStatusNotAvailable")
            }
            PathValidationStatus::Misconfiguration => write!(f, "Misconfiguration"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PathValidation(err) => write!(f, "PathValidationError: {}", err),
            Error::NotFound => write!(f, "NotFound"),
            Error::Unrecognized => write!(f, "Unrecognized"),
            Error::InvalidUriScheme => write!(f, "InvalidUriScheme"),
            Error::LengthError => write!(f, "LengthError"),
            Error::ParseError => write!(f, "ParseError"),
            Error::Success => write!(f, "Success"),
            Error::CrlIncompatible => write!(f, "CrlIncompatible"),
            Error::UnsupportedIndirectCrl => write!(f, "UnsupportedIndirectCrl"),
            Error::UnsupportedCrlExtension => write!(f, "UnsupportedCrlExtension"),
            Error::UnsupportedCrlEntryExtension => write!(f, "UnsupportedCrlEntryExtension"),
            Error::NetworkError => write!(f, "NetworkError"),
            Error::OcspResponseError => write!(f, "OcspResponseError"),
            Error::Asn1Error(err) => write!(f, "Asn1Error: {}", err),
            Error::UriOnBlocklist => write!(f, "UriOnBlocklist"),
            Error::ResourceUnchanged => write!(f, "ResourceUnchanged"),
            #[cfg(feature = "std")]
            Error::StdIoError(err) => write!(f, "StdError: {:?}", err),
        }
    }
}

#[test]
fn error_test() {
    use alloc::format;

    let _s = format!("{}", PathValidationStatus::Valid);
    let _s = format!("{}", PathValidationStatus::NameChainingFailure);
    let _s = format!("{}", PathValidationStatus::SignatureVerificationFailure);
    let _s = format!("{}", PathValidationStatus::InvalidNotBeforeDate);
    let _s = format!("{}", PathValidationStatus::InvalidNotAfterDate);
    let _s = format!("{}", PathValidationStatus::MissingBasicConstraints);
    let _s = format!("{}", PathValidationStatus::InvalidBasicConstraints);
    let _s = format!("{}", PathValidationStatus::InvalidPathLength);
    let _s = format!("{}", PathValidationStatus::InvalidKeyUsage);
    let _s = format!("{}", PathValidationStatus::NullPolicySet);
    let _s = format!("{}", PathValidationStatus::NameConstraintsViolation);
    let _s = format!("{}", PathValidationStatus::UnprocessedCriticalExtension);
    let _s = format!("{}", PathValidationStatus::MissingTrustAnchor);
    let _s = format!("{}", PathValidationStatus::MissingTrustAnchorName);
    let _s = format!("{}", PathValidationStatus::ProhibitedAlg);
    let _s = format!("{}", PathValidationStatus::ProhibitedKeySize);
    let _s = format!("{}", PathValidationStatus::EncodingError);
    let _s = format!("{}", PathValidationStatus::MissingCertificate);
    let _s = format!("{}", PathValidationStatus::NoPathsFound);
    let _s = format!("{}", PathValidationStatus::CountryCodeViolation);
    let _s = format!("{}", PathValidationStatus::CertificateRevoked);
    let _s = format!("{}", PathValidationStatus::CertificateRevokedEndEntity);
    let _s = format!(
        "{:?}",
        PathValidationStatus::CertificateRevokedIntermediateCa
    );
    let _s = format!("{}", PathValidationStatus::RevocationStatusNotDetermined);
    let _s = format!("{}", PathValidationStatus::CertificateOnHold);
    let _s = format!("{}", PathValidationStatus::CertificateBlocklisted);
    let _s = format!("{}", PathValidationStatus::StatusCheckReliedOnStaleCrl);
    let _s = format!("{}", PathValidationStatus::RevocationStatusNotAvailable);
    let _s = format!("{}", PathValidationStatus::Misconfiguration);

    //let _s = format!("{}", Error::PathValidation(PathValidationStatus));
    let _s = format!("{}", Error::NotFound);
    let _s = format!("{}", Error::Unrecognized);
    let _s = format!("{}", Error::InvalidUriScheme);
    let _s = format!("{}", Error::LengthError);
    let _s = format!("{}", Error::ParseError);
    let _s = format!("{}", Error::Success);
    let _s = format!("{}", Error::CrlIncompatible);
    let _s = format!("{}", Error::UnsupportedIndirectCrl);
    let _s = format!("{}", Error::UnsupportedCrlExtension);
    let _s = format!("{}", Error::UnsupportedCrlEntryExtension);
    let _s = format!("{}", Error::NetworkError);
    let _s = format!("{}", Error::OcspResponseError);
    //let _s = format!("{}", Error::Asn1Error(der::Error));
    let _s = format!("{}", Error::UriOnBlocklist);
    let _s = format!("{}", Error::ResourceUnchanged);
}

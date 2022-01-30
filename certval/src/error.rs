//! Error types

use core::fmt;

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
pub enum Error {
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
    /// NotFound occurs when an action failed because a necessary artifact was not found.
    NotFound,
    /// A configuration error was detected. See textual log output for more details.
    Misconfiguration,
    /// Unrecognized occurs when an error conditions does not match anything else here.
    Unrecognized,
    /// No error was observed
    Success,
    /// Asn1Error is used to propagate error information from the x509 crate.
    Asn1Error,
}

//TODO implement Error trait?

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NameChainingFailure => write!(f, "Name chaining failure"),
            Error::SignatureVerificationFailure => write!(f, "Signature verification failure"),
            Error::InvalidNotBeforeDate => write!(f, "InvalidNotBeforeDate"),
            Error::InvalidNotAfterDate => write!(f, "InvalidNotAfterDate"),
            Error::MissingBasicConstraints => write!(f, "MissingBasicConstraints"),
            Error::InvalidBasicConstraints => write!(f, "InvalidBasicConstraints"),
            Error::InvalidPathLength => write!(f, "InvalidPathLength"),
            Error::InvalidKeyUsage => write!(f, "InvalidKeyUsage"),
            Error::NullPolicySet => write!(f, "NullPolicySet"),
            Error::NameConstraintsViolation => write!(f, "NameConstraintsViolation"),
            Error::UnprocessedCriticalExtension => write!(f, "UnprocessedCriticalExtension"),
            Error::MissingTrustAnchor => write!(f, "MissingTrustAnchor"),
            Error::MissingTrustAnchorName => write!(f, "MissingTrustAnchorName"),
            Error::ProhibitedAlg => write!(f, "ProhibitedAlg"),
            Error::ProhibitedKeySize => write!(f, "ProhibitedKeySize"),
            Error::EncodingError => write!(f, "EncodingError"),
            Error::MissingCertificate => write!(f, "MissingCertificate"),
            Error::NoPathsFound => write!(f, "NoPathsFound"),
            Error::CountryCodeViolation => write!(f, "CountryCodeViolation"),
            Error::CertificateRevoked => write!(f, "CertificateRevoked"),
            Error::RevocationStatusNotDetermined => write!(f, "RevocationStatusNotDetermined"),
            Error::CertificateOnHold => write!(f, "CertificateOnHold"),
            Error::CertificateBlocklisted => write!(f, "CertificateBlocklisted"),
            Error::StatusCheckReliedOnStaleCrl => write!(f, "StatusCheckReliedOnStaleCrl"),
            Error::RevocationStatusNotAvailable => write!(f, "RevocationStatusNotAvailable"),
            Error::NotFound => write!(f, "NotFound"),
            Error::Misconfiguration => write!(f, "Misconfiguration"),
            Error::Unrecognized => write!(f, "Unrecognized"),
            Error::Success => write!(f, "Success"),
            Error::Asn1Error => write!(f, "Asn1Error"),
        }
    }
}

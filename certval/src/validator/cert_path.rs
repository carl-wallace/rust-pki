//! Provides structure that represents a certification path including target, optional intermediate CAs,
//! trust anchor and optional revocation information.

use crate::{CertificateChain, PDVCertificate, PDVTrustAnchorChoice};

use alloc::{vec, vec::Vec};

/// `CertificationPath` is used to represent the trust anchor, intermediate CA certificates and target certificate
/// that comprise a certification path.
#[derive(Clone)]
#[readonly::make]
pub struct CertificationPath {
    /// `target` contains the target certificate for the certification path
    #[readonly]
    pub target: PDVCertificate,
    /// `intermediates` contains zero or more intermediate CA certificates, beginning with the certificate that
    /// was issued by `trust_anchor` and proceeding in order to a certificate that issued the target, i.e.,
    /// `intermediates\[0\]` can be used to verify `intermediates\[1\]`, `intermediates\[1\]` can be used to verify
    /// `intermediates\[2\]`, etc. until `intermediates[intermediates.len() - 1]` can be used to verify `target`.
    #[readonly]
    pub intermediates: CertificateChain,
    /// `trust_anchor` contains the trust anchor for the certification path
    #[readonly]
    pub trust_anchor: PDVTrustAnchorChoice,

    /// crls is a vector of buffers of size intermediates.len() + 1, to allow for a CRL for each
    /// intermediate CA and the target beginning with the intermediate CA issued by the trust anchor,
    /// if any, and proceeding through the target. Where no CRL is available when path is constructed,
    /// None is present.
    pub crls: Vec<Option<Vec<u8>>>,

    /// ocsp_responses is a vector of buffers of size intermediates.len() + 1, to allow for an OCSP response for each
    /// intermediate CA and the target beginning with the intermediate CA issued by the trust anchor,
    /// if any, and proceeding through the target. Where no OCSP response is available when path is constructed,
    /// None is present.
    pub ocsp_responses: Vec<Option<Vec<u8>>>,
}

impl CertificationPath {
    /// instantiates a new TaSource
    pub fn new(
        trust_anchor: PDVTrustAnchorChoice,
        intermediates: CertificateChain,
        target: PDVCertificate,
    ) -> CertificationPath {
        let len = intermediates.len() + 1;
        CertificationPath {
            trust_anchor,
            intermediates,
            target,
            crls: vec![None; len],
            ocsp_responses: vec![None; len],
        }
    }

    /// stapled_rev_info_available returns true if any caller-supplied CRLs or OCSP responses are available
    /// and false otherwise.
    pub fn stapled_rev_info_available(&self) -> bool {
        if self.ocsp_responses.iter().any(|x| x.is_some()) || self.crls.iter().any(|x| x.is_some())
        {
            return true;
        }
        false
    }
}

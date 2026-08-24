//! Accepting a certificate in whichever encoding its file happened to hold.
//!
//! This exists because getting it wrong is not loud. Every entry point that takes bytes from a
//! caller has to tolerate PEM, and one that does not fails in a way that looks like something else
//! entirely: on 2026-08-20 a PEM target validated normally while contributing nothing to the
//! revocation harvest, so every certificate reported `undetermined` with no explanation, and the
//! same encoding later stopped the URI checker before it began. Two bugs, one cause, in code that
//! had each grown its own parse.
//!
//! So the rule is: decode here, once, at every boundary where caller bytes arrive — and never let a
//! DER-only parse be the first thing a file meets.

use certval::{certs_from_signed_data, Error, Result};

// Re-exported so a caller has one place for both halves of "what is a certificate file": which
// extensions to offer, and how to decode what arrives. pittv3-gui does not depend on certval.
pub use certval::{CERT_BUNDLE_EXTENSIONS, SINGLE_CERT_EXTENSIONS, TA_BUNDLE_EXTENSIONS};

/// Returns DER bytes given a buffer that may be PEM or DER encoded.
///
/// DER is detected by its leading tag rather than by attempting a parse: `SEQUENCE` covers
/// certificates and the certificate variant of `TrustAnchorChoice`, and the two context tags cover
/// the `tbsCert` and `taInfo` variants of a DER-encoded RFC 5914 `TrustAnchorChoice`. Anything else
/// is offered to the PEM decoder, and a failure there means the bytes are neither.
pub fn maybe_pem(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.is_empty() && matches!(bytes[0], 0x30 | 0xA1 | 0xA2) {
        return Ok(bytes.to_vec());
    }
    match pem_rfc7468::decode_vec(bytes) {
        Ok((_label, der)) => Ok(der),
        Err(_) => Err(Error::Unrecognized),
    }
}

/// Returns every certificate a caller's buffer carries, in DER, whatever container it arrived in.
///
/// [`maybe_pem`] answers "what encoding is this one object in"; this answers "what certificates are
/// in this file", which is the question a trust-anchor or CA input actually asks. The two differ for
/// exactly the containers that hold more than one certificate: a certs-only PKCS#7 message (`.p7c`,
/// how DoD PKE publishes cross-certificate bundles) and a concatenated PEM bundle. Passing either to
/// `maybe_pem` yields well-formed DER that is not a certificate, or only the first of several, and
/// both fail quietly downstream.
pub fn certs_in(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if let Some(certs) = certs_from_signed_data(bytes) {
        return Ok(certs);
    }
    Ok(vec![maybe_pem(bytes)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two encodings of one certificate must reduce to the same bytes — the property every
    /// caller of this depends on, and the one whose absence caused both bugs above.
    #[test]
    fn pem_and_der_reduce_to_the_same_der() {
        let der = include_bytes!("../../certval/tests/examples/amazon.com/2-target.der").to_vec();
        let pem = include_bytes!("../../certval/tests/examples/amazon.com/2-target.pem").to_vec();
        assert_ne!(der, pem, "fixtures must genuinely differ in encoding");
        assert_eq!(
            maybe_pem(&der).unwrap(),
            der,
            "DER passes through unchanged"
        );
        assert_eq!(maybe_pem(&pem).unwrap(), der, "PEM decodes to the same DER");
    }

    /// The reason `certs_in` exists rather than callers using `maybe_pem`: a `.p7c` passes
    /// `maybe_pem` unchanged, because it is well-formed DER starting with SEQUENCE. It is just not
    /// a certificate, so every caller that assumed one got nothing and said nothing.
    #[test]
    fn certs_in_expands_a_container_that_maybe_pem_passes_through_whole() {
        let p7c = include_bytes!("../../certval/tests/examples/caCertsIssuedTofbcag4.p7c");
        assert_eq!(
            maybe_pem(p7c).unwrap(),
            p7c.to_vec(),
            "maybe_pem hands back the container, which is the bug this closes"
        );
        assert_eq!(6, certs_in(p7c).unwrap().len());

        let der = include_bytes!("../../certval/tests/examples/amazon.com/2-target.der").to_vec();
        let pem = include_bytes!("../../certval/tests/examples/amazon.com/2-target.pem").to_vec();
        assert_eq!(
            vec![der.clone()],
            certs_in(&der).unwrap(),
            "a bare certificate is one cert"
        );
        assert_eq!(
            vec![der],
            certs_in(&pem).unwrap(),
            "and so is its PEM encoding"
        );
    }

    #[test]
    fn neither_encoding_is_refused_rather_than_guessed() {
        assert!(maybe_pem(b"").is_err());
        assert!(maybe_pem(b"not a certificate in any encoding").is_err());
    }
}

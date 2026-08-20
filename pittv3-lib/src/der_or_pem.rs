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

use certval::{Error, Result};

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

    #[test]
    fn neither_encoding_is_refused_rather_than_guessed() {
        assert!(maybe_pem(b"").is_err());
        assert!(maybe_pem(b"not a certificate in any encoding").is_err());
    }
}

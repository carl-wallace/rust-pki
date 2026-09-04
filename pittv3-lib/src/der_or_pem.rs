//! Accepting a certificate in whichever encoding its file happened to hold.
//!
//! This exists because getting it wrong is not loud. Every entry point that takes bytes from a
//! caller has to tolerate PEM, and one that does not fails in a way that looks like something else
//! entirely: on 2026-08-20 a PEM target validated normally while contributing nothing to the
//! revocation harvest, so every certificate reported `undetermined` with no explanation, and the
//! same encoding later stopped the URI checker before it began. Two bugs, one cause, in code that
//! had each grown its own parse.
//!
//! The same shape recurred on 2026-08-25 one layer in: the container expansion below was itself a
//! DER-only parse, so a PEM-armored `.p7b` — how DoD PKE publishes its CA bundle — got past it,
//! decoded to a well-formed SignedData, and was taken for a certificate. Forty-nine certificates
//! arrived as one unusable object and nothing said so.
//!
//! So the rule is: decode here, once, at every boundary where caller bytes arrive — and never let a
//! DER-only parse be the first thing a file meets, the expansion of a container included.

use certval::{certs_from_signed_data, decode_bare_base64, decode_pem_to_ders, Error, Result};

// Re-exported so a caller has one place for both halves of "what is a certificate file": which
// extensions to offer, and how to decode what arrives. pittv3-gui does not depend on certval.
pub use certval::{CERT_BUNDLE_EXTENSIONS, SINGLE_CERT_EXTENSIONS, TA_BUNDLE_EXTENSIONS};

/// Returns DER bytes given a buffer that may be PEM or DER encoded.
///
/// DER is detected by its leading tag rather than by attempting a parse: `SEQUENCE` covers
/// certificates and the certificate variant of `TrustAnchorChoice`, and the two context tags cover
/// the `tbsCert` and `taInfo` variants of a DER-encoded RFC 5914 `TrustAnchorChoice`. Anything else
/// is offered to the PEM decoder, then to [`decode_bare_base64`] for a file that is base64 with
/// no boundaries at all; a failure there means the bytes are none of the three.
pub fn maybe_pem(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.is_empty() && matches!(bytes[0], 0x30 | 0xA1 | 0xA2) {
        return Ok(bytes.to_vec());
    }
    if let Ok((_label, der)) = pem_rfc7468::decode_vec(bytes) {
        return Ok(der);
    }
    decode_bare_base64(bytes).ok_or(Error::Unrecognized)
}

/// Returns every certificate a caller's buffer carries, in DER, whatever container it arrived in.
///
/// [`maybe_pem`] answers "what encoding is this one object in"; this answers "what certificates are
/// in this file", which is the question a trust-anchor or CA input actually asks. The two differ for
/// exactly the containers that hold more than one certificate: a certs-only PKCS#7 message (`.p7c`
/// or `.p7b`, how DoD PKE publishes cross-certificate and CA bundles) and a concatenated PEM
/// bundle. Passing either to `maybe_pem` yields well-formed DER that is not a certificate, or only
/// the first of several, and both fail quietly downstream.
///
/// Either container may itself arrive PEM-armored, and a `.p7b` is a certs-only PKCS#7 message
/// whichever of the two encodings it is written in — but only the DER spelling survives a container
/// parse applied to the bytes as they arrived. So the armored case is handed to
/// [`decode_pem_to_ders`], which is what the CLI's folder loader already reads bundles with: it
/// takes each block in turn and expands a block that is itself a certs-only message. Deferring to it
/// rather than decoding here keeps one implementation of "what objects are in this file"; it is also
/// the more forgiving decoder, which matters because some DoD and FPKI tools wrap base64 at a width
/// strict RFC 7468 rejects.
pub fn certs_in(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if let Some(certs) = certs_from_signed_data(bytes) {
        return Ok(certs);
    }
    // Bare DER is one object, already in the encoding the caller wants. Same leading tags as
    // maybe_pem, for the same reason.
    if matches!(bytes.first(), Some(0x30 | 0xA1 | 0xA2)) {
        return Ok(vec![bytes.to_vec()]);
    }
    // One object with no boundaries around it. Tried before the armor check below because that
    // check is what would otherwise refuse it: an unarmored file is not a bundle, so there is
    // nothing here for the multi-object decoder to do that the single-object one has not.
    if let Some(der) = decode_bare_base64(bytes) {
        return match certs_from_signed_data(&der) {
            Some(certs) => Ok(certs),
            None => Ok(vec![der]),
        };
    }
    // Guarded on the armor rather than left to decode_pem_to_ders, which passes unarmored bytes
    // through as a single object: bytes that are neither DER nor PEM have to stay an error here, or
    // an unreadable upload becomes a certificate-shaped nothing that fails quietly later instead.
    if !bytes.windows(ARMOR.len()).any(|w| w == ARMOR) {
        return Err(Error::Unrecognized);
    }
    decode_pem_to_ders(bytes)
}

/// The pre-encapsulation boundary, matched as the same prefix [`decode_pem_to_ders`] looks for so
/// the two cannot disagree about whether a buffer is armored.
const ARMOR: &[u8] = b"-----BEGIN";

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Encoding as _;

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

    /// The 2026-08-25 bug: DoD PKE ships its CA bundle in both spellings, and only the DER one
    /// expanded. The PEM one decoded to the container itself and passed for a single certificate,
    /// so an upload of forty-nine anchors contributed one unusable object and reported no error.
    /// The two spellings of one bundle must reduce to the same certificates.
    #[test]
    fn a_pem_armored_pkcs7_expands_like_its_der_spelling() {
        let der = include_bytes!("../../certval/tests/examples/caCertsIssuedTofbcag4.p7c");
        let pem = pem_rfc7468::encode_string("PKCS7", pem_rfc7468::LineEnding::LF, der).unwrap();

        let from_der = certs_in(der).unwrap();
        assert_eq!(6, from_der.len());
        assert_eq!(
            from_der,
            certs_in(pem.as_bytes()).unwrap(),
            "the armor is an encoding of the container, not a certificate"
        );
        assert_eq!(
            maybe_pem(pem.as_bytes()).unwrap(),
            der.to_vec(),
            "maybe_pem still hands back the container, which is what certs_in must not do"
        );
    }

    /// A concatenated PEM bundle — how DoD PKE publishes a CA chain — is several documents in one
    /// file. The single-document decoder `maybe_pem` reaches for reads one and rejects the trailing
    /// data, so the whole file was refused rather than yielding the certificates it plainly holds.
    /// The preamble is part of the case: such files are published with it.
    #[test]
    fn a_concatenated_pem_bundle_yields_every_certificate() {
        let ta = include_bytes!("../../certval/tests/examples/amazon.com/0-ta.der").to_vec();
        let ca = include_bytes!("../../certval/tests/examples/amazon.com/1.der").to_vec();
        let ee = include_bytes!("../../certval/tests/examples/amazon.com/2-target.der").to_vec();

        let armor = |der: &[u8]| {
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der).unwrap()
        };
        // Interleaved with the commentary such files are published with, which the decoder has to
        // step over rather than choke on.
        let bundle = format!(
            "subject=Amazon Root CA 1\n{}\nsubject=Amazon RSA 2048 M01\n{}\n{}",
            armor(&ta),
            armor(&ca),
            armor(&ee)
        );

        assert_eq!(vec![ta, ca, ee], certs_in(bundle.as_bytes()).unwrap());
    }

    /// A bundle may mix the two: an armored container beside a bare certificate. Each block is
    /// expanded on its own, so the result is every certificate in the file and not a count of
    /// blocks.
    #[test]
    fn blocks_are_expanded_individually_not_counted() {
        let ee = include_bytes!("../../certval/tests/examples/amazon.com/2-target.der").to_vec();
        let p7c = include_bytes!("../../certval/tests/examples/caCertsIssuedTofbcag4.p7c");

        let mixed = format!(
            "{}{}",
            pem_rfc7468::encode_string("PKCS7", pem_rfc7468::LineEnding::LF, p7c).unwrap(),
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &ee).unwrap()
        );

        let certs = certs_in(mixed.as_bytes()).unwrap();
        assert_eq!(7, certs.len(), "six from the container plus the bare one");
        assert_eq!(ee, certs[6]);
    }

    /// The multi-object decoder passes unarmored bytes through as a single object, which for an
    /// upload would turn an unreadable file into one certificate-shaped entry that fails silently
    /// somewhere else. `certs_in` has to refuse it here, where the caller still has a name to put
    /// in the message.
    #[test]
    fn an_unreadable_upload_is_an_error_not_an_object() {
        assert!(certs_in(b"").is_err());
        assert!(certs_in(b"not a certificate in any encoding").is_err());
        assert!(
            certs_in(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----")
                .is_err(),
            "armor alone does not make a file readable"
        );
        assert!(
            certs_in(b"dGhpc0lzVmFsaWRCYXNlNjRUZXh0").is_err(),
            "and accepting unarmored base64 does not admit text that merely decodes"
        );
    }

    /// The FPKI PIV/PIV-I test certificates ship as `.crt` files holding one unwrapped line of
    /// base64 with no encapsulation boundaries. Both decoders `maybe_pem` used to reach for want
    /// the armor, so twenty such targets were refused as unparseable and a run over them reported
    /// fewer paths with nothing to say why. Every spelling of one certificate must reduce to the
    /// same DER, and the wrapping width is not part of the question. Both entry points, since an
    /// unarmored file reaches whichever one the caller happens to be.
    #[test]
    fn unarmored_base64_decodes_like_the_armored_spelling() {
        use base64ct::{Base64, Encoding};
        let der = include_bytes!("../../certval/tests/examples/amazon.com/2-target.der").to_vec();
        let b64 = Base64::encode_string(&der);

        assert_eq!(
            maybe_pem(b64.as_bytes()).unwrap(),
            der,
            "one unwrapped line, as the FPKI files arrive"
        );

        assert_eq!(
            certs_in(b64.as_bytes()).unwrap(),
            vec![der.clone()],
            "and the bundle entry point agrees with the single-object one"
        );

        for width in [64, 76] {
            let wrapped: String = b64
                .as_bytes()
                .chunks(width)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                maybe_pem(wrapped.as_bytes()).unwrap(),
                der,
                "wrapped at {width}, still the same certificate"
            );
        }
    }

    #[test]
    fn neither_encoding_is_refused_rather_than_guessed() {
        assert!(maybe_pem(b"").is_err());
        assert!(maybe_pem(b"not a certificate in any encoding").is_err());
        assert!(
            maybe_pem(b"   \n\t  ").is_err(),
            "whitespace is not an empty certificate"
        );
        // Prose is often accidentally valid base64; what it is not is DER. Without the tag check on
        // the decoded bytes this becomes a certificate-shaped nothing that fails somewhere later.
        assert!(
            base64ct::Base64::decode_vec("dGhpc0lzVmFsaWRCYXNlNjRUZXh0").is_ok(),
            "the guard has to be doing the work, not the base64 decoder"
        );
        assert!(maybe_pem(b"dGhpc0lzVmFsaWRCYXNlNjRUZXh0").is_err());
    }
}

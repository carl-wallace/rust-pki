//! One corpus of real-world-broken inputs, run through both decode routes, asserting they agree.
//!
//! There are two routes into the same certval, because the two frontends arrive differently: the
//! desktop has a filesystem and reads through `get_file_as_byte_vec_pem` → [`decode_pem_to_der`]
//! (or `get_file_as_der_certs_pem` → [`decode_pem_to_ders`]), while the browser has only bytes and
//! reaches `der_or_pem` ([`maybe_pem`] / [`certs_in`]). Three times now a tolerance for real-world
//! garbage has landed on whichever route hit it first and silently not existed on the other:
//!
//! - 2026-08-20 — a PEM target validated normally while contributing nothing to the revocation
//!   harvest, so every certificate reported `undetermined` with no explanation.
//! - 2026-08-25 — a PEM-armored `.p7b`, how DoD PKE publishes its CA bundle, decoded to a
//!   well-formed SignedData and was taken for a certificate: forty-nine certificates arriving as
//!   one unusable object, and nothing said so.
//! - 2026-09-15 — a certificate file with one trailing `0x0A` parsed on the desktop and was refused
//!   in the browser, because `decode_pem_to_der` ends with a trim and `maybe_pem`'s leading-tag
//!   fast path skipped it.
//!
//! The tolerances themselves are right; none of this gets fixed upstream. What was missing is that
//! a tolerance proven on one route was unproven on the other. So the assertion here is **agreement**
//! rather than correctness alone: a row added for the next incident is checked against both routes
//! at once, and nobody has to remember that the other one exists.
//!
//! Rows are generated from clean fixtures rather than checked in as junk files, so the corpus reads
//! as a list of what the world does to a file. The exception is anything that cannot be synthesized
//! honestly — an `.ir4`, a real UTF-16 export — which belongs on disk as the artifact it is.

use base64ct::{Base64, Encoding};
use certval::{decode_pem_to_der, decode_pem_to_ders};
use pittv3_lib::der_or_pem::{certs_in, maybe_pem};

const CERT: &[u8] = include_bytes!("../../certval/tests/examples/ee.der");
const CERT2: &[u8] = include_bytes!("../../certval/tests/examples/DigiCertGlobalCAG2.der");

/// The DoD PKE cross-certificate bundle for the Federal Bridge CA G4 — the container shape an SIA
/// `caRepository` commonly serves, and the one the 2026-08-25 incident was about.
const P7C: &[u8] = include_bytes!("../../certval/tests/examples/caCertsIssuedTofbcag4.p7c");

/// Certificates carried by [`P7C`].
const P7C_CERTS: usize = 6;

// --- the ways a file arrives broken ------------------------------------------------------------

/// PEM armor at a chosen wrap width and line ending. `width` of 0 leaves the base64 on one line,
/// which is what a copy out of a browser produces.
fn armor(label: &str, der: &[u8], width: usize, crlf: bool) -> Vec<u8> {
    let nl = if crlf { "\r\n" } else { "\n" };
    let body = Base64::encode_string(der);
    let mut s = format!("-----BEGIN {label}-----{nl}");
    if width == 0 {
        s.push_str(&body);
        s.push_str(nl);
    } else {
        for chunk in body.as_bytes().chunks(width) {
            s.push_str(core::str::from_utf8(chunk).expect("base64 is ascii"));
            s.push_str(nl);
        }
    }
    s.push_str(&format!("-----END {label}-----{nl}"));
    s.into_bytes()
}

/// Base64 with no boundaries around it — what a paste of the middle of a PEM leaves behind.
fn bare_base64(der: &[u8]) -> Vec<u8> {
    Base64::encode_string(der).into_bytes()
}

fn followed_by(bytes: &[u8], slop: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.extend_from_slice(slop);
    v
}

fn preceded_by(preamble: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut v = preamble.to_vec();
    v.extend_from_slice(bytes);
    v
}

/// A PEM file written by PowerShell's `Out-File`, whose default encoding is UTF-16LE with a BOM.
fn utf16le(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for unit in String::from_utf8_lossy(bytes).encode_utf16() {
        v.extend_from_slice(&unit.to_le_bytes());
    }
    v
}

// --- one certificate ----------------------------------------------------------------------------

/// Every spelling of a single certificate that both single-object routes accept, asserted to reach
/// the identical DER. A tolerance that exists on one side and not the other shows up here as a
/// refusal rather than as a validation result nobody can explain.
#[test]
fn every_spelling_of_one_certificate_reaches_the_same_der() {
    let spellings: Vec<(&str, Vec<u8>)> = vec![
        ("bare DER", CERT.to_vec()),
        // The 2026-09-15 incident: a certificate plus the newline an editor or mail client adds.
        // Fatal rather than cosmetic -- `Certificate::from_der` rejects the whole buffer with
        // `TrailingData` rather than ignoring the extra byte.
        ("DER followed by a newline", followed_by(CERT, b"\n")),
        ("DER followed by junk", followed_by(CERT, b"\xff\x00\xaa")),
        (
            "PEM, LF, wrapped at 64",
            armor("CERTIFICATE", CERT, 64, false),
        ),
        // Windows line endings, which strict RFC 7468 refuses and the lenient fallback accepts.
        ("PEM, CRLF", armor("CERTIFICATE", CERT, 64, true)),
        // Widths other than 64 are emitted by some DoD and FPKI tools.
        ("PEM, wrapped at 76", armor("CERTIFICATE", CERT, 76, false)),
        ("PEM, unwrapped", armor("CERTIFICATE", CERT, 0, false)),
        // OpenSSL writes this label for a certificate carrying trust settings; the body still opens
        // with the certificate, so the trim is what makes it readable.
        (
            "PEM labelled TRUSTED CERTIFICATE",
            armor("TRUSTED CERTIFICATE", CERT, 64, false),
        ),
        (
            "PEM labelled X509 CERTIFICATE",
            armor("X509 CERTIFICATE", CERT, 64, false),
        ),
        ("bare base64", bare_base64(CERT)),
        (
            "bare base64 followed by a newline",
            followed_by(&bare_base64(CERT), b"\n"),
        ),
        // Notepad and PowerShell write the mark ahead of the armor; it is stripped before the
        // armor check rather than left to defeat it.
        (
            "PEM behind a UTF-8 BOM",
            preceded_by(b"\xef\xbb\xbf", &armor("CERTIFICATE", CERT, 64, false)),
        ),
    ];

    for (name, bytes) in spellings {
        let browser = maybe_pem(&bytes)
            .unwrap_or_else(|e| panic!("{name}: the browser route refused it: {e:?}"));
        let desktop = decode_pem_to_der(&bytes)
            .unwrap_or_else(|e| panic!("{name}: the desktop route refused it: {e:?}"));
        assert_eq!(
            CERT,
            browser.as_slice(),
            "{name}: browser route lost the certificate"
        );
        assert_eq!(browser, desktop, "{name}: the two routes disagree");
    }
}

// --- bundles ------------------------------------------------------------------------------------

/// The same for containers. `certs_in` and `decode_pem_to_ders` answer the same question — what
/// certificates does this file hold — so they have to answer it the same way.
#[test]
fn every_spelling_of_a_bundle_reaches_the_same_certificates() {
    let two_certs = followed_by(
        &armor("CERTIFICATE", CERT, 64, false),
        &armor("CERTIFICATE", CERT2, 64, false),
    );
    let spellings: Vec<(&str, Vec<u8>, usize)> = vec![
        ("a certs-only PKCS#7", P7C.to_vec(), P7C_CERTS),
        // The 2026-08-25 incident: both spellings of one bundle must reduce to the same set.
        (
            "a PEM-armored PKCS#7",
            armor("PKCS7", P7C, 64, false),
            P7C_CERTS,
        ),
        ("a concatenated PEM bundle", two_certs.clone(), 2),
        // Such bundles are published with commentary between the blocks, which has to be stepped
        // over rather than choked on.
        (
            "a concatenated PEM bundle with commentary",
            preceded_by(b"subject=Federal Bridge CA G4\n", &two_certs),
            2,
        ),
        ("one certificate, as a bundle of one", CERT.to_vec(), 1),
    ];

    for (name, bytes, expected) in spellings {
        let browser = certs_in(&bytes)
            .unwrap_or_else(|e| panic!("{name}: the browser route refused it: {e:?}"));
        let desktop = decode_pem_to_ders(&bytes)
            .unwrap_or_else(|e| panic!("{name}: the desktop route refused it: {e:?}"));
        assert_eq!(expected, browser.len(), "{name}: browser route");
        assert_eq!(browser, desktop, "{name}: the two routes disagree");
    }
}

// --- the deliberate difference --------------------------------------------------------------

/// Where the two routes are *meant* to differ, pinned so a change to either is deliberate.
///
/// certval's decoders are general: `decode_pem_to_der` is the CRL reader as well as the certificate
/// one, so it cannot know what error to raise and hands unrecognized bytes back for the caller's
/// own parse to reject with the message it always did. `der_or_pem` asks a narrower question — is
/// this a certificate — and so can refuse outright. Both reject; only the diagnosis differs.
#[test]
fn what_is_not_an_object_is_refused_by_the_certificate_route_and_passed_on_by_the_general_one() {
    // A 404 or captive-portal page saved where a certificate was expected. The retrieval path makes
    // this a live shape rather than a hypothetical.
    let html = b"<html><body>404 Not Found</body></html>".to_vec();
    let powershell = utf16le(&armor("CERTIFICATE", CERT, 64, false));

    for (name, bytes) in [
        ("an HTML error page", html),
        ("a PEM exported as UTF-16", powershell),
        ("an empty file", Vec::new()),
    ] {
        assert!(
            maybe_pem(&bytes).is_err(),
            "{name}: the certificate route must refuse it"
        );
        assert!(
            certs_in(&bytes).is_err(),
            "{name}: the certificate route must refuse it"
        );
        assert!(
            decode_pem_to_der(&bytes).is_ok(),
            "{name}: the general route passes bytes on for the caller to reject"
        );
    }
}

/// The other axis, and the one the incident log does not name: single-object and container decoders
/// disagree with each other about leading noise, on *both* frontends. Anything before the armor
/// defeats a check on the first byte, while the container decoders scan for the boundary anywhere.
///
/// So a file `openssl pkcs12` wrote, with its `Bag Attributes` preamble, is readable as a CA bundle
/// and unreadable as a target. Pinned as it stands rather than asserted to be right.
#[test]
fn leading_noise_is_tolerated_by_the_container_decoders_and_not_the_single_object_ones() {
    let pem = armor("CERTIFICATE", CERT, 64, false);
    for (name, bytes) in [
        ("a leading blank line", preceded_by(b"\n", &pem)),
        (
            "an openssl pkcs12 preamble",
            preceded_by(
                b"Bag Attributes\n    friendlyName: id\nsubject=CN=x\n",
                &pem,
            ),
        ),
    ] {
        assert!(
            maybe_pem(&bytes).is_err(),
            "{name}: still unread by the single-object route"
        );
        assert_eq!(
            vec![CERT.to_vec()],
            certs_in(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}")),
            "{name}: the container route steps over it"
        );
    }
}

// --- known divergences, ignored until fixed ----------------------------------------------------
//
// Each states the intended result rather than the current one, so removing the `#[ignore]` is the
// acceptance criterion for the fix rather than a second edit someone has to remember.

/// `certs_in` trims before the container check; `decode_pem_to_ders` runs `certs_from_signed_data`
/// on untrimmed bytes, that strict parse fails, and the whole SignedData comes back as though it
/// were one certificate. Six certificates arrive as one unusable object — the 2026-08-25 failure,
/// reached by the route that was not fixed.
///
/// It is silent: `file_utils.rs` fans a bundle out, the bogus object fails `from_der`, and the arm
/// that handles that is a bare `continue` with no log. The file contributes nothing and says so
/// nowhere.
#[test]
#[ignore = "known divergence: decode_pem_to_ders does not trim before the container check"]
fn a_container_with_trailing_bytes_expands_on_both_routes() {
    let bytes = followed_by(P7C, b"\n");
    assert_eq!(P7C_CERTS, certs_in(&bytes).unwrap().len());
    assert_eq!(P7C_CERTS, decode_pem_to_ders(&bytes).unwrap().len());
}

/// Same shape one branch along: after decoding bare base64, `certs_in` asks again whether the
/// result is a container and `decode_pem_to_ders` does not, so it returns the SignedData whole.
#[test]
#[ignore = "known divergence: decode_pem_to_ders does not re-check for a container after base64"]
fn a_container_in_bare_base64_expands_on_both_routes() {
    let bytes = bare_base64(P7C);
    assert_eq!(P7C_CERTS, certs_in(&bytes).unwrap().len());
    assert_eq!(P7C_CERTS, decode_pem_to_ders(&bytes).unwrap().len());
}

/// A byte-order mark was the one piece of leading noise neither route stepped over, because it is
/// glued to the `-----BEGIN` line rather than sitting on a line of its own: the block failed the
/// leading-`0x2D` check inside `decode_pem_to_der` and left by the passthrough, so the file yielded
/// one "object" that was the armor text itself.
///
/// That was worse than a refusal — the count looked right, the bytes were not a certificate, and
/// the caller dropped them at `file_utils.rs` through an arm with no log. Notepad and PowerShell
/// both write this file. Fixed 2026-09-16 by stripping the mark ahead of the armor check.
#[test]
fn a_byte_order_mark_does_not_hide_the_certificate() {
    let bytes = preceded_by(b"\xef\xbb\xbf", &armor("CERTIFICATE", CERT, 64, false));
    assert_eq!(vec![CERT.to_vec()], certs_in(&bytes).unwrap());
    assert_eq!(vec![CERT.to_vec()], decode_pem_to_ders(&bytes).unwrap());
}

/// Not a divergence — both routes agree, and both are wrong. A file holding two DER objects back to
/// back comes back as one: the trim truncates to the first and the rest is dropped with no error.
/// The plural decoder can split PEM blocks and PKCS#7 containers but not concatenated DER.
///
/// Worth knowing how it got here: before the trim the same input came back whole and failed the
/// caller's parse, so nothing loaded. Now object one parses cleanly and the rest vanishes, which
/// looks like success. Neither reported anything; the shape changed from "nothing" to "partial".
#[test]
#[ignore = "known gap: concatenated bare DER is truncated to its first object on both routes"]
fn concatenated_bare_der_yields_every_object() {
    let bytes = followed_by(CERT, CERT2);
    assert_eq!(2, certs_in(&bytes).unwrap().len());
    assert_eq!(2, decode_pem_to_ders(&bytes).unwrap().len());
}

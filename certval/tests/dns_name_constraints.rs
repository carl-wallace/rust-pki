//! dNSName name constraints against a wildcard leaf.
//!
//! RFC 5280 4.2.1.10 matches dNSName constraints lexically: a subtree matches a presented name when
//! it is a suffix of it on label boundaries. `*` is not special there -- it is simply a label -- so
//! a leaf presenting `*.example.com` is **not** within an excluded subtree of `foo.example.com` and
//! the path validates, while a leaf presenting the literal `foo.example.com` is within it and is
//! rejected.
//!
//! That gap is worth pinning because it is counterintuitive and easy to "fix" into a spec deviation:
//! under RFC 9525 the same wildcard *does* match the reference identity `foo.example.com` when a TLS
//! client checks it, so the certificate an issuer meant to exclude can still be presented for that
//! name. Path validation is not the layer that closes this, and it should not pretend to. What
//! certval does do is record the excluded subtree it processed, so a caller can surface the
//! constraint the wildcard slips past.
//!
//! The fixtures are an ECDSA (P-256) chain: a root, an intermediate asserting
//! `nameConstraints = critical, excluded; DNS:foo.example.com`, and two end entities differing only
//! in the dNSName they present.
#![cfg(feature = "std")]

use certval::environment::pki_environment::PkiEnvironment;
use certval::path_settings::*;
use certval::validator::path_validator::*;
use certval::*;

// 2027-01-01T00:00:00Z, within every fixture's validity window (EEs: 2026-07-06 .. 2027-08-07),
// pinned so the test does not become time-dependent as the fixtures approach expiry.
const TOI: u64 = 1_798_761_600;

const ROOT: &[u8] = include_bytes!("examples/dns_name_constraints/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("examples/dns_name_constraints/intermediate.der");

/// Builds the Root -> Intermediate -> EE path and runs RFC 5280 validation at the pinned time of
/// interest, returning the result and the results object so callers can inspect recorded state.
fn validate(der_ee: &[u8]) -> (certval::Result<()>, CertificationPathResults) {
    let mut ta = PDVTrustAnchorChoice::try_from(ROOT).unwrap();
    ta.parse_extensions(EXTS_OF_INTEREST);

    let mut ta_source = TaSource::new();
    ta_source.push(CertFile {
        filename: "root.der".to_string(),
        bytes: ROOT.to_vec(),
    });
    ta_source.initialize().unwrap();

    let mut ca = PDVCertificate::try_from(INTERMEDIATE).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_ee).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_source));

    let mut cert_path = CertificationPath::new(ta, vec![ca], ee);
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    let mut cpr = CertificationPathResults::new();
    let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
    (r, cpr)
}

#[test]
fn wildcard_leaf_is_not_within_an_excluded_dns_subtree() {
    let ee = include_bytes!("examples/dns_name_constraints/ee-wildcard.der");
    let (r, cpr) = validate(ee);
    assert!(
        r.is_ok(),
        "*.example.com is lexically outside excluded foo.example.com"
    );

    // The excluded subtree the path was validated against is recorded even though nothing was
    // excluded by it, which is what lets a frontend show the constraint the wildcard slips past.
    let excluded = cpr
        .get_final_excluded_subtrees()
        .expect("excluded subtrees recorded on success");
    let excluded = name_constraints_set_to_name_constraints_settings(&excluded).unwrap();
    assert_eq!(
        excluded.dns_name,
        Some(vec!["foo.example.com".to_string()]),
        "terminal excluded set should carry the intermediate's excluded dNSName"
    );
}

#[test]
fn literal_leaf_is_rejected_by_the_excluded_dns_subtree() {
    // The control that gives the case above its meaning: without this, a passing wildcard could just
    // as easily mean the constraint was never enforced at all.
    let ee = include_bytes!("examples/dns_name_constraints/ee-literal.der");
    let (r, cpr) = validate(ee);
    assert_eq!(
        r.err(),
        Some(Error::PathValidation(
            PathValidationStatus::NameConstraintsViolation
        )),
        "literal foo.example.com is within the excluded subtree"
    );
    // A name-constraints failure returns before the terminal state is recorded.
    assert!(cpr.get_final_permitted_subtrees().is_none());
    assert!(cpr.get_final_excluded_subtrees().is_none());
}

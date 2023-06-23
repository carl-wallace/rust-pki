//! OID and type for the PivNaciIndicator indicate type in FIPS 201-2 Appendix B

use const_oid::ObjectIdentifier;

/// OID for PIV NACI extension: 2.16.840.1.101.3.6.9.1. See [`PivNaciIndicator`](type.PivNaciIndicator.html).
pub const PIV_NACI_INDICATOR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.6.9.1");

/// NACI-indicator as defined in [FIPS 201-2 Appendix B].
///
/// This extension is identified by the [`PIV_NACI_INDICATOR`](constant.PIV_NACI_INDICATOR.html) OID.
///
/// ```text
/// NACI-indicator ::= BOOLEAN
/// ```
///
/// [FIPS 201-2 Appendix B]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-2.pdf
pub type PivNaciIndicator = bool;
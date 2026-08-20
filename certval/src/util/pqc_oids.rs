//! OIDs for PQC algorithms as captured here: <https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md>
//! ML-DSA and SLH-DSA object identifiers are relative to the `sigAlgs` arc as defined in the [NIST CSOR].
//!
//! ```text
//!    nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
//!      country(16) us(840) organization(1) gov(101) csor(3) 4 }
//!
//!    sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }
//! ```
//! [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
#![cfg(feature = "pqc")]
#![allow(missing_docs)]

use const_oid::ObjectIdentifier;
use hex_literal::hex;

// HACKATHON OIDs (NON-STANDARD - DO NOT USE)
// These are the OQS/open-quantum-safe OID assignments for the NIST round-3 Falcon
// finalist. The `PADDED` variants denote the fixed-length ("padded") signature
// encoding; the non-padded variants use the variable-length compressed encoding.
// FN-DSA (the FIPS name for standardized Falcon) has no published OID yet.
/// Falcon-512                    1.3.9999.3.6*
pub const OQ_FALCON_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.6");

/// Falcon-1024                    1.3.9999.3.9*
pub const OQ_FALCON_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.9");

/// Falcon-padded-512             1.3.9999.3.11*
pub const OQ_FALCON_PADDED_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.11");

/// Falcon-padded-1024            1.3.9999.3.14*
pub const OQ_FALCON_PADDED_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.14");

//---------------------------------------------------------------------
// Definitions are from [draft-ietf-lamps-pq-composite-kem-08](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-08)
// and [draft-ietf-lamps-pq-composite-sigs-12](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-12).
//---------------------------------------------------------------------
pub const ID_MLKEM768_RSA2048_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.55");
pub const ID_MLKEM768_RSA3072_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.56");
pub const ID_MLKEM768_RSA4096_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.57");
pub const ID_MLKEM768_X25519_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.58");
pub const ID_MLKEM768_ECDH_P256_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.59");
pub const ID_MLKEM768_ECDH_P384_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.60");
pub const ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.61");
pub const ID_MLKEM1024_RSA3072_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.62");
pub const ID_MLKEM1024_ECDH_P384_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.63");
pub const ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.64");
pub const ID_MLKEM1024_X448_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.65");
pub const ID_MLKEM1024_ECDH_P521_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.66");

pub const DS_MLKEM768_RSA2048_SHA3_256: &[u8; 20] = b"MLKEM768-RSAOAEP2048";
pub const DS_MLKEM768_RSA3072_SHA3_256: &[u8; 20] = b"MLKEM768-RSAOAEP3072";
pub const DS_MLKEM768_RSA4096_SHA3_256: &[u8; 20] = b"MLKEM768-RSAOAEP4096";
pub const DS_MLKEM768_X25519_SHA3_256: &[u8; 6] = &hex!("5C2E2F2F5E5C"); // \.//^\
pub const DS_MLKEM768_ECDH_P256_SHA3_256: &[u8; 13] = b"MLKEM768-P256";
pub const DS_MLKEM768_ECDH_P384_SHA3_256: &[u8; 13] = b"MLKEM768-P384";
pub const DS_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256: &[u8; 14] = b"MLKEM768-BP256";
pub const DS_MLKEM1024_RSA3072_SHA3_256: &[u8; 21] = b"MLKEM1024-RSAOAEP3072";
pub const DS_MLKEM1024_ECDH_P384_SHA3_256: &[u8; 14] = b"MLKEM1024-P384";
pub const DS_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256: &[u8; 15] = b"MLKEM1024-BP384";
pub const DS_MLKEM1024_X448_SHA3_256: &[u8; 14] = b"MLKEM1024-X448";
pub const DS_MLKEM1024_ECDH_P521_SHA3_256: &[u8; 14] = b"MLKEM1024-P521";

pub const ID_MLDSA44_RSA2048_PSS_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.37");
pub const ID_MLDSA44_RSA2048_PKCS15_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.38");
pub const ID_MLDSA44_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.39");
pub const ID_MLDSA44_ECDSA_P256_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.40");
pub const ID_MLDSA65_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.41");
pub const ID_MLDSA65_RSA3072_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.42");
pub const ID_MLDSA65_RSA4096_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.43");
pub const ID_MLDSA65_RSA4096_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.44");
pub const ID_MLDSA65_ECDSA_P256_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.45");
pub const ID_MLDSA65_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.46");
pub const ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.47");
pub const ID_MLDSA65_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.48");
pub const ID_MLDSA87_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.49");
pub const ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.50");
pub const ID_MLDSA87_ED448_SHAKE256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.51");
pub const ID_MLDSA87_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.52");
pub const ID_MLDSA87_RSA4096_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.53");
pub const ID_MLDSA87_ECDSA_P521_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.54");

pub const DS_MLDSA44_RSA2048_PSS_SHA256: &[u8; 34] = b"COMPSIG-MLDSA44-RSA2048-PSS-SHA256";
pub const DS_MLDSA44_RSA2048_PKCS15_SHA256: &[u8; 37] = b"COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256";
pub const DS_MLDSA44_ED25519_SHA512: &[u8; 30] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
pub const DS_MLDSA44_ECDSA_P256_SHA256: &[u8; 33] = b"COMPSIG-MLDSA44-ECDSA-P256-SHA256";
pub const DS_MLDSA65_RSA3072_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA65-RSA3072-PSS-SHA512";
pub const DS_MLDSA65_RSA3072_PKCS15_SHA512: &[u8; 37] = b"COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512";
pub const DS_MLDSA65_RSA4096_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA65-RSA4096-PSS-SHA512";
pub const DS_MLDSA65_RSA4096_PKCS15_SHA512: &[u8; 37] = b"COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512";
pub const DS_MLDSA65_ECDSA_P256_SHA512: &[u8; 33] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";
pub const DS_MLDSA65_ECDSA_P384_SHA512: &[u8; 33] = b"COMPSIG-MLDSA65-ECDSA-P384-SHA512";
pub const DS_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: &[u8; 34] =
    b"COMPSIG-MLDSA65-ECDSA-BP256-SHA512";
pub const DS_MLDSA65_ED25519_SHA512: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
pub const DS_MLDSA87_ECDSA_P384_SHA512: &[u8; 33] = b"COMPSIG-MLDSA87-ECDSA-P384-SHA512";
pub const DS_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: &[u8; 34] =
    b"COMPSIG-MLDSA87-ECDSA-BP384-SHA512";
pub const DS_MLDSA87_ED448_SHAKE256: &[u8; 30] = b"COMPSIG-MLDSA87-Ed448-SHAKE256";
pub const DS_MLDSA87_RSA3072_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA87-RSA3072-PSS-SHA512";
pub const DS_MLDSA87_RSA4096_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA87-RSA4096-PSS-SHA512";
pub const DS_MLDSA87_ECDSA_P521_SHA512: &[u8; 33] = b"COMPSIG-MLDSA87-ECDSA-P521-SHA512";

//! Provides definitions of OIDs from PKIXAlgs-2009 and PKIX1-PSS-OAEP-Algorithms-2009

use der::asn1::ObjectIdentifier;

// -------------------------------------------------------------------------------------------------
// OIDs from PKIXAlgs-2009
// -------------------------------------------------------------------------------------------------

/// rsaEncryption OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
///     pkcs-1(1) 1 }
pub const PKIXALG_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");

/// id-ecPublicKey OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
pub const PKIXALG_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");

/// id-ecDH OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) schemes(1)
///     ecdh(12) }
pub const PKIXALG_DH: ObjectIdentifier = ObjectIdentifier::new("1.3.132.1.12");

/// secp192r1 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
///     prime(1) 1 }
pub const PKIXALG_SECP192R1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.1");

/// sect163k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 1 }
pub const PKIXALG_SECP163K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.1");

///    sect163r2 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 15 }
pub const PKIXALG_SECP163R2: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.15");

///    secp224r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 33 }
pub const PKIXALG_SECP224R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.33");

///    sect233k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 26 }
pub const PKIXALG_SECP233K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.26");

///    sect233r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 27 }
pub const PKIXALG_SECP233R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.27");

///    secp256r1 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
///     prime(1) 7 }
pub const PKIXALG_SECP256R1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");

///    sect283k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 16 }
pub const PKIXALG_SECP283K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.16");

///    sect283r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 17 }
pub const PKIXALG_SECP283R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.17");

///    secp384r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 34 }
pub const PKIXALG_SECP384R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");

///    sect409k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 36 }
pub const PKIXALG_SECP409K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.36");

///    sect409r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 37 }
pub const PKIXALG_SECP409R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.37");

///    secp521r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 35 }
pub const PKIXALG_SECP521R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.35");

///    sect571k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 38 }
pub const PKIXALG_SECP571K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.38");

///    sect571r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 39 }
pub const PKIXALG_SECP571R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.39");

/// ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 1 }
pub const PKIXALG_ECDSA_WITH_SHA224: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.1");

/// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 2 }
pub const PKIXALG_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 3 }
pub const PKIXALG_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.3");

/// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 4 }
pub const PKIXALG_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.4");

// -------------------------------------------------------------------------------------------------
// OIDs from PKIX1-PSS-OAEP-Algorithms-2009
// -------------------------------------------------------------------------------------------------
//    pkcs-1  OBJECT IDENTIFIER  ::=
//        { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }

/// sha224WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 14 }
pub const PKIXALG_SHA224_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.14");

/// sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }
pub const PKIXALG_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.11");

/// sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 12 }
pub const PKIXALG_SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.12");

/// sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 13 }
pub const PKIXALG_SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.13");

/// id-RSAES-OAEP  OBJECT IDENTIFIER  ::=  { pkcs-1 7 }
pub const PKIXALG_RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.7");

/// id-pSpecified  OBJECT IDENTIFIER  ::=  { pkcs-1 9 }
pub const PKIXALG_PSPECIFIED: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.9");

/// id-mgf1  OBJECT IDENTIFIER  ::=  { pkcs-1 8 }
pub const PKIXALG_MGF1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.8");

/// id-RSASSA-PSS  OBJECT IDENTIFIER  ::=  { pkcs-1 10 }
pub const PKIXALG_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.10");

/// id-sha224  OBJECT IDENTIFIER  ::=
///     { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///     csor(3) algorithms(4) hashalgs(2) 4 }
pub const PKIXALG_SHA224: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.4");

/// id-sha256  OBJECT IDENTIFIER  ::=
///        { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///        csor(3) algorithms(4) hashalgs(2) 1 }
pub const PKIXALG_SHA256: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.1");

/// id-sha384  OBJECT IDENTIFIER  ::=
///        { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///        csor(3) algorithms(4) hashalgs(2) 2 }
pub const PKIXALG_SHA384: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.2");

/// id-sha512  OBJECT IDENTIFIER  ::=
///        { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///        csor(3) algorithms(4) hashalgs(2) 3 }
pub const PKIXALG_SHA512: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.3");

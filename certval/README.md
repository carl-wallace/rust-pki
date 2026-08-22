# certval

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

Pure Rust implementation of X.509 public key infrastructure certification path validation algorithm described in [RFC 5280] as 
as augmented by [RFC 5937]. Support for certification path building and revocation status determination is also included. 

ASN.1 encoders and decoders and cryptographic support are primarily provided by various [RustCrypto] libraries.

A change log is available at the root of the `certval` project.

## Crate Feature Flags

The certval library provides seven feature gates that enable varying levels of support.

- `default-features = false` provides path validation support for no-std applications without support for revocation status determination or multi-thread support. Certificates and partial paths can be provided via a CBOR file, providing rich certification path development support for environments in which new CAs are introduced infrequently.
- `revocation` augments the `default-features = false` feature by adding support for processing CRLs and OCSP responses that are provided by the caller, such as may have been obtained by stapling to a higher level protocol.
- `std` augments the `default-features = false` feature by adding support for obtaining artifacts via the file system and addition of support for multi-threaded use.
- `revocation,std` augments the `std` feature by adding support for processing CRLs and OCSP responses that are provided by the caller or obtained via the file system.
- `remote` is enabled by default (the default feature set is `remote` plus `webpki`). It replaces and augments the `revocation,std` features by adding support for retrieving certificates via URIs expressed in SIA and AIA extensions, for retrieving CRLs via URIs expressed in CRL DP extensions, and for interacting with OCSP responders via URIs expressed in AIA extensions.
- `pqc` adds support for ML-DSA (FIPS 204), including the hash-ML-DSA-with-SHA-512 variants, and SLH-DSA (FIPS 205), using the [ml-dsa](https://crates.io/crates/ml-dsa) and [slh-dsa](https://crates.io/crates/slh-dsa) implementations, plus composite ML-DSA signatures. Object identifiers for the standardized algorithms come from `const_oid`'s FIPS 204 and FIPS 205 tables; the composite and pre-standardization identifiers are declared in certval's own `pqc_oids` module.
- `webpki` adds support for instantiating TaSource instances using trust anchors from the [webpki-roots](https://crates.io/crates/webpki-roots) crate
- `rsa` enables use of the RSA algorithm. RSA support is not enabled by default.
- `eddsa` enables use of the Ed25519 algorithm. Ed25519 support is not enabled by default.

## Sample Usage

The suite of [PITTv3](../pittv3/index.html) applications uses the `certval` library and can serve as sample code for usage in command
line, desktop, and WASM contexts.

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited.

It has been tested against the following test suites, both of which run in CI:

- **x509-limbo** — 9,737 cases, of which 9,698 reach the expected result: **99.60%**. The 39
  mismatches fall in two namespaces, `webpki::` (22) and `rfc5280::` (17); every other namespace is
  clean, `cve::` included. The `webpki::` cases are Web PKI-specific behavior this crate does not
  implement, being a path validator rather than a TLS verifier; the `rfc5280::` ones remain to be
  triaged. The harness is `support/x509-limbo-tests`, and CI regenerates its results file and fails
  on any diff, so a change in conformance cannot land unremarked.
- **NIST PKITS** — sections 4.1 through 4.14 and 4.16, in seventeen editions: the original RSA-2048
  material, a P-256 re-issue, and fifteen post-quantum re-issues (ML-DSA-44/65/87 and twelve SLH-DSA
  parameter sets). Editions that carry no CRLs skip the revocation cases (§4.4, plus seven named
  cases in §4.7 and §4.14); the harness asserts that every case it did not explicitly skip reached
  the end of validation, so a run cannot quietly no-op.

Neither suite is a substitute for an audit.

## Minimum Supported Rust Version (MSRV) Policy

This crate requires **Rust 1.85** at a minimum.

MSRV increases are not considered breaking changes and can happen in patch releases.

The crate MSRV accounts for all supported targets and crate feature combinations, excluding
explicitly unstable features.

## License

All crates licensed under either of the following, at your option:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[RFC 5937]: https://datatracker.ietf.org/doc/html/rfc5937

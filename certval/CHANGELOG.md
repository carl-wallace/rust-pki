# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

*The 0.1.x entries below describe an unpublished library as it stood at each of those dates,
and are retained as history. None was published to crates.io. For what the crate does now,
see the most recent entry.*

## [0.1.0] - 2022-01-30 

Initial release including basic path building and validation support.

## [0.1.1] - 2022-03-31

### Added
- Added initial support for determining revocation status via CRLs.
- Added initial support for determining revocation status via OCSP.
- Added set of five feature gates to offer varying levels of support, from no-std environment 
with path validation support only up through environment with std support, dynamic path building support, 
and revocation status determination support.
- Added test cases. Code coverage across certval and pittv3 (including use of some manually executed tests to augment test
cases in the repo) is roughly 90%.

### Changes
- Improved logging output.
- Reorganized library into set of six cooperating modules.
- Refactored PkiEnvironment and associated trait objects so the Sync trait is automatically derived.
- Added support for serializing/deserializing CertificationPathSettings objects. Decoupled CertificationPathSettings and
CertificationPathResults and added proc macros to generate getters/setters for CertificationPathResults.
- Aligned with changes to Rust Crypto formats library.

## [0.1.2] - 2023-01-24

- Aligned with significant changes to the formats repo, i.e., change from no-copy to owned types.
- Add PQC support with associated pqc feature flag to turn off/on.
- Modify or temporarily comment out test cases due to artifact expiration.

## [0.1.3] - 2023-07-28

- Use log macros directly, instead of a through a wrapper. The log crate is no longer optional.
- Continued move towards using owned types. Refactored some trait implementations and added new CertVector trait in support of this. Eliminated CertificationPathBuilder trait and moved get_paths_for_target to CertificateSource. CertSource and TaSource fields are no longer public.
- Implemented support for [draft-ietf-lamps-x509-policy-graph-01](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-x509-policy-graph-01) as an optional policy processing implementation.
- Added a few TryFrom implementations to simplify creation of PDVTrustAnchorChoice and PDVCertificate instances.
- Added webpki feature to allow instantiating TaSource instance using trust anchors from the [webpki-roots](https://crates.io/crates/webpki-roots) crate.

## [0.2.0] - unreleased

First published release. Versions 0.1.0 through 0.1.4 were used internally and never published to
crates.io; the entries above are retained as history. This entry describes what the library is
rather than how it changed — the commit history covers the latter.

### What certval does

Certification path building and validation for X.509 public key infrastructure, per **RFC 5280** as
augmented by **RFC 5937**, with certificate policy processing following the graph-based algorithm of
**RFC 9618**. Trust anchors may be certificates or **RFC 5914** `TrustAnchorInfo` values, so anchors
carrying constraints are honored as such. The library is `no_std`-capable at its core, with file
system, threading and network support layered on by feature.

### Feature gates

Nine, from a `no_std` core outward: `revocation` (CRL and OCSP processing for artifacts the caller
supplies), `std` (file system and multi-threaded use), `remote` (retrieval over the network, the
default alongside `webpki`), `pqc`, `webpki`, `capi`, `rsa`, `eddsa` and `sha1_sig`. RSA and Ed25519
are off by default; a build takes only the algorithms it intends to trust. `sha1_sig` admits
sha1WithRSAEncryption signatures, for certificates still in service that carry them.

### Trust anchor and certificate sources

Trust anchors and intermediate CA certificates load from folders or individual files, DER or PEM,
including PEM files holding several concatenated objects. A **CBOR store** serializes a set of CA
certificates together with the partial paths already computed for them, so a PKI is indexed once and
validated against thereafter — the arrangement that makes path building practical in an environment
with no file system or network. Anchors from the `webpki-roots` crate can instantiate a source
directly. On Windows, the `capi` feature reads Microsoft CryptoAPI system certificate stores into a
`TaSource` or `CertSource`, and offers a `CertVector` that writes back to one. Trust anchor
collisions are detected rather than silently resolved.

### Revocation

CRLs and OCSP, from whatever the deployment can reach: a folder of CRLs indexed for lookup, an
in-memory cache of CRLs already verified, artifacts stapled in by the caller, and responders queried
over the network. OCSP requests carry a nonce (**RFC 8954**), responses are tolerated a modest clock
skew so an on-demand responder is not read as answering from the future, and a responder certificate
without a `no-check` extension is itself checked. `PS_REVOCATION_MAX_AGE` bounds any artifact that
omits an explicit freshness field. Results record which mechanism settled each certificate rather
than leaving it to be inferred.

### Cryptography

Signature verification and hashing are supplied to the library as traits, so a deployment can route
them anywhere — including a hardware module: `certval-pkcs11` does exactly this. Blanket
implementations mean a plain closure still works. An optional cache avoids repeating verifications
within a run. Supported: RSA (PKCS#1 v1.5 and RSASSA-PSS), ECDSA over P-256/384/521, Ed25519, and
post-quantum **ML-DSA** (FIPS 204, including Hash ML-DSA) and **SLH-DSA** (FIPS 205, including the
pre-hash variants), plus composite ML-DSA.

### Name constraints

Directory names, `dNSName`, `rfc822Name` in its mailbox, host and domain forms, URIs, IP address
ranges, and user principal names — the URI and directory name forms implemented without pulling in
`url` or `regex`, so they hold in `no_std` builds too.

### Results

Validation produces a structured result rather than a verdict and a log: the index of the
certificate that failed, the terminal explicit-policy, policy-mapping and inhibit-anyPolicy state,
the terminal name constraints, which revocation source answered, and the certificates and CRLs
involved. The status type serializes, so a caller can carry it across a process boundary — which is
how the PITTv3 browser and service frontends report.

### Hardening

Malformed input returns errors rather than panicking, including at the CBOR store boundary. Ceilings
bound the certificate store, the certificate policy pool and path length, so retrieval driven by a
certificate's own extensions cannot be made unbounded by that certificate.

### Conformance

Measured, not asserted, and both suites run in CI: **x509-limbo** at 99.60% (9,737 cases, 39
mismatches, confined to the `webpki::` and `rfc5280::` namespaces), and the NIST **PKITS** suite,
sections 4.1–4.14 and 4.16, run in seventeen editions — the original RSA-2048 material, a P-256
re-issue, and fifteen post-quantum re-issues.

### Deliberate limitations

- **Delta CRLs are not supported.** They are not indexed and not considered; a scope requiring one
  fails closed rather than being approximated.
- **FN-DSA is not verified**, pending a FIPS 206 implementation. The identifiers are declared; the
  verification is not.
- **This is not a TLS verifier.** Web PKI-specific behavior is out of scope by design, which is what
  the `webpki::` x509-limbo mismatches above record.

### Minimum supported Rust version

**1.85.** MSRV increases are not considered breaking changes and can happen in patch releases,
matching the policy of the RustCrypto crates this library is built on.

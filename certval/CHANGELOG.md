# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2022-01-30 

Initial release including basic path building and validation support.

## [0.1.1] - 2022-03-31

### Added
- Added initial support for determining revocation status via CRLs. At present, there is no support
for using CA key rollover certificates or designated CRL signing certificates to validate CRLs (i.e., 
the key used to verify a certificate must be the same as used to verify the CRL). Support for CA key 
rollover certificates will be added. Additionally, there is no support for delta CRLs or indirect CRLs. 
Support for these is unlikely to be added.
- Added initial support for determining revocation status via OCSP. At present, there is no support for 
using CA key rollover certificates to validate OCSP responses or responder certificates (i.e., the key 
used to verify a certificate must be the same as used to verify the response or OCSP responder certificate). 
Support for CA key rollover certificates will be added. Similarly, there is no support locally authorized
responders, i.e., responses must be signed by the CA or a responder delegated by the CA. Support for locally
authorized responders is unlikely to be added. There is currently no support for using nonces. This will 
likely be added.
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

### Known issues
- As noted above, CA key rollover certificates cannot be used to verify CRLs, OCSP responses or OCSP responder certificates at present.
- P384 signatures do not verify. This will be resolved when p384 support in the [Rust Crypto Elliptic Curves](https://github.com/RustCrypto/elliptic-curves) crate is complete
- CRL store hygiene is poor.
- Name constraints support is incomplete, i.e., no support for IP addresses and UPNs, minimally.
- Error::Unrecognized more or less signifies spots where error handling needs improvement.
- Certificate indexing should be handled by CertificateSource, not the caller. Lifetime and reference issues complicate this.
- Partial support for last modified times and blocklists needs to be completed. Blocklists may be better expressed as host names.
- Support for using CRLs relative to a grace period is not yet in place.
- Support for using OCSP nonces is not yet in place.
- The metadata field in the various PDV*** structures should either be dropped or changed to use interior mutability to 
provide means to store more than just a filename, i.e., storing the results of self-signed certificate check, key ID of 
key that verifies the certificate, etc.
- Some relatively common certificates will not parse due to strictness of the ASN.1 encoders and decoders. Known issues
include negative serial numbers, out of order set elements in multi-valued RDNs, and names containing TeletexString values.
These may or may not be addressed.
- Top level API should be wrapped or refactored for easier use. Non-idiomatic code should be replaced with idiomatic code.

## [0.1.2] - 2023-01-24

- Aligned with significant changes to the formats repo, i.e., change from no-copy to owned types.
- Add PQC support with associated pqc feature flag to turn off/on.
- Modify or temporarily comment out test cases due to artifact expiration.
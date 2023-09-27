# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2022-01-30

Initial release including basic path building and validation support.

## [0.1.1] - 2022-03-31

### Added
- Added set of six feature gates to offer varying levels of support, from no-std environment with path validation support 
only up through environment with std support, dynamic path building support, and revocation status determination support. 
These match the feature gates in the certval library with one additional feature gate that allows the app to have std 
support while library is no-std.
- Added support for using serialized CertificationPathSettings objects.
- Added support for parsing CSV files downloaded from [Non-revoked, non-expired Intermediate CA Certificates chaining up to roots in Mozilla's program with the Websites trust bit set](https://ccadb-public.secure.force.com/mozilla/MozillaIntermediateCertsCSVReport) 
on Mozilla's [CA/Intermediate Certificates wiki](https://wiki.mozilla.org/CA/Intermediate_Certificates). Certificates are saved
to a folder that may be subsequently used to generate a CBOR file containing buffers and partial paths. 
- Added test cases. Code coverage across certval and pittv3 (including use of some manually executed tests to augment test 
cases in the repo) is roughly 90%.

### Changes
- Moved large chunks of code from PITTv3 into certval.
- Dropped the tls_eku flag since richer extended key usage support is in place.
- Aligned with changes to the certval library and the Rust Crypto formats libraries.

### Known issues
- Path validation for no-std lacks support for DNS, RFC822 and URI name constraints (owing to lack of no-std regex and URI parsing support at present).
- Dynamic building is primilarly implemented in PITTv3. This will likely move to certval at some point in the future.
- The OCSP client does not yet support use of nonces.

## [0.1.2] - 2023-01-24

- Aligned with significant changes to the formats repo, i.e., change from no-copy to owned types.
- Add PQC support with associated pqc feature flag to turn off/on.
- Modify or temporarily comment out test cases due to artifact expiration.

## [0.1.3] - 2023-07-28

- Align with certval changes
- Cleanup use of cfg-if
- Remove some no-longer-necessary clap code used to display help information
- Added webpki feature to allow instantiating TaSource instance using trust anchors from the [webpki-roots](https://crates.io/crates/webpki-roots) crate.

## [0.1.4] - 2023-09-30

- Refactored the pittv3 crate to move command line utility to the new pittv3-cli crate (i.e., this crate) with supporting 
code moved to pittv3-lib. This alignment allows a command line utility and a GUI utility to share the same undercarriage
and better allows parts to be reused from a WASM context. 
- Created new Pittv3CliArgs that uses [clap](https://crates.io/crates/clap) to solicit options via the command line. A TryInto was added to converted this 
structure to Pittv3Args, which in addition to being used by the GUI app is also used by a WASM client. The WASM client does 
not sustain building the `clap` dependency.
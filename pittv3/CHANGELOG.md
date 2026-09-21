# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

*The 0.1.x entries below describe the tool as it stood at each of those dates, and are retained
as history. For what PITTv3 does now, see the most recent entry.*

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

## [0.1.2] - 2023-01-24

- Aligned with significant changes to the formats repo, i.e., change from no-copy to owned types.
- Add PQC support with associated pqc feature flag to turn off/on.
- Modify or temporarily comment out test cases due to artifact expiration.

## [0.1.3] - 2023-07-28

- Align with certval changes
- Cleanup use of cfg-if
- Remove some no-longer-necessary clap code used to display help information
- Added webpki feature to allow instantiating TaSource instance using trust anchors from the [webpki-roots](https://crates.io/crates/webpki-roots) crate.

## [0.2.0] - unreleased

A summary of PITTv3's capabilities as of this release.

### Interfaces

PITTv3 is no longer only a command line tool. The same validation code is reached five ways, differing in what must be 
installed and what transits the network:

- **Command line** — `pittv3`, the original interface, installed locally and with full network-driven path building 
  and revocation status determination capabilities.
- **Desktop** — similar to the **Command line** but with a graphical interface that includes a store selector, settings editor and
  results panel.
- **Browser** — a WASM application that runs in a web browser and requires no network to validate certificates supplied 
  by the user. Hosted at <https://pittv3.redhoundsoftware.com>, so no local installation is required.
- **Browser with a relay** — similar to **Browser** but uses an optional same-origin service capable of retrieving 
  artifacts on its behalf, so URIs and OCSP requests leave the browser but end-entity certificates do not.
- **Service API** — server-side validation for a caller that would rather send certificates for remote processing instead
  of fetching artifacts directly.

### Inputs

- Trust anchors and CA certificates are accepted as a folder or a single file, in DER or PEM,
  including containers that hold more than one: a concatenated PEM file, or a certs-only PKCS#7
  message (`.p7c` or `.p7b`, how DoD PKE publishes its CA and cross-certificate bundles). Either
  container may itself arrive PEM-armored.
- DoD **InstallRoot** streams are accepted as trust anchor or CA inputs.
- **CBOR stores** are both an input and an output: `--cbor` for CA certificates and partial paths,
  `--ta-cbor` for trust anchors, and `--generate --cbor-ta-store` to write one. A store built once
  is reused, so paths already calculated are not recalculated.
- Trust anchors may come from the **webpki-roots** crate (`--webpki-tas`), and the GUIs offer
  built-in stores — U.S. DoD NIPR production and operational test (JITC), DoD ECA, the Purebred
  development environment, the U.S. Federal PKI, and the Mozilla root program in TLS, S/MIME and
  combined forms — each exportable to disk.
- On Windows, Microsoft CryptoAPI certificate stores are a source in their own right: `--capi-ta`,
  `--capi-ca` and `--capi-ca-rw`, with the desktop selector offering the user and machine stores.
  The store is live rather than a snapshot, so a certificate installed after selection is seen.
- Web PKI intermediates can be loaded from Mozilla's CCADB CSV export (`--mozilla-csv`).
- Path validation inputs — the initial policy set, the policy indicators, name constraint subtrees,
  the time of interest — are supplied as a JSON settings file (`--settings`), shared by every
  interface.

### Validation

- RFC 5280 path validation augmented by RFC 5937, with graph-based certificate policy processing
  per RFC 9618.
- **Post-quantum signatures** are validated: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), alongside
  RSA, ECDSA and Ed25519.
- Paths are built from a store, or dynamically by chasing AIA and SIA URIs (`--dynamic-build`), or
  both. `--validate-all` exercises every path to a target rather than stopping at the first that
  validates.
- Revocation status from CRLs and OCSP: a CRL folder that is indexed and reused
  (`--crl-folder`), an in-memory cache of verified CRLs (`--keep-crl-entries-in-memory`), artifacts
  supplied by the caller, and responders reached over the network. Each interface can turn fetching
  off.
- `--validate-self-signed` answers the narrower question of whether one certificate is self-signed.

### Diagnostics

- `--check-uris` reports per-URI reachability and correctness for the AIA, SIA, CRL DP and
  freshest-CRL extensions of one certificate, independently of path processing and with no store
  required; the issuer is discovered from AIA caIssuers or supplied with `--issuer`.
- The store can be interrogated: partial paths overall, for a target, or for a leaf CA; the
  certificates it holds; the name constraints in force; the trust anchors loaded; and the AIA and
  SIA URIs present, optionally downloading what they name.
- `--cleanup` and `--ta-cleanup` remove or relocate material that cannot contribute — expired,
  unparseable, self-signed or non-CA certificates — and `--report-only` says what would go without
  touching anything.

### Output

- A machine-readable **validation report** describing each path and why it succeeded or failed,
  which is what the GUIs display and the service returns, rather than log output alone.
- Results and errant certificates can be written to folders for review, and logging is configured
  through a log4rs YAML file.

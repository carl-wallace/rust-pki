# PKI Interoperability Test Tool (PITTv3)

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

PKI Interoperability Test Tool v3 (PITTv3) can be used to build and validate certification paths using different sets 
of trust anchors, intermediate CA certificates and end entity certificates. It uses ASN.1 encoders and decoders and 
cryptographic support provided by various [RustCrypto] libraries. It also serves as a sample app for using the 
[certval](../certval/index.html) library and related RustCrypto formats libraries.

A change log is available at the root of the `pittv3` project.

## Using PITTv3

**1) Serialize a set intermediate CA certificates and partial certification paths**

PITTv3 works best when using a set of intermediate CA certificates and partial certification
paths that have been serialized to a [CBOR file](../certval/source/cert_source/struct.BuffersAndPaths.html).
To generate a CBOR file for a given PKI:
- prepare a set of trust anchor certificates in a folder
- prepare a set of CA certificates in a folder,
- use the `generate` option, as shown below.

The `chase-aia-and-sia` can be included to download additional certificates. The downloaded
artifacts may be directed to a location specified by the `download-folder` option for later
review or to the `ca-folder` for inclusion in CBOR file.
```text
 pittv3 --cbor example.cbor --ca-folder path/to/ca_folder --ta-folder path/to/ta_folder --generate
```
If intermediate CA certificates are not available but one or more end entity certificates are
available, the `validate-all` and `dynamic-build` options can be used with the `ta-folder` and
`download-folder` options to download available intermediate CA certificates relevant to the
validation of the end entity certificate(s) using URIs read from AIA and SIA extensions. The
`last-modified-map` and `blocklist` can be used to improve performance of AIA and SIA retrieval
operations during generation or during dynamic certification path building.
```text
 pittv3 -t path/to/ta_folder -e path/to/ee/certificate -d path/to/download/folder -v -y
```
Intermediate CA certificates for the web PKI can be parsed from the a [CSV file made available by
Mozilla](https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV) using
the `mozilla-csv` option.
 ```
 pittv3 --mozilla-csv path/to/MozillaIntermediateCerts.csv --ca-folder path/to/ca_folder
 ```

The `generate` command can then be used as shown above to prepare a CBOR file for use in
validating end entity certificates or analyzing certification paths within the PKI.

**2) Build and validate certification paths**

To validate certificates using a CBOR file, use the cbor option in tandem with the `ta-folder` option
and either the `end-entity-file` or `end-entity-folder` options. The `validate-all` option can be added
to validate all available possible paths. Validation results can be saved by specifying a folder
to receive the results using the `results-folder` option.
```text
 pittv3 -b example.cbor -t path/to/ta_folder -e path/to/ee/certificate.der
```
The `dynamic-build` and `download-folder` options can be added to dynamically develop certification paths for validation by
downloading certificates from location specified in AIA or SIA extensions. Download operations
can be influenced by the `last-modified-map` and `blocklist` options in [CertificationPathSettings](../certval/validator/path_settings/index.html)
or the automatically generated files in the folder used to download artifacts. Generation and validation
operations use the `time-of-interest` option to determine if certificates are expired or not yet
valid. By default, the current time is used. An alternative time of interest can be specified
by passing the number of seconds since the Unix epoch via the `time-of-interest` option.

**3) Analyze a given PKI**

Several diagnostic tools are provided. Of these, `list-partial-paths-for-target` and
`list-partial-paths-for-leaf-ca` options are likely the most useful. These return a list of
partial certifications paths and list of associated certificates given a target certificate or
leaf CA index. The `cbor` and `ta-folder` options are required for most diagnostic tools. As
with validation operations, the `time-of-interest` option can be used to vary the partial paths
returned for a target by ignoring invalid certificates.

 ```
 pittv3 --cbor example.cbor --list-partial-paths-for-target path/to/ee/certificate.der
 ```

**4) Logging**

PITTv3 generates a large volume of logging output to aid in troubleshooting or analysis efforts.
The `logging-config` option can be used to specify a YAML file that follows the [`log4-rs`](https://docs.rs/log4rs/latest/log4rs/)
configuration practices. When no logging configuration is specified output generated at the Info
level and higher is directed to stdout.

## Crate Feature Flags

The pittv3 binary features the seven feature gates of the certval library, plus two of its own.
The gates shared with certval enable varying levels of support and are as follows:

- `default-features = false` provides path validation support for no-std applications without support for revocation status determination or multi-thread support.
  Trust anchors and CA certificates/partial paths are provided by a pair of CBOR files built into the app.
- `revocation` augments the `default-features = false` feature by adding support for processing CRLs and OCSP responses that are provided by the caller. This mode is not
  presently demonstrated by PITTv3, i.e., no revocation information is baked in.
- `std` augments the `default-features = false` feature by adding support for obtaining artifacts via the file system and addition of support for multi-threaded use.
- `revocation,std` augments the `std` feature by adding support for processing CRLs and OCSP responses that are provided by the caller or obtained via the file system.
- `remote` replaces and augments the `revocation,std` feature by adding support for retrieving certificates via URIs expressed in SIA and AIA extensions, for retrieving CRLs via URIs
  expressed in CRL DP extensions, and for interacting with OCSP responders via URIs expressed in AIA extensions. It is part of the default feature set, which is `remote`, `webpki`, `pqc`, `rsa` and `eddsa` — broader than certval's own default of `remote` plus `webpki`, since the binary is meant to be handed whatever certificates a user has.
- `pqc` adds support for ML-DSA (FIPS 204), including the hash-ML-DSA-with-SHA-512 variants, and SLH-DSA (FIPS 205), using the [ml-dsa](https://crates.io/crates/ml-dsa) and [slh-dsa](https://crates.io/crates/slh-dsa) implementations, plus composite ML-DSA signatures.
- `webpki` adds support for instantiating TaSource instances using trust anchors from the [webpki-roots](https://crates.io/crates/webpki-roots) crate
- `rsa` enables use of the RSA algorithm. It is off by default in certval and on by default here.
- `eddsa` enables use of the Ed25519 algorithm. It is off by default in certval and on by default here.

The first of the two additional gates is `std_app`, which builds certval as `default-features = false` but
builds pittv3 with std support so that end entity files can be selected for validation (additional
work could be done to broaden the capabilities of the app while using certval in no-std but for now
it's only for selecting end entity files).

The second is `sha1_sig`, which registers an additional signature verification callback covering
`sha1WithRsaEncryption`, an algorithm the RustCrypto libraries certval builds on do not implement.
It implies `rsa`, and exists so that legacy material can be examined; it does not make SHA-1 a
sound signature algorithm.

## ⚠️ Security Warning

PITTv3 is a diagnostic tool built on `certval`, which has never been independently audited. See the
security warning in `certval/README.md` for the conformance suites the library is tested against —
x509-limbo and NIST PKITS — and what they do and do not establish.

## Minimum Supported Rust Version

This crate requires **Rust 1.85** at a minimum, and tracks `certval`'s MSRV; see that crate's MSRV
policy. No promise is made about when it moves — nothing resolves against this binary, so an
increase cannot break a downstream build.

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

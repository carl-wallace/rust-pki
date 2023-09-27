# Supporting library for the PKI Interoperability Test Tool (pittv3-lib)

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

PKI Interoperability Test Tool v3 (PITTv3) can be used to build and validate certification paths using different sets 
of trust anchors, intermediate CA certificates and end entity certificates. It uses ASN.1 encoders and decoders and 
cryptographic support provided by various [RustCrypto] libraries. It also serves a sample app for using the 
[certval](../certval/index.html) library and related RustCrypto formats libraries.

This crate provides a library that is used by pittv3-cli, pittv3-gui and pittv3-wasm.

## Crate Feature Flags

The pittv3-lib library features the same five feature gates as the certval library, plus one additional.
The seven feature gates shared with certval enable varying levels of support and are as follows:

- `default-features = false` provides path validation support for no-std applications without support for revocation status determination or multi-thread support.
  Trust anchors and CA certificates/partial paths are provided by a pair of CBOR files built into the app.
- `revocation` augments the `default-features = false` feature by adding support for processing CRLs and OCSP responses that are provided by the caller. This mode is not
  presently demonstrated by PITTv3, i.e., no revocation information is baked in.
- `std` augments the `default-features = false` feature by adding support for obtaining artifacts via the file system and addition of support for multi-threaded use.
- `revocation,std` augments the `std` feature by adding support for processing CRLs and OCSP responses that are provided by the caller or obtained via the file system.
- `remote` is the default. It replaces and augments the `revocation,std` feature by adding support for retrieving certificates via URIs expressed in SIA and AIA extensions, for retrieving CRLs via URIs
  expressed in CRL DP extensions, and for interacting with OCSP responders via URIs expressed in AIA extensions.
- `pqc` adds support for dilithium, falcon and sphincsplus using algorithm implementations from the [pqcrypto](https://github.com/rustpq/pqcrypto) project and object identifiers from the [IETF 115 PQC hackathon](https://github.com/IETF-Hackathon/pqc-certificates).
- `webpki` adds support for instantiating TaSource instances using trust anchors from the [webpki-roots](https://crates.io/crates/webpki-roots) crate

The one additional feature gate is `std_app`, which builds certval as `default-features = false` but
builds pittv3-cli and pittv3-lib with std support so that end entity files can be selected for validation (additional
work could be done to broaden the capabilities of the app while using certval in no-std but for now
it's only for selecting end entity files).

## Status

tl;dr: not ready to use.

This is a work-in-progress implementation which is at an early stage of
development.

## Minimum Supported Rust Version

This crate requires **Rust 1.65** at a minimum.

The MSRV may change in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[RFC 5937]: https://datatracker.ietf.org/doc/html/rfc5937

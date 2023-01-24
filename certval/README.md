# certval

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

Pure Rust implementation of X.509 public key infrastructure certification path validation algorithm described in [RFC 5280] as 
as augmented by [RFC 5937]. Support for certification path building and revocation status determination is also included. 

ASN.1 encoders and decoders and cryptographic support are primarily provided by various [RustCrypto] libraries.

A change log is available at the root of the certval project.

## Crate Feature Flags

The certval library provides five feature gates that enable varying levels of support.

- `default-features = false` provides path validation support for no-std applications without support for revocation status determination or multi-thread support. Certificates and partial paths can be provided via a CBOR file, providing rich certification path development support for environments in which new CAs are introduced infrequently.
- `revocation` augments the `default-features = false` feature by adding support for processing CRLs and OCSP responses that are provided by the caller, such as may have been obtained by stapling to a higher level protocol.
- `std` augments the `default-features = false` feature by adding support for obtaining artifacts via the file system and addition of support for multi-threaded use.
- `revocation,std` augments the `std` feature by adding support for processing CRLs and OCSP responses that are provided by the caller or obtained via the file system.
- `remote` is the default. It replaces and augments the `revocation,std` features by adding support for retrieving certificates via URIs expressed in SIA and AIA extensions, for retrieving CRLs via URIs expressed in CRL DP extensions, and for interacting with OCSP responders via URIs expressed in AIA extensions.
- `pqc` adds support for dilithium, falcon and sphincsplus using algorithm implementations from the [pqcrypto](https://github.com/rustpq/pqcrypto) project and object identifiers from the [IETF 115 PQC hackathon](https://github.com/IETF-Hackathon/pqc-certificates).

## Sample Usage

The [PITTv3](../pittv3/index.html) application provides means of exercising the certval library and can serve as sample code for usage of the library.

## Status

tl;dr: not ready to use.

This is a work-in-progress implementation which is at an early stage of
development.

## Minimum Supported Rust Version

This crate requires **Rust 1.56** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
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
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[RFC 5937]: https://datatracker.ietf.org/doc/html/rfc5937

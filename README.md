# Rust Certification Path Processing

Pure Rust Libraries and tools related to certification path processing. 

A browser-based frontend for PITTv3 is hosted at <https://pittv3.redhoundsoftware.com>; no local
build is required to try it.

## Crates

| Name              | Description                                                                         |
| ----------------- |-------------------------------------------------------------------------------------|
| `certval`         | Certification path building and validation implementation                           |
| `pittv3`          | Command-line version of PKI Interoperability Test Tool functionality                |
| `pittv3-lib`      | Argument structure and processing logic shared by every PITTv3 frontend             |
| `pittv3-gui`      | Desktop (dioxus-desktop) frontend for PITTv3                                        |
| `pittv3-gui-lib`  | User interface components shared by the desktop and browser frontends               |
| `pittv3-wasm`     | Browser (WASM) frontend for PITTv3, hosted at <https://pittv3.redhoundsoftware.com> |
| `pittv3-relay`    | Retrieves PKI artifacts over HTTP for a caller that cannot retrieve them itself     |
| `pittv3-service`  | Serves the browser frontend, the relay it calls, and server-side validation         |
| `pkiprocmacros`   | Procedural macros that support certval and friends                                  |

The `certval` crate is the focal point of this repo. The various `pittv3` crates provide different ways of 
exercising `certval`'s capabilities. Five different `pittv3` interfaces are provided: command line, desktop GUI,
WASM, WASM + relay, and a (limited) scriptable service API. The WASM + relay option hosted at 
<https://pittv3.redhoundsoftware.com> provides a means to exercise the library without building or installing
any components and without having end entity certificates leave the web browser.

## Standards

`certval` validates certification paths per [RFC 5280], with the trust anchor constraint
processing of [RFC 5937] over trust anchors expressed as [RFC 5914] `TrustAnchorChoice` values.
Certificate policy processing follows the graph-based algorithm of [RFC 9618]. Revocation
status is determined from CRLs and from OCSP ([RFC 6960], including the nonce handling of
[RFC 8954]), and path building based on the practices described in [RFC 4158]. Signatures are
verified for RSA, ECDSA, Ed25519, ML-DSA ([FIPS 204]) and SLH-DSA ([FIPS 205]).

Conformance is measured against [x509-limbo] and the NIST [PKITS] suite; `certval`'s security
warning reports the pass rate and where the remaining mismatches fall.

[RFC 4158]: https://datatracker.ietf.org/doc/html/rfc4158
[RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[RFC 5914]: https://datatracker.ietf.org/doc/html/rfc5914
[RFC 5937]: https://datatracker.ietf.org/doc/html/rfc5937
[RFC 6960]: https://datatracker.ietf.org/doc/html/rfc6960
[RFC 8954]: https://datatracker.ietf.org/doc/html/rfc8954
[RFC 9618]: https://datatracker.ietf.org/doc/html/rfc9618
[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final
[FIPS 205]: https://csrc.nist.gov/pubs/fips/205/final
[x509-limbo]: https://github.com/C2SP/x509-limbo
[PKITS]: https://csrc.nist.gov/projects/pki-testing

## License

All crates licensed under either of the following, at your option: 

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.


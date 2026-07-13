# PITTv3 WASM

This crate provides a browser-based frontend for the PKI Interoperability Test Tool v3 (PITTv3)
that performs certification path validation in a WASM context, including validation of
certificates signed using post-quantum algorithms, i.e., ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
All processing occurs in the browser; certificates never leave the page.

Trust anchor and CA certificate stores for several PKITS editions (ML-DSA-44, ML-DSA-65, ML-DSA-87
and SLH-DSA-SHA2-128s) are baked into the application as CBOR. Alternatively, trust anchors and
intermediate CA certificates can be uploaded to validate certificates from other sources, e.g.,
artifacts produced by other implementations during interoperability testing.

To run locally: `dx serve` from this folder (requires the [Dioxus CLI](https://dioxuslabs.com/learn/0.7/getting_started/)).
To produce a deployable site: `dx bundle --release`.

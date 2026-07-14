# PITTv3 library

This crate provides the argument structure and processing logic underpinning the PKI
Interoperability Test Tool v3 (PITTv3). It exists so that different frontends, i.e., the
`pittv3` command line utility and GUI applications, can share the same implementation.

The [`Pittv3Args`](args::Pittv3Args) structure is a plain data structure with no command line
parsing dependencies, allowing frontends to populate it directly. The various `options_*` modules
provide the top-level processing entry points relative to the feature set in use, mirroring the
feature gates of the `certval` crate:

- no-default-features provides full path validation without file system support, network or thread safety (and no revocation support)
- `revocation` adds support for verifying CRLs and OCSP responses presented to the library
- `std` adds file-based utilities (including graph building) and support for multi-threading
- `remote` adds support for dynamic path building, CRL fetching and OCSP
- `std_app` provides std support for frontends while building certval with no-default-features
- `webpki` adds a means of initializing a TaSource from the webpki-roots crate

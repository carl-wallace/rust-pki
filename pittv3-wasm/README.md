# PITTv3 WASM

This crate provides a browser-based frontend for the PKI Interoperability Test Tool v3 (PITTv3)
that performs certification path validation in a WASM context, including validation of
certificates signed using post-quantum algorithms, i.e., ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
All processing occurs in the browser; certificates never leave the page.

A hosted instance is available at <https://pittv3.redhoundsoftware.com>; no local build is required
to try it.

Trust anchor and CA certificate stores for several PKITS editions (ML-DSA-44, ML-DSA-65, ML-DSA-87
and SLH-DSA-SHA2-128s) are baked into the application as CBOR. Trust anchors and intermediate CA
certificates can also be uploaded and are used together with the selected built-in store (or alone
when no store is selected) to validate certificates from other sources, e.g., artifacts produced by
other implementations during interoperability testing. Uploads and certificates to validate
accumulate across uploads, so a set of loaded certificates can be re-validated after changing the
trust configuration or settings. Values that govern the RFC 5280 path validation inputs, e.g., the
initial policy set and related indicators, can be edited in the UI.

Provider archives from the [IETF Hackathon PQC Certificate repo](https://github.com/IETF-Hackathon/pqc-certificates)
in the artifacts_certs_r5.zip format can be validated wholesale: `*_ta.der` entries form a
self-contained trust anchor store and are each validated as self-signed targets, `*_ee.der`
entries (e.g., ML-KEM certificates) are validated against that store, and all other entries are
ignored. The `ziptest` host-side binary exercises the same logic from the command line:
`cargo run --bin ziptest -- <path-to-zip>`.

## Prerequisites

The app is built with [Trunk](https://trunkrs.dev/) (the `index.html` in this folder carries the
`data-trunk` directives that drive the build):

```sh
rustup target add wasm32-unknown-unknown
cargo install trunk --locked
```

## Build and run locally

From this folder:

```sh
trunk serve
```

This compiles a debug build, serves it at <http://127.0.0.1:8080>, and rebuilds automatically when
sources change. To serve the optimized build instead (slower to compile, much smaller and faster to
load):

```sh
trunk serve --release --cargo-profile wasm-release
```

## Build and deploy to an HTTP server

From this folder:

```sh
trunk build --release --cargo-profile wasm-release
```

The `wasm-release` profile is defined in the workspace `Cargo.toml`; it optimizes for size
(`opt-level = "z"`, `lto = true`). Do not build with plain `--release` for deployment — without
the size optimizations and LTO the `.wasm` file comes out roughly three times larger
(~60 MB vs ~20 MB).

The output lands in `dist/`, which is fully static:

- `index.html`
- `pittv3-wasm-<hash>.js` and `pittv3-wasm-<hash>_bg.wasm` (content-hashed)
- `snippets/` (JS glue)

Copy the contents of `dist/` to the web server's document root or any subdirectory. `Trunk.toml`
sets `public_url = "./"` so the generated `index.html` references its assets relative to itself
and the site works from any mount point; Trunk's default of `/` produces site-root-absolute links
that break when the app is deployed to a subdirectory, e.g., `/pittv3/`.

For Apache, copy `apache.htaccess` alongside `index.html` as `.htaccess` (or fold it into the
vhost configuration if `AllowOverride` is off). It sets the `application/wasm` MIME type (enables
streaming compilation), enables compression (the `.wasm` file compresses roughly 4x), and sets
cache headers: the hashed `.js`/`.wasm` assets are cached forever while `index.html` is always
revalidated so browsers pick up new hashes on redeploy. For other servers (nginx, etc.), replicate
those three behaviors. No server-side logic is required; any static HTTP server works.

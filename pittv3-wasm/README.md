# PITTv3 WASM

This crate provides a browser-based frontend for the PKI Interoperability Test Tool v3 (PITTv3)
that performs certification path validation in a WASM context, including validation of
certificates signed using post-quantum algorithms, i.e., ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
All processing occurs in the browser; certificates never leave the page.

A hosted instance is available at <https://pittv3.redhoundsoftware.com>; no local build is required
to try it.

The two trust-community stores — the Web PKI (Mozilla roots and CCADB intermediates) and U.S. DoD
(NIPR) — are shipped as CBOR files in `resources/`, which Trunk copies into `dist/` and the app
fetches by relative URL when the store is selected, rather than embedding them, which would be paid
on every page load. They are regenerated from their provider crates by `build.rs`. The ML-DSA-44
PKITS edition is different: it is small, static test collateral with no provider behind it, so it is
compiled in from `fixtures/` alongside its two sample end entity certificates. See
`resources/NOTICE` for what each artifact is, where it came from and the terms it travels under.

Trust anchors and intermediate CA certificates can also be uploaded and are used together with the
selected built-in store (or alone when no store is selected) to validate certificates from other
sources, e.g., artifacts produced by other implementations during interoperability testing. Uploads and certificates to validate
accumulate across uploads, so a set of loaded certificates can be re-validated after changing the
trust configuration or settings. Values that govern the RFC 5280 path validation inputs, e.g., the
initial policy set and related indicators, can be edited in the UI.

The **End entity certificate** group takes what is to be validated from one of two sources, chosen
with the *Load from* control: a **File**, or a **TLS server**. The second exists because a browser
holds the certificate of every site it talks to and hands over none of them, so the certificate
people most often want to look at — the one a site is serving right now — is the one that could not
be uploaded without going away and fetching it with another tool first. Naming a host has the
service complete a handshake with it and keep what it sent: the host's own certificate is loaded
here, anything sent with it joins the CA certificates path building draws on, and a stapled OCSP
response is kept as revocation data. Nothing is requested over the connection, and making the
handshake does not judge the certificate — that is what Validate is for, which is the point, since a
chain a browser refuses is usually the reason someone came. It needs a service, so it works only in
the relayed tier. Both sources feed one list, and switching between them discards nothing, so the
count beside *Loaded* is what a run will validate however the certificates arrived.

A **Retrieval** selector on the Validate tab chooses what the app may fetch. *In this browser only*
is the historical behavior and the only option when no service is serving the page: nothing leaves
it, paths are built from the selected store and uploads, and revocation status stays undetermined
unless the data was supplied. *Retrieve through the service* has `pittv3-service` fetch on the
page's behalf — issuer certificates from AIA and SIA URIs when no path can be built, and, for the
certificates on the paths that are built, their CRLs and an OCSP response per certificate whose
issuer runs a responder. The certificates being validated never leave the page; the URIs they name
do, and an OCSP request identifies the certificate being asked about even though the certificate
itself is not sent. The setting also drives the settings form's per-capability notices, and flips
what an unstated revocation preference means, since with a relay the check can actually be
satisfied.

*Retrieve through the service* is the tier a served page starts on. A deployment that runs a
service is one that means to retrieve, and starting elsewhere there makes the first run report
missing issuers and undetermined revocation status for want of a switch nobody was told to flip.
The selector is one click either way, and its hint states what leaves the page. A statically hosted
copy has no service to answer `api/health`, so it starts — and stays — in the browser-only tier
with the selector disabled and a line saying why.

The harvesting and folding around that retrieval are `pittv3_gui_lib::retrieval`, shared with the
server-hosted tier, so the same certificate validated either way goes through the same code.

When the app is served by `pittv3-service` it also asks that service, once at startup, what stores
it holds (`GET api/stores`) and adds the ones it does not already ship to the selector. A store the
service names with an identifier this crate already ships is not offered twice: the service
generates its built-in stores from the same provider environments this crate's `build.rs` does, so
the two are the same material by construction. The selector says where the selected store came from
— published with the app, from a provider built into the service, or from the store directory that
service was configured with — because a configured store may hold certificates whose only
provenance is that some repository served them. A statically hosted copy asks, gets no answer, and
carries on with the stores in `resources/`; nothing about deploying to a static host changes.

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

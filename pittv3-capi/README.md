# pittv3-capi

Certification path building and validation through the Microsoft CryptoAPI chain engine
(`CertGetCertificateChain` plus `CertVerifyCertificateChainPolicy`), packaged as a second opinion to
set beside the certval-based validation the rest of PITTv3 performs.

This is the PITTv3 equivalent of PITTv2's CAPI panel. Where PITTv2 drove the chain engine from a
wxWidgets thread and wrote its findings into a grid as it went, this crate is a single synchronous
function over bytes:

```rust,no_run
# #[cfg(windows)] {
use pittv3_capi::{verify, CapiOptions};

let target = std::fs::read("target.der")?;
let result = verify(&target, &CapiOptions::default())?;

println!("validated: {}", result.validated);
for chain in &result.chains {
    println!("chain {} ({} elements): {}",
        chain.index, chain.elements.len(), chain.trust_status.describe());
}
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Why it is a separate crate

`certval`, `pittv3-gui` and `pittv3-gui-lib` are each `#![forbid(unsafe_code)]`, and every Win32
entry point in the `windows` crate is an `unsafe fn`. The unsafe is confined to [`verify`]'s module
so those three keep the lint.

`certval` already reads CAPI *stores* — see `certval::source::capi_source` — but it does so through
`schannel`'s safe wrappers, and reads them only as trust anchor and certificate *sources* that
certval's own path builder then consumes. That module's documentation notes the limit it runs into:

> Closing the gap would mean handing path building to `CertGetCertificateChain`, which is the thing
> using this crate is instead of.

This crate is that hand-off, offered deliberately and separately rather than as a fallback.

## Results are CAPI-shaped on purpose

Nothing here is translated into `PathValidationStatus` or `PathReport`. A CAPI verdict is a pair of
bit masks per chain and per element plus, separately, an `HRESULT` from the policy check, and those
do not map cleanly onto certval's status enum — `CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT` has no
counterpart at all. Reporting what CAPI said, in CAPI's vocabulary, is the only form in which the
two columns of a comparison mean anything.

## Platform

Windows only. On other targets the crate still compiles — the flag decoding in
[`status`](crate::status) is portable and tested everywhere — but [`verify`] is absent.

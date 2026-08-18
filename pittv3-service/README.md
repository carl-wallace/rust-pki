# PITTv3 service

This crate hosts the two frontends of the PKI Interoperability Test Tool v3 (PITTv3) that need a
server: the browser application working against a relay, and server-side validation for a caller
that would rather send certificates than retrieve PKI artifacts itself. It is one binary serving
both, alongside the browser application itself, so the application and the endpoints it calls share
an origin.

The endpoints are:

- `POST /api/fetch` retrieves one artifact through `pittv3_relay`, which enforces the network policy
  and the per-retrieval budgets. The service does not look at what comes back.
- `POST /api/validate` validates the certificates in the request and returns a `ValidationReport`,
  the same structure the CLI writes and the GUIs display.
- `GET /api/stores` lists the trust stores the service holds, in the shape the browser
  application's store selector already consumes, and `GET /stores/{id}/{ta,ca}.cbor` serves them.

## Trust stores

The service comes up offering a catalogue whether or not it is configured with one. The built-in
stores are generated when the crate is built, by the same `serialize_environment` call on the same
`certval_stores_*` provider environments that the browser application's build script makes:
`dod_nipr_prod`, `webpki` (Mozilla roots for all purposes, with the CCADB intermediates),
`webpki_tls`, `webpki_email`, `fpki` and `dod_purebred_dev`. Because they are generated the same
way and named the same way, a store the browser already ships is recognized as the same material and
not offered twice.

`--stores <dir>` adds whatever a deployment holds — an export from a desktop run, a store built for
one community, a graph assembled by chasing — and a store there replaces a built-in of the same
name, which is how a deployment serves fresher material under a familiar identifier. It is read once
at startup and never written to. Three layouts are accepted, so nothing has to be renamed after a
PITTv3 tool produced it: `<id>/ta.cbor` + `<id>/ca.cbor` in a folder (what the desktop's Export PKI
Environment writes), `<id>_ta.cbor` + `<id>_ca.cbor` (what the trust store providers generate), and
`<id>.ta.cbor` + `<id>.ca.cbor`. An optional `stores.json` maps identifier to display name. The CA
half is optional; a CA artifact with no trust anchors beside it is skipped.

Two ways to have less than all of that. `--no-builtin-stores` offers only what `--stores` names, for
a deployment that means to present a chosen catalogue and nothing else. Building without the
`builtin-stores` feature goes further: the provider crates leave the build entirely, so the binary
sheds the 7.9 MB of trust material it linked in (6.6 MB of that the Mozilla CA store) and the
build no longer reaches the repositories carrying it.

The listing says where each store came from — `provider` for a built-in, `configured` for one from
the store directory — because the two are not equally answerable for their contents. Every
certificate in a provider store was published by the community it belongs to and is covered by a
conformance check; a configured store may have been assembled by following authority information
access URIs, where the provenance of a certificate is that some repository served it. Presenting
them as peers in one selector would hide that, so the browser application says which it offered.

## Validation

Server-side validation calls the same synchronous validation path the browser calls, in
`pittv3_gui_lib::validate`, with certval built the same way the browser builds it. The two tiers
therefore cannot disagree about a certificate, which for a conformance tool is the property that
matters. What differs between them is only who does the retrieving, and therefore what leaves the
browser: URIs and OCSP requests in the relayed tier, certificates in the server-hosted one.

certval is built here without its `remote` feature, so nothing in the validation stack opens a
socket of its own. Every retrieval goes through the relay, where the scheme and address checks, the
redirect rules and the byte, time and count budgets are applied — the same treatment for a URI
found inside an uploaded certificate as for one a client asks the relay to retrieve.

Revocation status is determined where the certificates say how. After preparing the environment the
service harvests the CRL distribution points named on the paths it built, retrieves them through the
relay, and puts them where the shared path's `check_revocation` looks — so the answer comes from the
same code the browser runs, with only the fetching done differently. `--no-revocation-fetch` turns
that off for a deployment that would rather not make those requests; status is then reported as
undetermined unless the caller supplied the data. Both mechanisms are used: the CRLs a path's
certificates name, and an OCSP request per certificate whose issuer runs a responder — CRLs first,
since one covers every certificate its issuer published it for while a responder answers about
exactly one, so each CRL is a question that then does not have to be asked.

Chasing is separate and off by default (`--allow-dynamic-build`), because it is unbounded in a way
revocation retrieval is not: one uploaded certificate naming a subject information access URI can
lead to a great deal of retrieval, whereas the CRLs worth fetching are those named on paths that
have already been built.

Settings arriving over the wire are sanitized before use: `CertificationPathSettings` can name
folders and files, which are meaningless to a client and dangerous to honor, so those keys are
removed server-side rather than trusted to be absent.

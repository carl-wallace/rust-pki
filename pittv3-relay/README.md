# PITTv3 relay

This crate retrieves PKI artifacts over HTTP on behalf of a caller that cannot retrieve them itself.
A browser is the motivating case: it can build and validate certification paths using certval
compiled to WASM, but the same-origin policy stops it from reading a CRL distribution point or
posting an OCSP request, so a relay hosted alongside the application does that part.

The relay handles the three verbs PKI retrieval needs: `GET` for certificates and CRLs named by
authority information access, subject information access and CRL distribution point extensions, and
`POST` for OCSP requests. It does not parse what it retrieves, does not cache by certificate
identity, and does not distinguish a CRL from any other sequence of bytes. Conditional request
headers pass through so a caller can benefit from `If-Modified-Since` the same way the PITTv3 CLI
does when it maintains a download folder.

It also takes the certificates a TLS server presents, which is retrieval of a different shape: the
artifact is not served at a URI, it is what a host sends when spoken to. A browser cannot obtain it
at all — it holds the certificate of every site it talks to and hands over none of them — so a
handshake made here is the only way the certificate a site serves reaches an application that wants
to validate it. The handshake accepts any certificate, deliberately: a chain a verifier would reject
is exactly the chain someone reaches for this tool to look at. What it does not skip is the peer's
handshake signature, so what comes back belongs to the party that answered rather than to anything
that could reach the address. Nothing is sent over the connection and nothing is parsed; a stapled
OCSP response is kept because the peer volunteered it.

Because the URIs it is asked to retrieve come from certificates supplied by whoever is using the
service, every request is treated as attacker-chosen. The `policy` module enforces a scheme and port
allowlist, resolves each hostname itself and rejects addresses that are loopback, private,
link-local, unique-local, multicast or otherwise not a public destination, and then connects to the
addresses it resolved rather than resolving a second time inside the HTTP client. A handshake goes
through the same checks, so it cannot reach a host, an address or a port a retrieval could not. Redirects are
refused unless a limit is configured, and each hop is checked afresh. Budgets bound the size of a
response, the time a request may take, and the size of a request body.

The public surface is a plain function taking a request description and returning bytes, with no
types from any HTTP server framework, so it can be exercised in a test without a running service.

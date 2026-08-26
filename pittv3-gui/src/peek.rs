//! Taking the certificates a TLS server presents, and putting them where a run will find them.
//!
//! The browser frontend has offered this since it had nowhere else to get a server's certificate
//! from: a browser holds the certificate of every site it talks to and will not hand it over, so a
//! person wanting to validate one had to reach for `openssl s_client` and a text editor first.
//! The desktop has a socket and could always have done it, and never did — which left the two
//! frontends with different answers to the same question, and left the desktop user with the
//! `s_client` detour the browser user had been spared.
//!
//! **No service is involved.** `pittv3-relay` does the handshake itself and does not depend on
//! certval, so the desktop calls it in process. That is the same code the browser reaches through
//! the service, so the two frontends take a chain the same way.
//!
//! Two things differ from the way a service configures that code, and the difference is the point
//! rather than an oversight:
//!
//! 1. **Private addresses are permitted here.** [`NetworkPolicy`]'s refusal of them is SSRF
//!    hardening — it protects a *server operator* from anonymous callers naming addresses only the
//!    server can reach. On the desktop the caller is the person at the keyboard and the address is
//!    their own network, where "check the certificate on our internal host" is the ordinary errand
//!    rather than the attack.
//! 2. **Any port may be named.** A service allows 80 and 443 so a peek cannot be used to sweep
//!    ports on a host the caller cannot reach; here the caller can already reach it.
//!
//! What is kept is the part that is about correctness rather than containment: the handshake
//! accepts any certificate — an expired or unknown-issuer chain is exactly what someone reaches for
//! this to look at — while still checking the peer's handshake signature, so the chain returned
//! belongs to the party actually spoken to rather than to whoever could answer at that address.

use std::fs;
use std::path::PathBuf;

use pittv3_gui_lib::settings_store::app_home;
use pittv3_relay::{FetchBudget, NetworkPolicy, PeekRequest, Relay};

/// Where a peek writes what it was given, `peeked` beneath the application home.
///
/// Written to disk rather than held in memory because the desktop's inputs are paths: the arguments
/// name files, and a handshake yields bytes with no name. Mirrors `stores::store_home`, which
/// materializes a built-in store for the same reason. It also leaves the user holding what the host
/// served, which the browser cannot do — there the bytes are gone on reload.
fn peek_home() -> Option<PathBuf> {
    Some(app_home()?.join("peeked"))
}

/// What a peek produced, as the paths a run takes.
pub(crate) struct Peeked {
    /// How the host was named, port included when it was not the default.
    pub source: String,
    /// The protocol version negotiated, when the handshake reported one.
    pub protocol: Option<String>,
    /// The server's own certificate, to validate.
    pub end_entity: String,
    /// Anything else the server sent, as CA input. A server following RFC 8446 sends its own
    /// certificate first and its issuers after; nothing here enforces that, because a server that
    /// does not is exactly the kind of finding this exists to surface.
    pub chain: Vec<String>,
    /// A stapled OCSP response, when one was stapled. Kept as revocation input: it is an answer the
    /// caller now holds without having asked a responder for it, and a stapled response that
    /// answers about a different certificate than the one it accompanies is a real
    /// misconfiguration that only a stapled copy can reveal.
    pub stapled_ocsp: Option<String>,
    /// Where the files were written.
    pub folder: String,
}

/// The policy a desktop peek runs under. See the module comment for why it is not the service's.
fn desktop_policy() -> NetworkPolicy {
    NetworkPolicy {
        // Only `https` reaches the handshake anyway — `peek` refuses anything else by name rather
        // than letting it fail as a transport error — but the list is what `check_uri` consults,
        // so it has to carry the scheme that will be asked for.
        schemes: vec!["https".to_string()],
        // Empty permits any port, which is what a desktop wants: a TLS service on a high port is
        // ordinary, and the user naming it is the one who has to reach it. A service keeps a list
        // precisely so a peek cannot sweep ports on a host the caller could not otherwise reach.
        ports: vec![],
        allow_hosts: vec![],
        deny_hosts: vec![],
        max_redirects: 0,
        allow_private_addresses: true,
    }
}

/// Completes a handshake with `host` and writes what it presented beneath [`peek_home`].
///
/// `host` may be given bare (`example.com`), with a port (`example.com:8443`), or as a URI; the
/// first two are completed to `https://`, since that is the only scheme a handshake begins with and
/// asking the user to type it adds nothing.
pub(crate) async fn take_presented_certificates(host: &str) -> Result<Peeked, String> {
    let asked = host.trim();
    if asked.is_empty() {
        return Err("Name a host first".to_string());
    }
    let uri = match asked.contains("://") {
        true => asked.to_string(),
        false => format!("https://{asked}"),
    };

    let relay = Relay::new(desktop_policy(), FetchBudget::default())
        .map_err(|e| format!("Could not set up the connection: {e}"))?;
    let presented = relay
        .peek(&PeekRequest::new(&uri))
        .await
        .map_err(|e| format!("{asked}: {e}"))?;

    // The default port is left unsaid; any other is part of what was asked for and is kept, because
    // "example.com" and "example.com:8443" are different services and their files should not land
    // in the same folder.
    let source = match presented.port {
        443 => presented.host.clone(),
        port => format!("{}:{port}", presented.host),
    };

    let dir = peek_home()
        .ok_or_else(|| "Could not locate a home directory to write to".to_string())?
        .join(source.replace(':', "_"));
    // Rewritten rather than added to: a second peek of the same host is a fresh look at it, and
    // leaving the previous chain beside the new one would have a run validate against certificates
    // the host has stopped serving.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| format!("Could not create {}: {e}", dir.display()))?;

    let write = |name: &str, bytes: &[u8]| -> Result<String, String> {
        let path = dir.join(name);
        fs::write(&path, bytes).map_err(|e| format!("Could not write {}: {e}", path.display()))?;
        Ok(path.to_string_lossy().to_string())
    };

    let mut certificates = presented.certificates.into_iter();
    let Some(end_entity) = certificates.next() else {
        return Err(format!("{source} presented no certificate."));
    };
    let end_entity = write("0-presented.der", &end_entity)?;

    let mut chain = vec![];
    for (i, der) in certificates.enumerate() {
        chain.push(write(&format!("{}-sent-with-it.der", i + 1), &der)?);
    }

    let stapled_ocsp = match presented.stapled_ocsp {
        Some(response) => Some(write("stapled.ocspResp", &response)?),
        None => None,
    };

    Ok(Peeked {
        source,
        protocol: presented.protocol,
        end_entity,
        chain,
        stapled_ocsp,
        folder: dir.to_string_lossy().to_string(),
    })
}

impl Peeked {
    /// What happened, in the words the browser frontend uses for the same outcome.
    pub(crate) fn summary(&self) -> String {
        let over = match &self.protocol {
            Some(p) => format!(" over {p}"),
            None => String::new(),
        };
        let mut said = format!("{}{over}: end entity loaded", self.source);
        if !self.chain.is_empty() {
            said.push_str(&format!(", {} sent with it", self.chain.len()));
        }
        if self.stapled_ocsp.is_some() {
            said.push_str(", stapled OCSP response kept as revocation data");
        }
        said.push_str(&format!(". Written to {}.", self.folder));
        said
    }
}

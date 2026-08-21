//! Retrieving the certificates a TLS server presents.
//!
//! A browser holds the certificate of every site it talks to and will not hand it over: there is no
//! API that yields the peer chain, and there is no way to open a socket and read one. So a person
//! who wants to validate the certificate a host serves has to obtain it some other way — with
//! `openssl s_client` and a text editor, today — before the application they came to use can say
//! anything about it. This module is the other way.
//!
//! What it does is deliberately small: connect, complete a handshake, keep what the peer sent, and
//! close. Nothing is requested over the connection, no application data is written, and nothing here
//! parses a certificate — that stays true of this crate as a whole.
//!
//! **The handshake accepts any certificate, on purpose.** A chain that a verifier would reject —
//! expired, self-signed, wrong name, unknown issuer — is precisely the chain someone reaches for
//! this tool to look at, so refusing it would deny the tool its subject. What is *not* skipped is
//! the peer's handshake signature, which is checked with the real algorithms: that is what makes the
//! chain we return the chain belonging to the party we actually spoke to, rather than to whoever
//! could answer on that address. Judging the chain is the caller's job, and the caller is a path
//! validator.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::debug;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;

use crate::policy::PolicyError;
use crate::{FetchError, Relay};

/// A host to take the certificates from.
#[derive(Clone, Debug, Default)]
pub struct PeekRequest {
    /// URI naming the host, which must be `https`. A port other than the default is honored when
    /// the policy permits it.
    pub uri: String,
    /// Timeout for the whole exchange, when shorter than the configured timeout.
    pub timeout: Option<Duration>,
}

impl PeekRequest {
    /// Builds a request for the host `uri` names.
    pub fn new(uri: impl Into<String>) -> Self {
        PeekRequest {
            uri: uri.into(),
            timeout: None,
        }
    }
}

/// What a host presented.
#[derive(Clone, Debug)]
pub struct PeekResponse {
    /// Host the handshake was made with, as written in the URI and sent as the server name.
    pub host: String,
    /// Port connected to.
    pub port: u16,
    /// Protocol version negotiated, e.g., `TLSv1.3`.
    pub protocol: Option<String>,
    /// Certificates the server sent, in the order it sent them. A server following RFC 8446 sends
    /// its own certificate first; nothing here enforces that, because a server that does not is
    /// exactly the kind of finding this tool exists to surface.
    pub certificates: Vec<Vec<u8>>,
    /// OCSP response the server stapled, when it stapled one. Kept because it is revocation data
    /// the caller now holds without asking a responder for it, and because a stapled response that
    /// answers about a different certificate than the one it accompanies is a real misconfiguration
    /// that only a stapled copy can reveal.
    pub stapled_ocsp: Option<Vec<u8>>,
}

impl Relay {
    /// Completes a TLS handshake with the host `request` names and returns what it presented.
    ///
    /// The URI is checked and its host resolved by the same policy every retrieval goes through, so
    /// a deployment that refuses a host or a private address refuses it here too. Only `https` is
    /// accepted: the other schemes the policy may permit do not begin with a handshake.
    pub async fn peek(&self, request: &PeekRequest) -> Result<PeekResponse, FetchError> {
        let dest = self.policy().check_uri(&request.uri)?;
        // The policy's scheme list governs retrieval, where `http` is ordinary. Here it would mean
        // opening a handshake against a port that is not speaking TLS, so it is refused by name
        // rather than left to fail as a transport error nobody can interpret.
        if dest.url.scheme() != "https" {
            return Err(FetchError::Policy(PolicyError::Scheme(
                dest.url.scheme().to_string(),
            )));
        }
        let addresses = self.policy().resolve(&dest).await?;
        let (host, port) = (dest.host.clone(), dest.port);

        let timeout = match request.timeout {
            Some(t) => t.min(self.budget().timeout),
            None => self.budget().timeout,
        };

        let provider = provider();
        // Held past the builder: the stapled OCSP response is handed to the verifier during the
        // handshake and is reachable nowhere else afterwards, so the verifier is where it is kept.
        let verifier = Arc::new(Harvest {
            provider: provider.clone(),
            stapled: Mutex::new(None),
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| FetchError::Setup(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        // A name is what a virtual host keys off, so it is sent as given rather than as whatever
        // address the name resolved to. `to_owned` because the handshake outlives the borrow.
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| FetchError::Policy(PolicyError::Malformed(host.clone())))?;

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let deadline = Instant::now() + timeout;
        let count = addresses.len();
        // What went wrong at the last address that answered at all. A refusal and a silence are
        // different facts about a host, and the difference is the whole diagnosis: a port nothing
        // listens on looks exactly like a slow server until something says which it was.
        let mut answered_badly = None;
        let mut established = None;

        for (attempted, address) in addresses.into_iter().enumerate() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Each address gets an equal share of what is left, rather than the first being allowed
            // to spend the whole allowance. A host that publishes several addresses and blackholes
            // one of them is ordinary; giving up on the host because of it is not, and an address
            // that fails quickly hands its unused share to the ones after it.
            let share = remaining / (count - attempted) as u32;
            let attempt = async {
                let tcp = TcpStream::connect(address)
                    .await
                    .map_err(|e| e.to_string())?;
                connector
                    .connect(server_name.clone(), tcp)
                    .await
                    .map_err(|e| e.to_string())
            };

            match tokio::time::timeout(share, attempt).await {
                Ok(Ok(tls)) => {
                    established = Some(tls);
                    break;
                }
                Ok(Err(e)) => {
                    debug!("{address} failed for {host}: {e}");
                    answered_badly = Some(format!("{address}: {e}"));
                }
                Err(_) => {
                    debug!("{address} did not answer for {host} within {share:?}");
                }
            }
        }

        let Some(stream) = established else {
            return match answered_badly {
                Some(e) => Err(FetchError::Transport(e)),
                None => Err(FetchError::Timeout(timeout)),
            };
        };

        let (_, connection) = stream.get_ref();
        let certificates = connection
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect::<Vec<Vec<u8>>>();
        // A handshake that completes without the peer sending a certificate is possible in the
        // abstract and useless here, and reporting an empty list would leave the caller to guess
        // whether the connection or the parsing failed.
        if certificates.is_empty() {
            return Err(FetchError::Transport(format!(
                "{host} completed a handshake without presenting a certificate"
            )));
        }
        // Named rather than debug-printed: `TLSv1_3` is the enum's spelling, "TLS 1.3" is the
        // protocol's, and this string is shown to a person.
        let protocol = connection.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
            rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
            other => format!("{other:?}"),
        });
        // A poisoned lock would mean the verifier panicked mid-handshake, which cannot leave a
        // handshake to complete; taking the stapled response as absent rather than unwrapping keeps
        // an impossible case from being the one thing that can panic here.
        let stapled_ocsp = verifier
            .stapled
            .lock()
            .ok()
            .and_then(|mut held| held.take());

        Ok(PeekResponse {
            host,
            port,
            protocol,
            certificates,
            stapled_ocsp,
        })
    }
}

/// The provider the handshake uses, named rather than taken from the process default. A default is
/// installed only if something installed it, and more than one is reachable in a workspace this
/// crate shares with an HTTP client; picking here means the handshake does not depend on what else
/// happened to run first.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accepts every certificate and verifies every handshake signature. See the module documentation
/// for why that pairing is the right one here.
#[derive(Debug)]
struct Harvest {
    provider: Arc<CryptoProvider>,
    /// Stapled OCSP response seen during the handshake. The verifier is the only thing the peer's
    /// stapled response is given to, so keeping it is the only way to have it afterwards.
    stapled: Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for Harvest {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !ocsp_response.is_empty() {
            if let Ok(mut held) = self.stapled.lock() {
                *held = Some(ocsp_response.to_vec());
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::FetchBudget;
    use crate::policy::NetworkPolicy;

    fn relay() -> Relay {
        Relay::new(NetworkPolicy::default(), FetchBudget::default()).unwrap()
    }

    /// The scheme is refused before anything is resolved, so a URI naming a plaintext port never
    /// becomes a handshake against a server that is not expecting one.
    #[tokio::test]
    async fn peek_refuses_a_scheme_that_does_not_begin_with_a_handshake() {
        let error = relay()
            .peek(&PeekRequest::new("http://example.com/"))
            .await
            .unwrap_err();
        let FetchError::Policy(PolicyError::Scheme(scheme)) = &error else {
            panic!("expected a scheme refusal, got {error}");
        };
        assert_eq!(scheme, "http");
    }

    /// The same address rules the retrieval path enforces apply here; a literal naming a private
    /// address is refused from the URI alone.
    #[tokio::test]
    async fn peek_refuses_a_private_address() {
        let error = relay()
            .peek(&PeekRequest::new("https://127.0.0.1/"))
            .await
            .unwrap_err();
        let FetchError::Policy(PolicyError::Address(_)) = &error else {
            panic!("expected an address refusal, got {error}");
        };
    }

    /// Takes the certificates from a real host, which is the only way to exercise the handshake
    /// itself: everything above this point stops before a socket is opened.
    ///
    /// Ignored by default because it needs the network, and on a machine that routes outbound
    /// traffic through a proxy it needs direct egress on 443 as well — a raw handshake cannot go
    /// through an HTTP proxy. Run it with `cargo test -p pittv3_relay -- --ignored --nocapture`,
    /// optionally naming a host in `PITTV3_PEEK_HOST`.
    #[tokio::test]
    #[ignore = "requires direct outbound TLS"]
    async fn peek_takes_the_chain_a_host_presents() {
        let host = std::env::var("PITTV3_PEEK_HOST")
            .unwrap_or_else(|_| "https://letsencrypt.org".to_string());
        let response = relay().peek(&PeekRequest::new(&host)).await.unwrap();

        assert_eq!(response.port, 443);
        assert!(
            !response.certificates.is_empty(),
            "a completed handshake presented no certificate"
        );
        // Not parsed — this crate does not know what a certificate is — but a chain whose entries
        // do not begin with a SEQUENCE is not one, and that is worth catching here rather than two
        // layers up where it looks like a decoding fault.
        for certificate in &response.certificates {
            assert_eq!(certificate.first(), Some(&0x30));
        }
        println!(
            "{host}: {:?}, {} certificates, stapled OCSP {:?} bytes",
            response.protocol,
            response.certificates.len(),
            response.stapled_ocsp.as_ref().map(|o| o.len())
        );
    }

    /// A port outside the policy's list is refused, so a peek cannot be used to sweep ports on a
    /// host the policy does permit.
    #[tokio::test]
    async fn peek_refuses_a_port_outside_the_policy() {
        let error = relay()
            .peek(&PeekRequest::new("https://example.com:8443/"))
            .await
            .unwrap_err();
        let FetchError::Policy(PolicyError::Port(port)) = &error else {
            panic!("expected a port refusal, got {error}");
        };
        assert_eq!(*port, 8443);
    }
}

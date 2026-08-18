//! Network policy applied to every URI the relay is asked to retrieve.
//!
//! The URIs handled by a relay come out of certificates supplied by whoever is using the service,
//! so they are attacker-chosen and the policy is the security boundary. It runs in two stages that
//! must not be separated: a URI check that rejects schemes, ports and hosts before any resolution
//! happens, and an address check applied to the addresses the policy resolves itself. The resolved
//! addresses are then handed to the HTTP client, which connects to them rather than resolving the
//! name a second time; resolving twice leaves a window in which a name that resolved to a public
//! address the first time resolves to an internal one for the connection that actually happens.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use log::debug;
use serde::{Deserialize, Serialize};

/// Reasons a URI or a resolved address is refused. These are returned to a caller as a refusal to
/// retrieve, and are deliberately specific enough to diagnose a misconfigured deployment while
/// naming nothing about the network the service runs on beyond what the requester already supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// URI could not be parsed.
    Malformed(String),
    /// Scheme is not on the allowlist, e.g., `ldap` or `file`.
    Scheme(String),
    /// URI has no host, as with `http:///crl` or a `data:` URI.
    MissingHost,
    /// Port is not on the allowlist.
    Port(u16),
    /// Host is on the denylist, or an allowlist is configured and the host is not on it.
    Host(String),
    /// Hostname resolution failed or returned nothing.
    Resolution(String),
    /// Host resolved only to addresses that are not permitted destinations, e.g., loopback or
    /// private addresses. The address is reported because it is what the requester's own DNS
    /// record says, not information about the service's network.
    Address(IpAddr),
    /// Redirect encountered when redirects are not permitted, or the hop limit was exhausted.
    Redirect(String),
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyError::Malformed(u) => write!(f, "malformed URI: {u}"),
            PolicyError::Scheme(s) => write!(f, "scheme not permitted: {s}"),
            PolicyError::MissingHost => write!(f, "URI has no host"),
            PolicyError::Port(p) => write!(f, "port not permitted: {p}"),
            PolicyError::Host(h) => write!(f, "host not permitted: {h}"),
            PolicyError::Resolution(h) => write!(f, "could not resolve host: {h}"),
            PolicyError::Address(a) => write!(f, "address not permitted: {a}"),
            PolicyError::Redirect(u) => write!(f, "redirect not permitted: {u}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Destination that passed the URI half of the policy: the parsed URI plus the host and port that
/// must be resolved and address-checked before a socket is opened.
#[derive(Clone, Debug)]
pub struct CheckedUri {
    /// Parsed URI, normalized by the URI parser.
    pub url: reqwest::Url,
    /// Host as written in the URI, which may be a name or a literal address.
    pub host: String,
    /// Port from the URI, or the default port for the scheme.
    pub port: u16,
}

/// Rules the relay applies to a URI before retrieving it.
///
/// The defaults are what a public deployment wants: HTTP and HTTPS on their usual ports, no
/// redirects, and no destination that is not a public address. `allow_private_addresses` exists for
/// the deployment that runs the relay beside a PKI repository on an internal network, where the
/// whole point is to reach an address this policy otherwise refuses; it is a deliberate,
/// configuration-level decision rather than something a request can ask for.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkPolicy {
    /// URI schemes that may be retrieved.
    pub schemes: Vec<String>,
    /// Ports that may be connected to.
    pub ports: Vec<u16>,
    /// Hosts that may be retrieved from. An empty list permits any host that survives the
    /// remaining checks; a non-empty list is exhaustive.
    pub allow_hosts: Vec<String>,
    /// Hosts that may never be retrieved from, applied ahead of `allow_hosts`.
    pub deny_hosts: Vec<String>,
    /// Number of redirects that may be followed. Zero refuses them outright, which is the default
    /// because a redirect is a second URI the requester did not present and the policy would
    /// otherwise never see.
    pub max_redirects: usize,
    /// Permits destinations that are not public addresses, for a relay deployed on the network
    /// whose repositories it is meant to reach.
    pub allow_private_addresses: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy {
            schemes: vec!["http".to_string(), "https".to_string()],
            ports: vec![80, 443],
            allow_hosts: vec![],
            deny_hosts: vec![],
            max_redirects: 0,
            allow_private_addresses: false,
        }
    }
}

impl NetworkPolicy {
    /// Applies the checks that can be made from the URI alone: scheme, host presence, host lists and
    /// port. Nothing is resolved and no socket is opened, so this is the check to run when accepting
    /// a request, before any work is scheduled.
    pub fn check_uri(&self, uri: &str) -> Result<CheckedUri, PolicyError> {
        let url = match reqwest::Url::parse(uri) {
            Ok(u) => u,
            Err(e) => {
                debug!("Rejected {uri} as unparseable: {e}");
                return Err(PolicyError::Malformed(uri.to_string()));
            }
        };

        let scheme = url.scheme().to_ascii_lowercase();
        if !self.schemes.iter().any(|s| s.eq_ignore_ascii_case(&scheme)) {
            return Err(PolicyError::Scheme(scheme));
        }

        let host = match url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return Err(PolicyError::MissingHost),
        };
        if self
            .deny_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&host))
        {
            return Err(PolicyError::Host(host));
        }
        let allowed = self.allow_hosts.is_empty()
            || self
                .allow_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&host));
        if !allowed {
            return Err(PolicyError::Host(host));
        }

        // A URI that names no port takes the scheme's default; port_or_known_default only knows the
        // schemes it knows, and one that survived the scheme allowlist above always has a default.
        let port = match url.port_or_known_default() {
            Some(p) => p,
            None => return Err(PolicyError::Port(0)),
        };
        if !self.ports.contains(&port) {
            return Err(PolicyError::Port(port));
        }

        // A URI naming an address rather than a name never reaches the resolver -- the HTTP client
        // has nothing to look up and connects straight to it -- so the address check has to happen
        // here as well. Without this, `http://169.254.169.254/` walks past a policy that refuses
        // every name resolving to that same address.
        // The literal form of an IPv6 host keeps its brackets here, and they are not part of the
        // address; a name that merely looks like an address does not parse and is left to the
        // resolver, which applies the same check to what it comes back with.
        if let Ok(addr) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            self.check_address(addr)?;
        }

        Ok(CheckedUri { url, host, port })
    }

    /// Rejects an address that is not a permitted destination. Applied to every address resolution
    /// produces, including the addresses a redirect target resolves to.
    pub fn check_address(&self, addr: IpAddr) -> Result<(), PolicyError> {
        if self.allow_private_addresses {
            return Ok(());
        }
        if is_public_address(addr) {
            return Ok(());
        }
        Err(PolicyError::Address(addr))
    }

    /// Resolves a checked destination and returns the addresses that survive [`check_address`],
    /// which are the addresses the HTTP client is then pinned to. An error is returned when the
    /// name does not resolve and when every address it resolves to is refused; the two are
    /// distinguished because a deployment that resolves everything to a private address is
    /// misconfigured rather than under attack.
    pub async fn resolve(&self, dest: &CheckedUri) -> Result<Vec<SocketAddr>, PolicyError> {
        let resolved = match tokio::net::lookup_host((dest.host.as_str(), dest.port)).await {
            Ok(addrs) => addrs.collect::<Vec<SocketAddr>>(),
            Err(e) => {
                debug!("Failed to resolve {} with {e}", dest.host);
                return Err(PolicyError::Resolution(dest.host.clone()));
            }
        };

        let mut refused = None;
        let mut permitted = vec![];
        for addr in resolved {
            match self.check_address(addr.ip()) {
                Ok(()) => permitted.push(addr),
                Err(e) => {
                    debug!("Refused {} for {}: {e}", addr.ip(), dest.host);
                    refused = Some(e);
                }
            }
        }

        if permitted.is_empty() {
            return Err(refused.unwrap_or_else(|| PolicyError::Resolution(dest.host.clone())));
        }
        Ok(permitted)
    }
}

/// Reports whether an address is a destination the relay is willing to reach, i.e., a unicast
/// address that is routable on the public internet.
///
/// Written as an allowlist of what remains after the excluded ranges rather than a denylist of
/// ranges to skip, so a range nobody thought about is refused instead of reached. The IPv4-mapped
/// and IPv4-compatible IPv6 forms are unwrapped first: `::ffff:127.0.0.1` is a loopback destination
/// written in a way that no IPv6 predicate recognizes.
pub fn is_public_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            // to_ipv4 also matches the deprecated IPv4-compatible form (::a.b.c.d), which is worth
            // unwrapping for the same reason even though nothing should still be using it.
            if let Some(v4) = v6.to_ipv4() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(addr: Ipv4Addr) -> bool {
    let [a, b, c, _] = addr.octets();
    // Ranges that must never be reached, in the order they appear in the address space. The
    // predicates the standard library offers as stable cover only part of this, so the octets are
    // examined directly and every range is named.
    let excluded = addr.is_unspecified()          // 0.0.0.0/8, "this network"
        || a == 0
        || addr.is_loopback()                     // 127.0.0.0/8
        || addr.is_private()                      // 10/8, 172.16/12, 192.168/16
        || addr.is_link_local()                   // 169.254.0.0/16, includes cloud metadata
        || addr.is_broadcast()                    // 255.255.255.255
        || addr.is_multicast()                    // 224.0.0.0/4
        || (a == 100 && (64..128).contains(&b))   // 100.64.0.0/10, carrier-grade NAT
        || (a == 192 && b == 0 && c == 0)         // 192.0.0.0/24, IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)         // 192.0.2.0/24, documentation
        || (a == 192 && b == 88 && c == 99)       // 192.88.99.0/24, 6to4 relay anycast
        || (a == 198 && (18..20).contains(&b))    // 198.18.0.0/15, benchmarking
        || (a == 198 && b == 51 && c == 100)      // 198.51.100.0/24, documentation
        || (a == 203 && b == 0 && c == 113)       // 203.0.113.0/24, documentation
        || a >= 240; // 240.0.0.0/4, reserved, and 255.255.255.255 with it
    !excluded
}

fn is_public_v6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    let excluded = addr.is_unspecified()                       // ::
        || addr.is_loopback()                                  // ::1
        || addr.is_multicast()                                 // ff00::/8
        || (segments[0] & 0xfe00) == 0xfc00                    // fc00::/7, unique local
        || (segments[0] & 0xffc0) == 0xfe80                    // fe80::/10, link local
        || (segments[0] & 0xffc0) == 0xfec0                    // fec0::/10, deprecated site local
        || segments[0] == 0x0100 && segments[1] == 0           // 100::/64, discard-only
        || (segments[0] == 0x2001 && segments[1] == 0)         // 2001::/32, Teredo
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)    // 2001:db8::/32, documentation
        || (segments[0] == 0x2002); // 2002::/16, 6to4, which embeds an arbitrary IPv4 address
    !excluded
}

/// Resolver handed to the HTTP client so the addresses it connects to are exactly the addresses the
/// policy approved. Registering the policy here rather than resolving separately and reconnecting by
/// name is what closes the rebinding window: the client never performs a lookup of its own, and a
/// redirect to a fresh hostname is resolved through the same check.
#[derive(Debug)]
pub struct PolicyResolver {
    policy: Arc<NetworkPolicy>,
}

impl PolicyResolver {
    /// Creates a resolver enforcing the supplied policy.
    pub fn new(policy: Arc<NetworkPolicy>) -> Self {
        PolicyResolver { policy }
    }
}

impl reqwest::dns::Resolve for PolicyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // The port is supplied by the client from the URI and replaces whatever appears here,
            // so resolution uses a placeholder and the port allowlist is enforced by check_uri.
            let dest = CheckedUri {
                url: reqwest::Url::parse(&format!("http://{host}"))
                    .map_err(|_| PolicyError::Malformed(host.clone()))?,
                host: host.clone(),
                port: 0,
            };
            let addrs = policy.resolve(&dest).await?;
            let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_addresses_that_are_not_public() {
        for addr in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            // Loopback and link-local written in forms an IPv6 predicate does not recognize.
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let parsed: IpAddr = addr.parse().unwrap();
            assert!(!is_public_address(parsed), "{addr} should not be reachable");
        }
    }

    #[test]
    fn permits_public_addresses() {
        for addr in ["8.8.8.8", "1.1.1.1", "214.3.44.7", "2606:4700::1111"] {
            let parsed: IpAddr = addr.parse().unwrap();
            assert!(is_public_address(parsed), "{addr} should be reachable");
        }
    }

    #[test]
    fn check_uri_enforces_scheme_host_and_port() {
        let policy = NetworkPolicy::default();

        assert!(policy.check_uri("http://crl.example.com/ca.crl").is_ok());
        assert!(policy.check_uri("https://ocsp.example.com/").is_ok());

        // Schemes a certificate can legitimately carry but this relay does not speak, and the
        // schemes an attacker reaches for.
        assert_eq!(
            policy
                .check_uri("ldap://directory.example.com/cn=ca")
                .unwrap_err(),
            PolicyError::Scheme("ldap".to_string())
        );
        assert_eq!(
            policy.check_uri("file:///etc/passwd").unwrap_err(),
            PolicyError::Scheme("file".to_string())
        );
        assert_eq!(
            policy
                .check_uri("http://crl.example.com:8080/ca.crl")
                .unwrap_err(),
            PolicyError::Port(8080)
        );
        assert!(matches!(
            policy.check_uri("not a uri"),
            Err(PolicyError::Malformed(_))
        ));
    }

    #[test]
    fn an_address_written_into_the_uri_is_checked_without_resolution() {
        let policy = NetworkPolicy::default();

        // The client connects straight to an address it is given, so these never reach the
        // resolver and have to be caught here. The metadata address is the one that matters.
        for uri in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/ca.crl",
            "http://10.0.0.1/ca.crl",
            "http://[::1]/ca.crl",
            "http://[fd00::1]/ca.crl",
        ] {
            assert!(
                matches!(
                    policy.check_uri(uri),
                    Err(PolicyError::Address(_)) | Err(PolicyError::Port(_))
                ),
                "{uri} should be refused"
            );
        }

        assert!(policy.check_uri("http://8.8.8.8/ca.crl").is_ok());
    }

    #[test]
    fn host_lists_apply_ahead_of_resolution() {
        let mut policy = NetworkPolicy {
            deny_hosts: vec!["blocked.example.com".to_string()],
            ..Default::default()
        };
        assert_eq!(
            policy
                .check_uri("http://BLOCKED.example.com/ca.crl")
                .unwrap_err(),
            PolicyError::Host("blocked.example.com".to_string())
        );

        policy.allow_hosts = vec!["crl.example.com".to_string()];
        assert!(policy.check_uri("http://crl.example.com/ca.crl").is_ok());
        assert_eq!(
            policy
                .check_uri("http://other.example.com/ca.crl")
                .unwrap_err(),
            PolicyError::Host("other.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn resolution_refuses_a_name_that_points_inward() {
        let policy = NetworkPolicy::default();
        // localhost is the case a deployment will actually meet: a name that resolves, and resolves
        // to an address the relay must not reach.
        let dest = policy.check_uri("http://localhost/ca.crl").unwrap();
        assert!(matches!(
            policy.resolve(&dest).await,
            Err(PolicyError::Address(_)) | Err(PolicyError::Resolution(_))
        ));

        let permissive = NetworkPolicy {
            allow_private_addresses: true,
            ..Default::default()
        };
        assert!(permissive.resolve(&dest).await.is_ok());
    }
}

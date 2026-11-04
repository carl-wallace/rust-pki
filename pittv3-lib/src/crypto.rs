//! Which implementations verify signatures in a run, chosen with `--crypto`.
//!
//! certval consults its signature verification implementations in the order they were registered and
//! stops at the first verdict. A list of [`CryptoProvider`] values is that order: each one named is
//! registered in turn, and only those. [`CryptoProvider::Software`] is certval's own implementations, so
//! listed last it covers whatever the providers before it declined, and left out there is no software
//! fallback at all. An empty list means software alone, which is what a run did before the choice
//! existed.
//!
//! Every variant exists in every build, so a saved argument file names the same values everywhere. A
//! provider the build does not contain is refused when a run starts, by [`populate_with_crypto`].

use alloc::{format, string::String, vec::Vec};

use certval::{calculate_hash_rust_crypto, PkiEnvironment};
use serde::{Deserialize, Serialize};

/// An implementation `--crypto` can name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoProvider {
    /// certval's software implementations
    Software,
    /// Apple's Security.framework, on macOS
    SecurityFramework,
    /// Windows CNG
    Cng,
    /// AWS-LC
    AwsLc,
    /// The system's OpenSSL 3, on Linux and macOS in a build with the `openssl` feature
    Openssl,
}

impl CryptoProvider {
    /// Every provider, in the order the desktop app consults the ones checked: the platform's module
    /// first, then AWS-LC and OpenSSL, and certval's software last, where it covers what the others
    /// declined.
    pub const ALL: [CryptoProvider; 5] = [
        CryptoProvider::SecurityFramework,
        CryptoProvider::Cng,
        CryptoProvider::AwsLc,
        CryptoProvider::Openssl,
        CryptoProvider::Software,
    ];

    /// The name `--crypto` takes and a saved argument file holds.
    pub fn name(self) -> &'static str {
        match self {
            CryptoProvider::Software => "software",
            CryptoProvider::SecurityFramework => "security-framework",
            CryptoProvider::Cng => "cng",
            CryptoProvider::AwsLc => "aws-lc",
            CryptoProvider::Openssl => "openssl",
        }
    }

    /// The name a person reads in a log or a report.
    pub fn label(self) -> &'static str {
        match self {
            CryptoProvider::Software => "certval software",
            CryptoProvider::SecurityFramework => "Security.framework",
            CryptoProvider::Cng => "CNG",
            CryptoProvider::AwsLc => "AWS-LC",
            CryptoProvider::Openssl => "OpenSSL",
        }
    }

    /// Whether this build contains the provider.
    pub fn is_available(self) -> bool {
        match self {
            CryptoProvider::Software => true,
            CryptoProvider::SecurityFramework => {
                cfg!(all(feature = "crypto-providers", target_os = "macos"))
            }
            CryptoProvider::Cng => cfg!(all(feature = "crypto-providers", target_os = "windows")),
            CryptoProvider::AwsLc => {
                cfg!(all(
                    feature = "crypto-providers",
                    not(target_arch = "wasm32")
                ))
            }
            CryptoProvider::Openssl => cfg!(all(
                feature = "openssl",
                not(any(windows, target_arch = "wasm32"))
            )),
        }
    }

    /// The providers this build contains, in the order of [`ALL`](Self::ALL).
    pub fn available() -> Vec<CryptoProvider> {
        Self::ALL.into_iter().filter(|p| p.is_available()).collect()
    }

    /// What the provider reports about FIPS mode, or `None` for certval's software, which makes no
    /// claim. Security.framework has no mode to report: Apple's validated module is the one it calls.
    pub fn fips_status(self) -> Option<&'static str> {
        match self {
            CryptoProvider::Software => None,
            CryptoProvider::SecurityFramework => Some("Apple corecrypto, no FIPS mode to report"),
            CryptoProvider::Cng => Some(cng_fips_status()),
            CryptoProvider::AwsLc => Some(awslc_fips_status()),
            CryptoProvider::Openssl => Some(openssl_fips_status()),
        }
    }
}

#[cfg(all(feature = "crypto-providers", target_os = "windows"))]
fn cng_fips_status() -> &'static str {
    match certval_cng::CngCrypto::fips_mode_enabled() {
        Some(true) => "FIPS mode on",
        Some(false) => "FIPS mode off",
        None => "FIPS mode unknown",
    }
}

#[cfg(not(all(feature = "crypto-providers", target_os = "windows")))]
fn cng_fips_status() -> &'static str {
    "not in this build"
}

#[cfg(all(feature = "crypto-providers", not(target_arch = "wasm32")))]
fn awslc_fips_status() -> &'static str {
    on_off(certval_awslc::AwsLcCrypto::fips_mode_enabled())
}

#[cfg(not(all(feature = "crypto-providers", not(target_arch = "wasm32"))))]
fn awslc_fips_status() -> &'static str {
    "not in this build"
}

#[cfg(all(feature = "openssl", not(any(windows, target_arch = "wasm32"))))]
fn openssl_fips_status() -> &'static str {
    on_off(certval_openssl::OpenSslCrypto::fips_mode_enabled())
}

#[cfg(not(all(feature = "openssl", not(any(windows, target_arch = "wasm32")))))]
fn openssl_fips_status() -> &'static str {
    "not in this build"
}

#[cfg(any(
    all(feature = "crypto-providers", not(target_arch = "wasm32")),
    all(feature = "openssl", not(any(windows, target_arch = "wasm32")))
))]
fn on_off(enabled: bool) -> &'static str {
    if enabled {
        "FIPS mode on"
    } else {
        "FIPS mode off"
    }
}

/// The providers a list names, in order, each with its FIPS status, for a log line or a report header.
/// An empty list reads as certval software, which is what it means.
pub fn describe(providers: &[CryptoProvider]) -> String {
    let providers = if providers.is_empty() {
        &[CryptoProvider::Software][..]
    } else {
        providers
    };
    providers
        .iter()
        .map(|p| match p.fips_status() {
            Some(status) => format!("{} ({status})", p.label()),
            None => String::from(p.label()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Registers certval's RFC 5280 implementations on `pe`, with signature verification done by the
/// providers `providers` names, in that order and no others. Used where a run would otherwise call
/// [`PkiEnvironment::populate_5280_pki_environment`], and registers everything that call does.
///
/// An empty list, or one naming only [`CryptoProvider::Software`], registers exactly what
/// `populate_5280_pki_environment` does. A provider this build does not contain is refused, and `pe`
/// is left unchanged.
///
/// Hashing goes to the first listed provider that offers it, with certval's software appended when
/// software is listed or none does (Security.framework has no hash interface).
pub fn populate_with_crypto(
    pe: &mut PkiEnvironment,
    providers: &[CryptoProvider],
) -> Result<(), String> {
    if let Some(p) = providers.iter().find(|p| !p.is_available()) {
        return Err(format!("{} is not available in this build", p.name()));
    }

    let software_listed = providers.is_empty() || providers.contains(&CryptoProvider::Software);
    if !software_listed {
        // populate_5280_pki_environment registers more than crypto (path validation, OID lookup), so
        // it runs regardless and its software crypto is then removed.
        pe.populate_5280_pki_environment();
        pe.clear_calculate_hash_callbacks();
        pe.clear_verify_signature_digest_callbacks();
        pe.clear_verify_signature_message_callbacks();
        pe.clear_verify_signature_message_ctx_callbacks();
    }

    // Software hashing arrives with populate_5280_pki_environment whenever software is listed.
    let mut hashes = software_listed;
    let mut populated = !software_listed;
    for p in providers {
        match p {
            // certval's software takes its place in the order by registering everything at this
            // point, after the providers named before it; named again, it has nothing to add.
            CryptoProvider::Software => {
                if !populated {
                    pe.populate_5280_pki_environment();
                    populated = true;
                }
            }
            CryptoProvider::SecurityFramework => register_security_framework(pe),
            CryptoProvider::Cng => hashes |= register_cng(pe),
            CryptoProvider::AwsLc => hashes |= register_awslc(pe),
            CryptoProvider::Openssl => hashes |= register_openssl(pe),
        }
    }
    if !populated {
        pe.populate_5280_pki_environment();
    }
    if !hashes {
        pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    }
    Ok(())
}

#[cfg(all(feature = "crypto-providers", target_os = "macos"))]
fn register_security_framework(pe: &mut PkiEnvironment) {
    use certval_security_framework::SecurityFrameworkCrypto;
    pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
    pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
}

#[cfg(not(all(feature = "crypto-providers", target_os = "macos")))]
fn register_security_framework(_pe: &mut PkiEnvironment) {}

/// Registers CNG, returning whether it registered a hash implementation.
#[cfg(all(feature = "crypto-providers", target_os = "windows"))]
fn register_cng(pe: &mut PkiEnvironment) -> bool {
    use certval_cng::CngCrypto;
    pe.add_calculate_hash_callback(CngCrypto::new());
    pe.add_verify_signature_message_callback(CngCrypto::new());
    pe.add_verify_signature_digest_callback(CngCrypto::new());
    true
}

#[cfg(not(all(feature = "crypto-providers", target_os = "windows")))]
fn register_cng(_pe: &mut PkiEnvironment) -> bool {
    false
}

/// Registers AWS-LC, returning whether it registered a hash implementation.
#[cfg(all(feature = "crypto-providers", not(target_arch = "wasm32")))]
fn register_awslc(pe: &mut PkiEnvironment) -> bool {
    use certval_awslc::AwsLcCrypto;
    pe.add_calculate_hash_callback(AwsLcCrypto::new());
    pe.add_verify_signature_message_callback(AwsLcCrypto::new());
    pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
    true
}

#[cfg(not(all(feature = "crypto-providers", not(target_arch = "wasm32"))))]
fn register_awslc(_pe: &mut PkiEnvironment) -> bool {
    false
}

/// Registers OpenSSL, returning whether it registered a hash implementation.
#[cfg(all(feature = "openssl", not(any(windows, target_arch = "wasm32"))))]
fn register_openssl(pe: &mut PkiEnvironment) -> bool {
    use certval_openssl::OpenSslCrypto;
    pe.add_calculate_hash_callback(OpenSslCrypto::new());
    pe.add_verify_signature_message_callback(OpenSslCrypto::new());
    pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
    true
}

#[cfg(not(all(feature = "openssl", not(any(windows, target_arch = "wasm32")))))]
fn register_openssl(_pe: &mut PkiEnvironment) -> bool {
    false
}

/// Parses `--crypto` and offers only the providers this build contains as its possible values.
#[cfg(feature = "clap")]
impl clap::ValueEnum for CryptoProvider {
    fn value_variants<'a>() -> &'a [Self] {
        static AVAILABLE: std::sync::OnceLock<Vec<CryptoProvider>> = std::sync::OnceLock::new();
        AVAILABLE.get_or_init(CryptoProvider::available)
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.name()).help(self.label()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use certval::{is_self_signed, parse_cert};
    use der::asn1::ObjectIdentifier;
    use spki::AlgorithmIdentifierOwned;

    /// PKITS' P-256 trust anchor, self-signed with ecdsa-with-SHA256: certval's software verifies it
    /// in every build, without the `rsa` feature.
    const ROOT: &[u8] = include_bytes!(
        "../../certval/tests/examples/PKITS_data_p256/certs/TrustAnchorRootCertificate.crt"
    );
    /// An end entity certificate from the same set, which its own key does not verify.
    const EE: &[u8] = include_bytes!(
        "../../certval/tests/examples/PKITS_data_p256/certs/ValidCertificatePathTest1EE.crt"
    );

    fn environment(providers: &[CryptoProvider]) -> PkiEnvironment {
        let mut pe = PkiEnvironment::default();
        populate_with_crypto(&mut pe, providers).unwrap();
        pe
    }

    fn self_signed(pe: &PkiEnvironment, der: &[u8]) -> bool {
        is_self_signed(pe, &parse_cert(der, "").unwrap()).unwrap()
    }

    #[test]
    fn each_available_provider_alone_reaches_both_verdicts() {
        for p in CryptoProvider::available() {
            let pe = environment(&[p]);
            assert!(
                self_signed(&pe, ROOT),
                "{} did not verify the root",
                p.name()
            );
            assert!(
                !self_signed(&pe, EE),
                "{} did not reject the end entity",
                p.name()
            );
        }
    }

    #[test]
    fn empty_list_is_software() {
        let pe = environment(&[]);
        assert!(self_signed(&pe, ROOT));
        assert!(!self_signed(&pe, EE));
        assert_eq!(describe(&[]), "certval software");
    }

    #[test]
    fn providers_before_software_keep_the_fallback() {
        let mut list = CryptoProvider::available();
        list.retain(|p| *p != CryptoProvider::Software);
        list.push(CryptoProvider::Software);
        let pe = environment(&list);
        assert!(self_signed(&pe, ROOT));
        assert!(!self_signed(&pe, EE));
    }

    #[test]
    fn hashing_survives_a_provider_without_a_hash_interface() {
        for p in CryptoProvider::available() {
            let pe = environment(&[p]);
            let sha256 = AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
                parameters: None,
            };
            assert_eq!(
                pe.calculate_hash(&pe, &sha256, b"abc").unwrap().len(),
                32,
                "{} left no hash implementation",
                p.name()
            );
        }
    }

    #[test]
    fn unavailable_provider_is_refused() {
        let Some(missing) = CryptoProvider::ALL.into_iter().find(|p| !p.is_available()) else {
            return;
        };
        let mut pe = PkiEnvironment::default();
        let e = populate_with_crypto(&mut pe, &[missing]).unwrap_err();
        assert!(e.contains(missing.name()));
    }

    #[test]
    fn names_round_trip_through_serde() {
        for p in CryptoProvider::ALL {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.name()));
            assert_eq!(serde_json::from_str::<CryptoProvider>(&json).unwrap(), p);
        }
    }
}

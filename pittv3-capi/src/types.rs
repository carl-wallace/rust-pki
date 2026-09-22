//! What a CAPI run is asked for and what it reports back.
//!
//! Deliberately not translated into [`certval`]'s vocabulary. A CAPI verdict is two bit masks per
//! chain and per element plus, separately, one `HRESULT` from the policy check; certval's verdict is
//! a `PathValidationStatus`. Several CAPI conditions have no counterpart at all —
//! `CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT` is one — so a mapping would have to invent an answer
//! for them, and an invented answer in one column of a comparison is worse than no column.
//!
//! The one thing that *is* shared is how a certificate is described: each element carries a
//! [`CertSummary`], built by the same code that builds one for a certval path. Two columns
//! disagreeing about a subject name or a digest would be a difference in rendering rather than in
//! validation, which is exactly the noise this tool exists to remove.
//!
//! Nothing in this module is `unsafe` or Windows-specific; [`verify`](crate::verify) is where the
//! platform lives.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use pittv3_lib::report::CertSummary;

use crate::status::{CapiError, CapiTrustStatus};

/// How much of a chain the engine is asked to check revocation for.
///
/// The default is [`ChainExcludeRoot`](RevocationChecking::ChainExcludeRoot), which is what PITTv2
/// asked for: a root is trusted by being in the store rather than by a status check, and asking for
/// one invites a `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` on every clean path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RevocationChecking {
    /// No revocation checking at all.
    None,
    /// The end certificate only.
    EndCertOnly,
    /// Every certificate in the chain, including the root.
    Chain,
    /// Every certificate in the chain except the root.
    #[default]
    ChainExcludeRoot,
}

/// Whether a requested usage or issuance policy list is satisfied by any one entry or by all of
/// them, mapping onto `USAGE_MATCH_TYPE_OR` and `USAGE_MATCH_TYPE_AND`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UsageMatch {
    /// Any one of the listed identifiers suffices. This is what PITTv2 asked for when it fed an
    /// initial policy set to the chain engine.
    #[default]
    Or,
    /// Every listed identifier must be present.
    And,
}

/// Which `CertVerifyCertificateChainPolicy` policy provider judges the built chain.
///
/// [`Base`](ChainPolicy::Base) is the default and is what PITTv2 used. Its comment there —
/// "CERT_CHAIN_POLICY_BASIC_CONSTRAINTS is apparently required to enforce basic constraints" — sat
/// above a call that passed `CERT_CHAIN_POLICY_BASE` anyway, with the other spelling commented out.
/// Both are offered here so the question can be answered by running it rather than by reading a
/// comment that contradicts the line under it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChainPolicy {
    /// `CERT_CHAIN_POLICY_BASE` — the implicit base policy.
    #[default]
    Base,
    /// `CERT_CHAIN_POLICY_BASIC_CONSTRAINTS`.
    BasicConstraints,
    /// `CERT_CHAIN_POLICY_AUTHENTICODE`.
    Authenticode,
    /// `CERT_CHAIN_POLICY_SSL`.
    Ssl,
    /// `CERT_CHAIN_POLICY_NT_AUTH`.
    NtAuth,
    /// `CERT_CHAIN_POLICY_EV`.
    Ev,
}

/// What a CAPI run is asked to do.
///
/// The [`Default`] is PITTv2's configuration: revocation over the chain excluding the root,
/// lower-quality chains returned, not-time-nested ignored by the policy check, and the base policy
/// provider — so a run with no options set is the comparison PITTv2 offered.
#[derive(Clone, Debug)]
pub struct CapiOptions {
    /// Build the chain but do not run the policy check.
    ///
    /// The distinction matters more than it looks: `CertGetCertificateChain` already reports a
    /// trust status, so a build-only run is not "no verdict" — it is the engine's verdict without
    /// the policy provider's. A chain that builds cleanly and then fails the policy check is one of
    /// the more interesting things this tool can show.
    pub build_only: bool,

    /// How much of the chain to check revocation for.
    pub revocation: RevocationChecking,

    /// Ask for `CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS`, so the engine reports the paths it
    /// rejected alongside the one it preferred.
    ///
    /// On by default. For a tool whose subject is path *building*, the rejected paths are half the
    /// answer: CAPI returning one chain where certval found three is a finding, and it is invisible
    /// without this.
    pub return_lower_quality_chains: bool,

    /// `CERT_CHAIN_PARA::dwUrlRetrievalTimeout`, in milliseconds. Zero means the platform default.
    pub url_retrieval_timeout_ms: u32,

    /// Extended key usage OIDs the chain must be good for, as dotted decimal.
    pub requested_usage: Vec<String>,

    /// Certificate policy OIDs to seed the chain engine with, as dotted decimal — the CAPI
    /// counterpart of certval's initial policy set.
    ///
    /// PITTv2 had this working and then commented it out wholesale, leaking an OID array on every
    /// call in the process. It is a first-class option here because feeding both validators the
    /// same initial policy set is the only way a policy-processing comparison means anything.
    pub requested_issuance_policy: Vec<String>,

    /// Whether the two lists above are satisfied by any entry or by all of them.
    pub usage_match: UsageMatch,

    /// Which policy provider judges the chain.
    pub policy: ChainPolicy,

    /// Pass `CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG` to the policy check, as PITTv2 did.
    pub ignore_not_time_nested: bool,

    /// Time of interest as Unix seconds, or `None` for the current time.
    ///
    /// PITTv2 always passed `NULL` here, i.e. now, which makes a run against archived test material
    /// fail for a reason that has nothing to do with the material. Setting it is what lets the same
    /// inputs be put to both validators at the same instant.
    pub time_of_interest: Option<u64>,

    /// Trust anchors to validate against, DER-encoded, *instead of* the Windows stores.
    ///
    /// Empty means the default chain engine, i.e. this machine's trust — which is the question
    /// "Validate Using CAPI" normally asks. Supplying anchors builds an engine with an exclusive
    /// root store instead, which is what makes a comparison controlled: put the same anchors to
    /// both validators and any difference in the answer is a difference between the validators.
    pub trust_anchors: Vec<Vec<u8>>,

    /// Additional intermediate CA certificates to offer the builder, DER-encoded.
    ///
    /// Handed over as `hAdditionalStore`, so they are candidates rather than trusted.
    pub additional_certs: Vec<Vec<u8>>,
}

impl Default for CapiOptions {
    fn default() -> Self {
        CapiOptions {
            build_only: false,
            revocation: RevocationChecking::ChainExcludeRoot,
            return_lower_quality_chains: true,
            url_retrieval_timeout_ms: 0,
            requested_usage: Vec::new(),
            requested_issuance_policy: Vec::new(),
            usage_match: UsageMatch::Or,
            policy: ChainPolicy::Base,
            ignore_not_time_nested: true,
            time_of_interest: None,
            trust_anchors: Vec::new(),
            additional_certs: Vec::new(),
        }
    }
}

/// Everything one CAPI run reported about one target certificate.
#[derive(Clone, Debug, PartialEq)]
pub struct CapiVerification {
    /// The target as this crate describes certificates, or `None` when certval could not parse the
    /// bytes CAPI accepted.
    ///
    /// That combination is not a defect to be smoothed over: CAPI accepting what certval rejects is
    /// a finding, and a run that refused to report it would be hiding the most interesting result
    /// the tool can produce. [`target_der`](Self::target_der) always holds the bytes.
    pub target: Option<CertSummary>,

    /// The bytes handed in, kept so a report can offer them whether or not they parsed.
    pub target_der: Vec<u8>,

    /// Chains the engine built: the preferred one first, then any lower-quality contexts, each
    /// flagged by [`CapiChain::lower_quality`].
    pub chains: Vec<CapiChain>,

    /// The trust status of the chain context as a whole, which is not simply the first chain's:
    /// `CERT_CHAIN_CONTEXT::TrustStatus` is the engine's summary across the context.
    pub trust_status: CapiTrustStatus,

    /// The policy check's verdict, or `None` when [`CapiOptions::build_only`] was set or the check
    /// passed.
    pub policy_error: Option<CapiError>,

    /// Where the policy check laid the blame, as `(chain index, element index)`, when it said.
    ///
    /// Either component is `-1` in the Win32 structure when not applicable, which is preserved
    /// rather than normalized away: "the chain as a whole" and "element 0" are different claims.
    pub policy_error_location: Option<(i32, i32)>,

    /// Whether the run counts as a pass: a chain was built, the context's trust status is clean and
    /// the policy check — when it ran — raised nothing.
    ///
    /// PITTv2 computed this as `validated & (chainStatus == 0)` where `validated` came only from
    /// the policy check, which meant a build-only run reported every target as invalid regardless
    /// of what the engine found. Here a build-only run is judged on the trust status it actually
    /// has.
    pub validated: bool,
}

/// One chain the engine built.
#[derive(Clone, Debug, PartialEq)]
pub struct CapiChain {
    /// Position in [`CapiVerification::chains`], preserving the order the engine reported.
    pub index: usize,

    /// Whether this came from `rgpLowerQualityChainContext` — a path the engine built and then
    /// declined to prefer.
    pub lower_quality: bool,

    /// `CERT_SIMPLE_CHAIN::TrustStatus`.
    pub trust_status: CapiTrustStatus,

    /// The chain's certificates, ordered from the target outward to the root, as CAPI orders them.
    ///
    /// Note this is the reverse of certval's ordering, which runs from the trust anchor to the
    /// target. Reversing it here would make the two columns line up on screen at the cost of
    /// reporting something other than what the engine returned; a consumer that wants them
    /// side by side can reverse it at the point of display, where the choice is visible.
    pub elements: Vec<CapiElement>,
}

/// One certificate within a chain, with the engine's verdict on it.
#[derive(Clone, Debug, PartialEq)]
pub struct CapiElement {
    /// The certificate as this crate describes certificates, or `None` when certval could not parse
    /// what the engine handed back — see [`CapiVerification::target`].
    pub cert: Option<CertSummary>,

    /// The certificate's encoding, always present.
    pub der: Vec<u8>,

    /// `CERT_CHAIN_ELEMENT::TrustStatus` — this certificate's own verdict, which can be clean on an
    /// element of a chain that failed elsewhere.
    pub trust_status: CapiTrustStatus,

    /// What the engine found out about this certificate's revocation status, when it looked.
    pub revocation: Option<CapiRevocationInfo>,

    /// `CERT_CHAIN_ELEMENT::pwszExtendedErrorInfo`, when the engine supplied any.
    pub extended_error_info: Option<String>,
}

/// `CERT_REVOCATION_INFO` for one element.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CapiRevocationInfo {
    /// `dwRevocationResult` — zero when the check succeeded, otherwise an `HRESULT` describing why
    /// it did not. Rendered through [`CapiError`], which is the right namespace for it.
    pub result: u32,

    /// `pszRevocationOid`, naming the mechanism used.
    pub oid: Option<String>,

    /// `dwFreshnessTime` in seconds, present only when `fHasFreshnessTime` was set.
    pub freshness_time: Option<u32>,

    /// The CRL the engine reached its conclusion from, when it used one.
    pub crl: Option<CapiCrlInfo>,
}

impl CapiRevocationInfo {
    /// Whether the revocation check succeeded.
    pub fn is_ok(&self) -> bool {
        self.result == 0
    }

    /// One line describing the outcome.
    pub fn describe(&self) -> String {
        let mut s = if self.is_ok() {
            String::from("revocation check succeeded")
        } else {
            CapiError(self.result).describe()
        };
        if let Some(oid) = &self.oid {
            s.push_str(&format!(" [{oid}]"));
        }
        s
    }
}

/// The CRL behind a revocation result, as far as `CERT_REVOCATION_CRL_INFO` reports it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CapiCrlInfo {
    /// Issuer of the base CRL, rendered the same way every other name here is — by decoding the CRL
    /// the engine handed back rather than by asking CAPI to format it, so one name has one
    /// spelling across both columns of a comparison.
    pub issuer: Option<String>,

    /// `thisUpdate` of the base CRL.
    pub this_update: Option<String>,

    /// `nextUpdate` of the base CRL, absent when the CRL carries none.
    pub next_update: Option<String>,

    /// Set when the engine matched the certificate to an entry, i.e. found it revoked.
    pub entry: Option<CapiCrlEntry>,

    /// Whether the matched entry came from a delta CRL rather than the base.
    pub entry_from_delta: bool,

    /// Issuer of the delta CRL, when one was used.
    pub delta_issuer: Option<String>,

    /// `thisUpdate` of the delta CRL, when one was used.
    pub delta_this_update: Option<String>,

    /// `nextUpdate` of the delta CRL, when one was used and it carries one.
    pub delta_next_update: Option<String>,
}

/// The CRL entry the engine matched the certificate to.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CapiCrlEntry {
    /// Serial number of the revoked certificate, uppercase ASCII hex in the order it appears in the
    /// CRL.
    ///
    /// Not byte-reversed. PITTv2 reversed CAPI serial numbers before printing them, because
    /// `CRYPT_INTEGER_BLOB` holds them little-endian; the reversal here happens at the boundary in
    /// [`verify`](crate::verify) so that what reaches this field reads the same as the serial on a
    /// certval row.
    pub serial: String,

    /// Revocation date.
    pub revocation_date: Option<String>,
}

/// Why a CAPI run could not produce a verdict.
///
/// A chain that built and then failed is not an error — it is a [`CapiVerification`] with
/// [`validated`](CapiVerification::validated) false. These are the cases where the engine was not
/// reached or would not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapiVerifyError {
    /// `CertCreateCertificateContext` refused the target bytes: CAPI would not parse them as a
    /// certificate. Carries the `HRESULT`.
    ///
    /// The mirror image of [`CapiVerification::target`] being `None`, and just as much a finding:
    /// certval parsing what CAPI rejects is worth knowing.
    TargetNotParsed(u32),

    /// `CertGetCertificateChain` failed outright, as distinct from building a chain it then found
    /// fault with. Carries the `HRESULT`.
    ChainBuildFailed(u32),

    /// `CertVerifyCertificateChainPolicy` itself failed, as distinct from reporting a policy error.
    /// Carries the `HRESULT`.
    PolicyCheckFailed(u32),

    /// A certificate store could not be created or populated for the supplied trust anchors or
    /// additional certificates. Carries the `HRESULT`.
    StoreFailed(u32),

    /// A chain engine could not be created for the supplied trust anchors. Carries the `HRESULT`.
    EngineFailed(u32),

    /// An OID in [`CapiOptions::requested_usage`] or
    /// [`CapiOptions::requested_issuance_policy`] could not be passed to Win32, which takes them as
    /// C strings — so an interior NUL makes one unrepresentable.
    InvalidOid(String),

    /// The build is not for Windows, so there is no chain engine to ask.
    ///
    /// Present on every target so a caller can name the case without a `cfg`; only ever returned on
    /// a non-Windows build.
    Unsupported,
}

impl fmt::Display for CapiVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapiVerifyError::TargetNotParsed(e) => write!(
                f,
                "CAPI would not parse the target as a certificate: {}",
                CapiError(*e)
            ),
            CapiVerifyError::ChainBuildFailed(e) => {
                write!(f, "CertGetCertificateChain failed: {}", CapiError(*e))
            }
            CapiVerifyError::PolicyCheckFailed(e) => write!(
                f,
                "CertVerifyCertificateChainPolicy failed: {}",
                CapiError(*e)
            ),
            CapiVerifyError::StoreFailed(e) => {
                write!(f, "could not build a certificate store: {}", CapiError(*e))
            }
            CapiVerifyError::EngineFailed(e) => {
                write!(f, "could not create a chain engine: {}", CapiError(*e))
            }
            CapiVerifyError::InvalidOid(oid) => {
                write!(f, "OID cannot be passed to Win32 as a C string: {oid}")
            }
            CapiVerifyError::Unsupported => {
                write!(f, "CAPI validation is only available on Windows")
            }
        }
    }
}

impl std::error::Error for CapiVerifyError {}

/// Seconds between the Windows epoch (1601-01-01) and the Unix epoch.
const FILETIME_UNIX_DELTA_SECS: i64 = 11_644_473_600;

/// A `FILETIME`, as its two halves, converted to Unix seconds.
///
/// Taken as two `u32`s rather than as the Win32 structure so the arithmetic is testable on any
/// target — it is the one part of the boundary that is easy to get wrong and has no platform in it.
/// Returns `None` for a value outside what Unix seconds can express, which in practice means a zero
/// `FILETIME`: the engine leaves one in place of a date it has not got, and treating that as
/// 1601-01-01 would put a fabricated date in a report.
pub fn filetime_to_unix_secs(low: u32, high: u32) -> Option<i64> {
    let ticks = ((high as u64) << 32) | (low as u64);
    if ticks == 0 {
        return None;
    }
    // 100-nanosecond intervals since 1601-01-01.
    let secs_since_1601 = (ticks / 10_000_000) as i64;
    Some(secs_since_1601 - FILETIME_UNIX_DELTA_SECS)
}

/// Renders Unix seconds the way the rest of a PITTv3 report renders a certificate's validity dates.
///
/// Returns `None` rather than a placeholder for a value that will not convert, for the reason given
/// on [`filetime_to_unix_secs`].
pub fn unix_secs_to_string(secs: i64) -> Option<String> {
    let secs = u64::try_from(secs).ok()?;
    der::DateTime::from_unix_duration(core::time::Duration::from_secs(secs))
        .ok()
        .map(|dt| dt.to_string())
}

/// Convenience for the pair, which is how it is always used at the boundary.
pub fn filetime_to_string(low: u32, high: u32) -> Option<String> {
    filetime_to_unix_secs(low, high).and_then(unix_secs_to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is PITTv2's configuration, so a caller that sets nothing gets the comparison
    /// PITTv2 offered rather than a weaker one.
    #[test]
    fn default_options_match_pittv2() {
        let o = CapiOptions::default();
        assert!(!o.build_only);
        assert_eq!(o.revocation, RevocationChecking::ChainExcludeRoot);
        assert!(o.return_lower_quality_chains);
        assert!(o.ignore_not_time_nested);
        assert_eq!(o.policy, ChainPolicy::Base);
        assert_eq!(o.usage_match, UsageMatch::Or);
        assert!(o.time_of_interest.is_none());
        assert!(o.trust_anchors.is_empty());
    }

    /// A zero `FILETIME` is the engine saying it has no date, not 1601-01-01.
    #[test]
    fn zero_filetime_is_absent_not_1601() {
        assert_eq!(filetime_to_unix_secs(0, 0), None);
        assert_eq!(filetime_to_string(0, 0), None);
    }

    /// The conversion lands on the instant the PKITS material is validated at, which is the same
    /// value `pittv3-gui-lib`'s tests use. 1_648_039_783 Unix = 2022-03-23T12:49:43Z.
    #[test]
    fn filetime_converts_to_the_pkits_time_of_interest() {
        let unix: i64 = 1_648_039_783;
        let ticks = ((unix + FILETIME_UNIX_DELTA_SECS) as u64) * 10_000_000;
        let low = (ticks & 0xFFFF_FFFF) as u32;
        let high = (ticks >> 32) as u32;

        assert_eq!(filetime_to_unix_secs(low, high), Some(unix));
        assert_eq!(
            filetime_to_string(low, high).as_deref(),
            Some("2022-03-23T12:49:43Z")
        );
    }

    /// The Unix epoch itself, where the delta is the whole of the value.
    #[test]
    fn filetime_at_the_unix_epoch() {
        let ticks = (FILETIME_UNIX_DELTA_SECS as u64) * 10_000_000;
        let low = (ticks & 0xFFFF_FFFF) as u32;
        let high = (ticks >> 32) as u32;
        assert_eq!(filetime_to_unix_secs(low, high), Some(0));
        assert_eq!(
            filetime_to_string(low, high).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
    }

    /// A date before 1970 converts to a negative Unix value and is reported as having no rendering
    /// rather than wrapping into the far future, which is what an unchecked cast to `u64` would do.
    #[test]
    fn pre_unix_epoch_filetime_has_no_rendering() {
        let ticks = 10_000_000u64; // one second after 1601-01-01
        let low = (ticks & 0xFFFF_FFFF) as u32;
        let high = (ticks >> 32) as u32;
        assert_eq!(
            filetime_to_unix_secs(low, high),
            Some(1 - FILETIME_UNIX_DELTA_SECS)
        );
        assert_eq!(filetime_to_string(low, high), None);
    }

    /// A revocation result of zero is a success and says so; a non-zero one is an HRESULT and is
    /// described as one, with the mechanism named when the engine named it.
    #[test]
    fn revocation_info_describes_both_outcomes() {
        let ok = CapiRevocationInfo {
            result: 0,
            oid: Some("1.3.6.1.5.5.7.48.1".into()),
            ..Default::default()
        };
        assert!(ok.is_ok());
        assert_eq!(
            ok.describe(),
            "revocation check succeeded [1.3.6.1.5.5.7.48.1]"
        );

        let revoked = CapiRevocationInfo {
            result: 0x8009_2010,
            ..Default::default()
        };
        assert!(!revoked.is_ok());
        assert!(revoked.describe().starts_with("CRYPT_E_REVOKED"));
    }

    /// Each error renders its own code, so a caller printing one is not left guessing which call
    /// failed.
    #[test]
    fn errors_name_the_call_that_failed() {
        assert!(CapiVerifyError::ChainBuildFailed(0x800B_010A)
            .to_string()
            .contains("CertGetCertificateChain"));
        assert!(CapiVerifyError::TargetNotParsed(0x8009_2002)
            .to_string()
            .contains("would not parse"));
        assert!(CapiVerifyError::InvalidOid("2.5.29\0.32".into())
            .to_string()
            .contains("2.5.29"));
        assert_eq!(
            CapiVerifyError::Unsupported.to_string(),
            "CAPI validation is only available on Windows"
        );
    }
}

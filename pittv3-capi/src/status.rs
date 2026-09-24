//! Decoding of the two status vocabularies CAPI answers in.
//!
//! The chain engine reports in two entirely separate namespaces, and keeping them apart is the
//! whole job of this module:
//!
//! - [`CapiTrustStatus`] — the `CERT_TRUST_STATUS` pair of bit masks (`dwErrorStatus` and
//!   `dwInfoStatus`) carried by every chain and by every element within it.
//! - [`CapiError`] — the single `HRESULT` that `CertVerifyCertificateChainPolicy` leaves in
//!   `CERT_CHAIN_POLICY_STATUS::dwError`.
//!
//! PITTv2 ran both through one `GetCAPIErrorText` switch, whose `default:` arm decoded its argument
//! as trust-status bits. That arm is only ever right for one of the two callers: an `HRESULT` such
//! as `CERT_E_INVALID_POLICY` (0x800B0113) that the switch has no case for falls into it and comes
//! back described as a handful of unrelated trust bits, because 0x800B0113 has those bits set the
//! way any number does. Two types, decoded by two functions, is the fix.
//!
//! Nothing here is `unsafe` or Windows-specific: the flag values are constants and the decoding is
//! arithmetic, so it builds and tests on any target. A Windows-only test in
//! [`verify`](crate::verify) checks each constant below against the one the `windows` crate
//! defines, so a transcription slip here fails a build rather than quietly mislabeling a verdict.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// `CERT_TRUST_STATUS::dwErrorStatus` flags, paired with the name Windows gives each.
///
/// Ordered by bit value rather than by importance, so that [`CapiTrustStatus::error_names`]
/// produces a stable, reproducible list — two runs that found the same thing read identically, and
/// a diff between two runs is a difference in findings rather than in ordering.
pub const ERROR_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "CERT_TRUST_IS_NOT_TIME_VALID"),
    (0x0000_0002, "CERT_TRUST_IS_NOT_TIME_NESTED"),
    (0x0000_0004, "CERT_TRUST_IS_REVOKED"),
    (0x0000_0008, "CERT_TRUST_IS_NOT_SIGNATURE_VALID"),
    (0x0000_0010, "CERT_TRUST_IS_NOT_VALID_FOR_USAGE"),
    (0x0000_0020, "CERT_TRUST_IS_UNTRUSTED_ROOT"),
    (0x0000_0040, "CERT_TRUST_REVOCATION_STATUS_UNKNOWN"),
    (0x0000_0080, "CERT_TRUST_IS_CYCLIC"),
    (0x0000_0100, "CERT_TRUST_INVALID_EXTENSION"),
    (0x0000_0200, "CERT_TRUST_INVALID_POLICY_CONSTRAINTS"),
    (0x0000_0400, "CERT_TRUST_INVALID_BASIC_CONSTRAINTS"),
    (0x0000_0800, "CERT_TRUST_INVALID_NAME_CONSTRAINTS"),
    (0x0000_1000, "CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT"),
    (0x0000_2000, "CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT"),
    (0x0000_4000, "CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT"),
    (0x0000_8000, "CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT"),
    (0x0001_0000, "CERT_TRUST_IS_PARTIAL_CHAIN"),
    (0x0002_0000, "CERT_TRUST_CTL_IS_NOT_TIME_VALID"),
    (0x0004_0000, "CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID"),
    (0x0008_0000, "CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE"),
    // The four below post-date PITTv2's list, which is why a PITTv2 run against a SHA-1 certificate
    // reported "Unknown error detected" where a run here names the weak signature.
    (0x0010_0000, "CERT_TRUST_HAS_WEAK_SIGNATURE"),
    (0x0100_0000, "CERT_TRUST_IS_OFFLINE_REVOCATION"),
    (0x0200_0000, "CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY"),
    (0x0400_0000, "CERT_TRUST_IS_EXPLICIT_DISTRUST"),
    (0x0800_0000, "CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT"),
];

/// `CERT_TRUST_STATUS::dwInfoStatus` flags, paired with the name Windows gives each.
///
/// These are not failures. `CERT_TRUST_IS_SELF_SIGNED` and `CERT_TRUST_HAS_EXACT_MATCH_ISSUER` are
/// how a reader tells *why* the engine assembled the chain it did, which is the interesting half
/// when the question is why CAPI and certval reached different answers on the same inputs.
pub const INFO_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "CERT_TRUST_HAS_EXACT_MATCH_ISSUER"),
    (0x0000_0002, "CERT_TRUST_HAS_KEY_MATCH_ISSUER"),
    (0x0000_0004, "CERT_TRUST_HAS_NAME_MATCH_ISSUER"),
    (0x0000_0008, "CERT_TRUST_IS_SELF_SIGNED"),
    (0x0000_0010, "CERT_TRUST_AUTO_UPDATE_CA_REVOCATION"),
    (0x0000_0020, "CERT_TRUST_AUTO_UPDATE_END_REVOCATION"),
    (0x0000_0040, "CERT_TRUST_NO_OCSP_FAILOVER_TO_CRL"),
    (0x0000_0080, "CERT_TRUST_IS_KEY_ROLLOVER"),
    (0x0000_0100, "CERT_TRUST_HAS_PREFERRED_ISSUER"),
    (0x0000_0200, "CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY"),
    (0x0000_0400, "CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS"),
    (0x0000_0800, "CERT_TRUST_IS_PEER_TRUSTED"),
    (0x0000_1000, "CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED"),
    (0x0000_2000, "CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE"),
    (0x0000_4000, "CERT_TRUST_IS_CA_TRUSTED"),
    (0x0000_8000, "CERT_TRUST_HAS_AUTO_UPDATE_WEAK_SIGNATURE"),
    (0x0001_0000, "CERT_TRUST_IS_COMPLEX_CHAIN"),
    (0x0002_0000, "CERT_TRUST_HAS_ALLOW_WEAK_SIGNATURE"),
    (0x0004_0000, "CERT_TRUST_SSL_HANDSHAKE_OCSP"),
    (0x0008_0000, "CERT_TRUST_SSL_TIME_VALID_OCSP"),
    (0x0010_0000, "CERT_TRUST_SSL_RECONNECT_OCSP"),
    (0x0100_0000, "CERT_TRUST_SSL_TIME_VALID"),
];

/// A `CERT_TRUST_STATUS`: the error and information bit masks the chain engine attaches both to a
/// chain as a whole and to each element within it.
///
/// Kept as the raw masks with decoding on demand, rather than decoded on construction into a set of
/// names, because a bit Windows adds after this was written still reaches the report — see
/// [`unknown_error_bits`](Self::unknown_error_bits). A list of names built at construction would
/// have silently dropped it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapiTrustStatus {
    /// `dwErrorStatus`, decoded by [`ERROR_FLAGS`].
    pub error: u32,
    /// `dwInfoStatus`, decoded by [`INFO_FLAGS`].
    pub info: u32,
}

impl CapiTrustStatus {
    /// A status carrying the given masks.
    pub fn new(error: u32, info: u32) -> Self {
        CapiTrustStatus { error, info }
    }

    /// Whether the engine recorded no error at all, which is what `CERT_TRUST_NO_ERROR` names.
    ///
    /// `CERT_TRUST_NO_ERROR` is zero, so it is the *absence* of bits and not a bit to test for.
    /// PITTv2 wrote `if (dwErrorStatus & CERT_TRUST_NO_ERROR)`, which is `x & 0` and therefore never
    /// taken; its "no error" line came from the separate check for an empty list, so the effect was
    /// invisible. Testing it correctly here is the point of the method existing at all.
    pub fn is_ok(&self) -> bool {
        self.error == 0
    }

    /// Whether a specific error bit is set.
    pub fn has_error(&self, flag: u32) -> bool {
        self.error & flag != 0
    }

    /// Whether a specific information bit is set.
    pub fn has_info(&self, flag: u32) -> bool {
        self.info & flag != 0
    }

    /// Whether the error bit [`ERROR_FLAGS`] gives this name is set.
    ///
    /// By name rather than by literal, so the table stays the one definition of every flag and a
    /// consumer testing for a condition cannot come to disagree with a report listing it about
    /// which bit it is. A name the table does not carry is `false`: an unrecognized bit is a
    /// residue, reported by [`unknown_error_bits`](Self::unknown_error_bits), and is nobody's
    /// named condition.
    pub fn has_named_error(&self, name: &str) -> bool {
        error_bit(name).is_some_and(|bit| self.has_error(bit))
    }

    /// The error bits set other than the named ones.
    ///
    /// Zero means the named conditions are the whole of what the engine faulted, which is what
    /// lets a caller say "this failed for no reason but that one". Unnamed bits count toward the
    /// residue rather than being masked out of it: a flag this build predates must not let a
    /// status read as though it carried only the conditions asked about.
    pub fn errors_besides(&self, names: &[&str]) -> u32 {
        let named = names
            .iter()
            .filter_map(|name| error_bit(name))
            .fold(0u32, |acc, bit| acc | bit);
        self.error & !named
    }

    /// The names of the error bits that are set, in ascending bit order.
    pub fn error_names(&self) -> Vec<&'static str> {
        names(self.error, ERROR_FLAGS)
    }

    /// The names of the information bits that are set, in ascending bit order.
    pub fn info_names(&self) -> Vec<&'static str> {
        names(self.info, INFO_FLAGS)
    }

    /// Error bits set in `dwErrorStatus` that [`ERROR_FLAGS`] has no name for.
    ///
    /// Zero when everything was recognized. A non-zero value means Windows reported something this
    /// build predates, and a report that prints it as a hex residue is telling the truth; one that
    /// omits it is claiming a clean result the engine did not give.
    pub fn unknown_error_bits(&self) -> u32 {
        residue(self.error, ERROR_FLAGS)
    }

    /// Information bits set in `dwInfoStatus` that [`INFO_FLAGS`] has no name for.
    pub fn unknown_info_bits(&self) -> u32 {
        residue(self.info, INFO_FLAGS)
    }

    /// One line naming the error bits, for a log or a results row.
    ///
    /// Reports unnamed bits as a hex residue rather than dropping them, for the reason given on
    /// [`unknown_error_bits`](Self::unknown_error_bits).
    pub fn describe(&self) -> String {
        if self.is_ok() {
            return "no errors".to_string();
        }
        let mut parts = self.error_names().join(", ");
        let unknown = self.unknown_error_bits();
        if unknown != 0 {
            if !parts.is_empty() {
                parts.push_str(", ");
            }
            parts.push_str(&format!("unrecognized bits 0x{unknown:08X}"));
        }
        parts
    }

    /// One line naming the information bits, for a log or a results row.
    pub fn describe_info(&self) -> String {
        let mut parts = self.info_names().join(", ");
        let unknown = self.unknown_info_bits();
        if unknown != 0 {
            if !parts.is_empty() {
                parts.push_str(", ");
            }
            parts.push_str(&format!("unrecognized bits 0x{unknown:08X}"));
        }
        if parts.is_empty() {
            "no additional information".to_string()
        } else {
            parts
        }
    }
}

impl fmt::Display for CapiTrustStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.describe())
    }
}

/// The bit [`ERROR_FLAGS`] gives this name, or `None` when the name is not one it carries.
pub fn error_bit(name: &str) -> Option<u32> {
    ERROR_FLAGS
        .iter()
        .find(|(_, flag)| *flag == name)
        .map(|(bit, _)| *bit)
}

fn names(mask: u32, table: &[(u32, &'static str)]) -> Vec<&'static str> {
    table
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn residue(mask: u32, table: &[(u32, &'static str)]) -> u32 {
    let known = table.iter().fold(0u32, |acc, (bit, _)| acc | bit);
    mask & !known
}

/// The `HRESULT` left in `CERT_CHAIN_POLICY_STATUS::dwError` by
/// `CertVerifyCertificateChainPolicy`.
///
/// A single code, not a bit mask — see the module documentation for why conflating the two produced
/// wrong text in PITTv2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapiError(pub u32);

/// The codes `CertVerifyCertificateChainPolicy` returns, with the sentences PITTv2 used for each.
///
/// Carried over verbatim where PITTv2 had them, because they are the platform's own wording from
/// the `winerror.h` documentation and rephrasing them would only make two tools describe one
/// condition differently.
const POLICY_ERRORS: &[(u32, &str)] = &[
    (
        0x8009_2010,
        "The certificate or signature has been revoked.",
    ),
    (
        0x8009_2013,
        "Since the revocation server was offline, the called function was not able to complete the revocation check.",
    ),
    (
        0x8009_6004,
        "The signature of the certificate cannot be verified.",
    ),
    (
        0x8009_6019,
        "The certificate's basic constraints are invalid or missing.",
    ),
    (
        0x800B_0101,
        "A required certificate is not within its validity period.",
    ),
    (
        0x800B_0102,
        "The validity periods of the certification chain do not nest correctly.",
    ),
    (
        0x800B_0103,
        "A certificate that can only be used as an end-entity is being used as a CA or vice versa.",
    ),
    (
        0x800B_0105,
        "A certificate contains an unsupported critical extension.",
    ),
    (
        0x800B_0106,
        "A certificate is being used for a non permitted purpose.",
    ),
    (
        0x800B_0109,
        "A certification chain processed correctly but terminated in a root certificate not trusted by the trust provider.",
    ),
    (
        0x800B_010A,
        "A chain of certificates was not correctly created.",
    ),
    (
        0x800B_010C,
        "A certificate in the chain has been explicitly revoked by its issuer.",
    ),
    (
        0x800B_010D,
        "The root certificate is a testing certificate and policy settings disallow test certificates.",
    ),
    (
        0x800B_010E,
        "The revocation process could not continue. The certificates could not be checked.",
    ),
    (
        0x800B_010F,
        "The certificate's CN name does not match the passed value.",
    ),
    (
        0x800B_0110,
        "The certificate is not valid for the requested usage.",
    ),
    (
        0x800B_0111,
        "The certificate was explicitly marked as untrusted by the user.",
    ),
    (0x800B_0113, "The certificate has invalid policy."),
    (
        0x800B_0114,
        "The certificate has an invalid name. Either the name is not included in the permitted list or is explicitly excluded.",
    ),
];

/// Symbolic names for [`POLICY_ERRORS`], kept as a parallel table so a report can print the
/// identifier a reader would grep for alongside the sentence.
const POLICY_ERROR_NAMES: &[(u32, &str)] = &[
    (0x8009_2010, "CRYPT_E_REVOKED"),
    (0x8009_2013, "CRYPT_E_REVOCATION_OFFLINE"),
    (0x8009_6004, "TRUST_E_CERT_SIGNATURE"),
    (0x8009_6019, "TRUST_E_BASIC_CONSTRAINTS"),
    (0x800B_0101, "CERT_E_EXPIRED"),
    (0x800B_0102, "CERT_E_VALIDITYPERIODNESTING"),
    (0x800B_0103, "CERT_E_ROLE"),
    (0x800B_0105, "CERT_E_CRITICAL"),
    (0x800B_0106, "CERT_E_PURPOSE"),
    (0x800B_0109, "CERT_E_UNTRUSTEDROOT"),
    (0x800B_010A, "CERT_E_CHAINING"),
    (0x800B_010C, "CERT_E_REVOKED"),
    (0x800B_010D, "CERT_E_UNTRUSTEDTESTROOT"),
    (0x800B_010E, "CERT_E_REVOCATION_FAILURE"),
    (0x800B_010F, "CERT_E_CN_NO_MATCH"),
    (0x800B_0110, "CERT_E_WRONG_USAGE"),
    (0x800B_0111, "TRUST_E_EXPLICIT_DISTRUST"),
    (0x800B_0113, "CERT_E_INVALID_POLICY"),
    (0x800B_0114, "CERT_E_INVALID_NAME"),
];

impl CapiError {
    /// The name Windows gives this code, when it is one this build knows.
    pub fn name(&self) -> Option<&'static str> {
        POLICY_ERROR_NAMES
            .iter()
            .find(|(code, _)| *code == self.0)
            .map(|(_, name)| *name)
    }

    /// The sentence describing this code, when it is one this build knows.
    pub fn message(&self) -> Option<&'static str> {
        POLICY_ERRORS
            .iter()
            .find(|(code, _)| *code == self.0)
            .map(|(_, text)| *text)
    }

    /// One line naming and describing the code, falling back to the bare hex value.
    ///
    /// The hex is always present, named or not: it is the only part a reader can take to
    /// `winerror.h` or to a support case, and a sentence without it cannot be looked up.
    pub fn describe(&self) -> String {
        match (self.name(), self.message()) {
            (Some(name), Some(text)) => format!("{name} (0x{:08X}): {text}", self.0),
            _ => format!("unrecognized policy error 0x{:08X}", self.0),
        }
    }
}

impl fmt::Display for CapiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// `CERT_TRUST_NO_ERROR` is zero, so "no error" is the absence of bits. PITTv2's `x & 0` test
    /// for it was never taken; this is the behavior that replaces it.
    #[test]
    fn no_error_is_the_absence_of_bits() {
        let clean = CapiTrustStatus::new(0, 0);
        assert!(clean.is_ok());
        assert!(clean.error_names().is_empty());
        assert_eq!(clean.describe(), "no errors");

        let untrusted = CapiTrustStatus::new(0x0000_0020, 0);
        assert!(!untrusted.is_ok());
        assert_eq!(untrusted.describe(), "CERT_TRUST_IS_UNTRUSTED_ROOT");
    }

    /// Set bits come back in ascending bit order regardless of how they were combined, so two runs
    /// that found the same thing produce the same line.
    #[test]
    fn error_names_are_ordered_by_bit() {
        let status = CapiTrustStatus::new(
            // offline revocation | not time valid | untrusted root
            0x0100_0000 | 0x0000_0001 | 0x0000_0020,
            0,
        );
        assert_eq!(
            status.error_names(),
            vec![
                "CERT_TRUST_IS_NOT_TIME_VALID",
                "CERT_TRUST_IS_UNTRUSTED_ROOT",
                "CERT_TRUST_IS_OFFLINE_REVOCATION",
            ]
        );
    }

    /// A bit this build has no name for is reported as a hex residue rather than dropped, so a
    /// future Windows flag cannot turn into a silently clean-looking result.
    #[test]
    fn unrecognized_error_bits_survive_into_the_description() {
        // 0x4000_0000 is not in ERROR_FLAGS.
        let status = CapiTrustStatus::new(0x4000_0000 | 0x0000_0004, 0);
        assert_eq!(status.unknown_error_bits(), 0x4000_0000);
        assert_eq!(
            status.describe(),
            "CERT_TRUST_IS_REVOKED, unrecognized bits 0x40000000"
        );
        assert!(!status.is_ok());
    }

    /// The same for information bits, and an all-unknown mask still says something.
    #[test]
    fn unrecognized_info_bits_survive_into_the_description() {
        let status = CapiTrustStatus::new(0, 0x8000_0000);
        assert_eq!(status.unknown_info_bits(), 0x8000_0000);
        assert_eq!(status.describe_info(), "unrecognized bits 0x80000000");
    }

    /// Information bits are not errors: a chain can be self-signed and complex and still be clean.
    #[test]
    fn info_bits_do_not_make_a_status_failed() {
        let status = CapiTrustStatus::new(0, 0x0000_0008 | 0x0001_0000);
        assert!(status.is_ok());
        assert_eq!(
            status.info_names(),
            vec!["CERT_TRUST_IS_SELF_SIGNED", "CERT_TRUST_IS_COMPLEX_CHAIN"]
        );
        assert_eq!(status.describe(), "no errors");
    }

    /// No flag value appears twice in either table, and each names exactly one bit — a duplicate
    /// would print one condition under two names, and a multi-bit entry would match a mask that
    /// only has part of it set.
    #[test]
    fn flag_tables_are_well_formed() {
        for table in [ERROR_FLAGS, INFO_FLAGS] {
            let mut seen = 0u32;
            for (bit, name) in table {
                assert_eq!(bit.count_ones(), 1, "{name} does not name exactly one bit");
                assert_eq!(seen & bit, 0, "{name} duplicates an earlier flag");
                seen |= bit;
            }
        }
    }

    /// Both tables are sorted ascending, which is what makes `error_names` ordered by bit.
    #[test]
    fn flag_tables_are_sorted() {
        for table in [ERROR_FLAGS, INFO_FLAGS] {
            assert!(
                table.windows(2).all(|w| w[0].0 < w[1].0),
                "flag table is not in ascending bit order"
            );
        }
    }

    /// A policy error is an HRESULT, and it is described as one. The regression this guards is
    /// PITTv2's: `CERT_E_INVALID_POLICY` had no case in its switch and fell into a `default:` arm
    /// that decoded it as trust-status bits, so the text came back as an unrelated list.
    #[test]
    fn policy_errors_are_described_as_hresults_not_as_bit_masks() {
        let invalid_policy = CapiError(0x800B_0113);
        assert_eq!(invalid_policy.name(), Some("CERT_E_INVALID_POLICY"));
        assert_eq!(
            invalid_policy.describe(),
            "CERT_E_INVALID_POLICY (0x800B0113): The certificate has invalid policy."
        );

        // What PITTv2's default arm would have produced from the same value: 0x800B0113 happens to
        // have the not-time-valid, revoked and not-valid-for-usage bits set, among others. None of
        // those is what the code means.
        let as_bits = CapiTrustStatus::new(0x800B_0113, 0);
        assert!(as_bits
            .error_names()
            .contains(&"CERT_TRUST_IS_NOT_TIME_VALID"));
        assert!(as_bits
            .error_names()
            .contains(&"CERT_TRUST_INVALID_EXTENSION"));
        assert_ne!(as_bits.describe(), invalid_policy.describe());
    }

    /// An unknown code still carries its hex, which is the part that can be looked up.
    #[test]
    fn unknown_policy_error_keeps_its_hex() {
        let unknown = CapiError(0x8007_0005);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.message(), None);
        assert_eq!(unknown.describe(), "unrecognized policy error 0x80070005");
    }

    /// The two policy tables are parallel: every code has both a name and a sentence, or the
    /// `describe` fallback silently swallows a code that is half known.
    #[test]
    fn policy_tables_agree() {
        assert_eq!(POLICY_ERRORS.len(), POLICY_ERROR_NAMES.len());
        for (code, _) in POLICY_ERRORS {
            let e = CapiError(*code);
            assert!(e.name().is_some(), "0x{code:08X} has a message but no name");
            assert!(
                e.message().is_some(),
                "0x{code:08X} has a name but no message"
            );
            assert!(e.describe().contains(&format!("0x{code:08X}")));
        }
        for (code, _) in POLICY_ERROR_NAMES {
            assert!(
                CapiError(*code).message().is_some(),
                "0x{code:08X} has a name but no message"
            );
        }
    }

    /// A condition can be tested by the name Windows documents, which is the name a report prints,
    /// so the two cannot drift. A name the table does not carry is not a condition.
    #[test]
    fn named_errors_resolve_through_the_flag_table() {
        let revoked = CapiTrustStatus::new(0x0000_0004, 0);
        assert!(revoked.has_named_error("CERT_TRUST_IS_REVOKED"));
        assert!(!revoked.has_named_error("CERT_TRUST_IS_PARTIAL_CHAIN"));
        assert!(!revoked.has_named_error("CERT_TRUST_NOT_A_REAL_FLAG"));

        assert_eq!(error_bit("CERT_TRUST_IS_PARTIAL_CHAIN"), Some(0x0001_0000));
        assert_eq!(error_bit("CERT_TRUST_NOT_A_REAL_FLAG"), None);
    }

    /// The residue is what is left when the named conditions are set aside, which is how a caller
    /// asks whether anything *else* went wrong.
    #[test]
    fn errors_besides_sets_aside_only_what_is_named() {
        const UNKNOWN: &[&str] = &[
            "CERT_TRUST_REVOCATION_STATUS_UNKNOWN",
            "CERT_TRUST_IS_OFFLINE_REVOCATION",
        ];

        // Revocation alone: nothing else is wrong with this chain.
        let revocation_only = CapiTrustStatus::new(0x0000_0040 | 0x0100_0000, 0);
        assert_eq!(revocation_only.errors_besides(UNKNOWN), 0);

        // The same two bits plus an untrusted root, which is a different answer entirely.
        let and_untrusted = CapiTrustStatus::new(0x0000_0040 | 0x0100_0000 | 0x0000_0020, 0);
        assert_eq!(and_untrusted.errors_besides(UNKNOWN), 0x0000_0020);

        // A bit no table names counts toward the residue. Masking it out would let a flag added
        // after this build read as a clean revocation-only result.
        let and_unknown_bit = CapiTrustStatus::new(0x0000_0040 | 0x8000_0000, 0);
        assert_eq!(and_unknown_bit.errors_besides(UNKNOWN), 0x8000_0000);

        // A name the table does not carry sets nothing aside.
        assert_eq!(
            revocation_only.errors_besides(&["CERT_TRUST_NOT_A_REAL_FLAG"]),
            0x0000_0040 | 0x0100_0000
        );
    }
}

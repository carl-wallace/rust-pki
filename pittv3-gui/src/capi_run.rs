//! Windows-only: the Validate Using CAPI action.
//!
//! Gathers the same material a certval run would be given — the store the selector names, the trust
//! anchor and CA pools, the end entity pool and the time of interest — and puts it to the Windows
//! chain engine through [`pittv3_capi`] instead. The point is a second opinion on one set of inputs:
//! where the two validators disagree, the inputs are not the variable.
//!
//! Results are not folded into the Results view's report. A [`CapiVerification`] is not a
//! `Pittv3Report`, and squeezing one into the other would mean inventing a `PathValidationStatus`
//! for conditions CAPI has and certval does not — see `pittv3_capi::types`. They go instead to the
//! CAPI pane, in `capi_view`, and to the log lines [`CapiRunResult::to_lines`] writes.
//!
//! Both surfaces describe one run, so the words they describe it in live here rather than in either
//! of them: [`rollup`] reduces an outcome to the six [`TargetStatus`] values and [`rollup_label`]
//! names it, once, for the badge and the log line alike. That is a rollup of an outcome and not a
//! translation of a condition — the conditions themselves stay in Windows' own vocabulary on both
//! surfaces, for the reason `pittv3_capi::types` gives.

use std::fs;
use std::path::Path;

use pittv3_capi::RevocationChecking;
use pittv3_capi::{verify, CapiError, CapiOptions, CapiVerification, CapiVerifyError};
use pittv3_gui_lib::gui_results::status_parts;
use pittv3_gui_lib::settings_store::{FileSettingsStore, SettingsStore};
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::der_or_pem::certs_in;
use pittv3_lib::report::TargetStatus;
use pittv3_lib::std_utils::{cbor_cert_store_certs, cbor_ta_store_anchors};

/// Which trust the chain engine is asked to use.
///
/// The checkbox beside the button. Both answers are worth having and they answer different
/// questions: [`RunAnchors`] asks whether this material validates, and [`MachineStores`] asks
/// whether *this machine* would accept the target, which is what PITTv2's CAPI panel asked and what
/// a reader chasing a real application's failure wants to know.
///
/// [`RunAnchors`]: CapiTrust::RunAnchors
/// [`MachineStores`]: CapiTrust::MachineStores
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapiTrust {
    /// The run's own anchors, handed to the engine as an exclusive root store.
    RunAnchors,
    /// This machine's certificate stores, as PITTv2 did.
    MachineStores,
}

/// The material one CAPI run works from.
pub struct CapiRunInputs {
    /// Targets as `(label, DER)`, the label being the path it was read from.
    pub targets: Vec<(String, Vec<u8>)>,
    /// Anchors for an exclusive root store, empty when the machine's stores are to be used.
    pub trust_anchors: Vec<Vec<u8>>,
    /// Intermediates offered to the builder as candidates.
    pub additional_certs: Vec<Vec<u8>>,
    /// Time of interest as Unix seconds, or `None` for now.
    pub time_of_interest: Option<u64>,
    /// The anchor-shaped inputs that were consulted, whether or not they yielded anything.
    ///
    /// Kept so a run that gathered no anchors can say where it looked. Without it the log reports
    /// an empty set and leaves the reader to guess between "no store was selected" and "the store
    /// was selected and could not be read", which are different problems with different fixes.
    pub anchor_sources: Vec<String>,
}

/// Collects what a run was given into the bytes [`verify`] takes.
///
/// Reads from the same arguments the certval run is built from rather than from the signals behind
/// them, so the two runs cannot be given different material by a control that one of them consults
/// and the other does not.
pub fn gather(args: &Pittv3Args, trust: CapiTrust) -> CapiRunInputs {
    let mut targets = vec![];
    for input in args
        .end_entity_file
        .iter()
        .chain(args.end_entity_folder.iter())
        .chain(args.ee_inputs.iter())
    {
        collect_labeled(Path::new(input), &mut targets);
    }

    // Anchor-shaped inputs: the store the selector materialized, the singular argument, and the
    // pool. `ta_cbor` already holds whichever of the store and the singular row won, since
    // `current_args` resolves that before this sees it.
    let mut anchor_paths: Vec<&String> = vec![];
    anchor_paths.extend(args.ta_cbor.iter());
    anchor_paths.extend(args.ta_folder.iter());
    anchor_paths.extend(args.ta_inputs.iter());

    let mut cert_paths: Vec<&String> = vec![];
    cert_paths.extend(args.cbor.iter());
    cert_paths.extend(args.ca_folder.iter());
    cert_paths.extend(args.ca_inputs.iter());

    let mut additional_certs = vec![];
    for p in cert_paths {
        collect_ders(Path::new(p), Shape::Certificates, &mut additional_certs);
    }

    let anchor_sources: Vec<String> = anchor_paths.iter().map(|p| (*p).clone()).collect();

    let trust_anchors = match trust {
        CapiTrust::MachineStores => {
            // The anchors still go in, as candidates rather than as trust. Without them a chain
            // that needs the store's intermediate to reach a machine-trusted root cannot be built,
            // and the run would report a partial chain about the material rather than an answer
            // about this machine.
            for p in anchor_paths {
                collect_ders(Path::new(p), Shape::Anchors, &mut additional_certs);
            }
            vec![]
        }
        CapiTrust::RunAnchors => {
            let mut anchors = vec![];
            for p in anchor_paths {
                collect_ders(Path::new(p), Shape::Anchors, &mut anchors);
            }
            anchors
        }
    };

    CapiRunInputs {
        targets,
        trust_anchors,
        additional_certs,
        // Zero is the command line's "unset"; the desktop always fills it, but this reads the
        // argument rather than the control, so it handles the argument's range.
        time_of_interest: (args.time_of_interest != 0).then_some(args.time_of_interest),
        anchor_sources,
    }
}

/// Whether a path is being read for anchors or for certificates, which decides only how a CBOR
/// store at that path is opened — the two kinds serialize differently.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Anchors,
    Certificates,
}

/// Appends every certificate reachable from `path` to `out`.
///
/// Accepts what every other input row accepts: a folder, a bare DER or PEM certificate, a PEM or
/// PKCS #7 bundle, or a CBOR store. Unreadable entries are skipped rather than reported, because
/// the certval run reading the same inputs reports them and having both say so would double every
/// complaint in the log.
fn collect_ders(path: &Path, shape: Shape, out: &mut Vec<Vec<u8>>) {
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            collect_ders(&entry.path(), shape, out);
        }
        return;
    }

    let name = path.to_string_lossy().to_string();
    // A store is not a certificate, and the two arrive through the same rows. Tried first because
    // `certs_in` would otherwise hand the CBOR back as one unparseable object.
    if shape == Shape::Anchors {
        if let Some(anchors) = cbor_ta_store_anchors(&name) {
            out.extend(anchors.into_iter().map(|cf| cf.bytes));
            return;
        }
    }
    if let Some(certs) = cbor_cert_store_certs(&name) {
        out.extend(certs.into_iter().map(|cf| cf.bytes));
        return;
    }

    let Ok(bytes) = fs::read(path) else {
        return;
    };
    if let Ok(certs) = certs_in(&bytes) {
        out.extend(certs);
    }
}

/// The target-side counterpart of [`collect_ders`], keeping the path each certificate came from.
///
/// A CBOR store is not read here: a store is trust material, and a run that validated every
/// certificate in one because it was named as a target would be answering a question nobody asked.
fn collect_labeled(path: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        // Sorted so a folder of targets is reported in the same order every run, which is what
        // makes two runs' logs comparable line by line.
        paths.sort();
        for p in paths {
            collect_labeled(&p, out);
        }
        return;
    }

    let Ok(bytes) = fs::read(path) else {
        return;
    };
    let Ok(certs) = certs_in(&bytes) else {
        return;
    };
    let name = path.to_string_lossy().to_string();
    match certs.len() {
        // The common case: one file, one target, named by its path.
        1 => out.push((name, certs.into_iter().next().unwrap_or_default())),
        // A bundle named as a target is several targets, and they need telling apart.
        _ => {
            for (i, der) in certs.into_iter().enumerate() {
                out.push((format!("{name}#{i}"), der));
            }
        }
    }
}

/// Whether this run checks revocation, as its settings file says.
///
/// Read from the file the certval run reads rather than defaulted, because a comparison in which
/// one validator checks revocation and the other does not is not a comparison -- the difference in
/// the answers would be the setting rather than the validators.
///
/// It is also what makes the button usable at all on the material this tool is usually pointed at.
/// With checking on and no route to a distribution point, the engine returns
/// `CRYPT_E_REVOCATION_OFFLINE` for every target and calls every path invalid, which says nothing
/// about the path: the PKITS suite reports exactly that, and so would any archived material.
fn checks_revocation(args: &Pittv3Args) -> bool {
    match &args.settings {
        Some(path) => FileSettingsStore::new(path)
            .load()
            .get_check_revocation_status(),
        // certval's default, which is what a run with no settings file gets.
        None => true,
    }
}

/// Which trust the engine actually consulted, as against which was asked for.
///
/// The distinction exists because an empty anchor set is not an empty trust set: `verify` reads one
/// as "use the default chain engine", i.e. this machine. Reporting that as "against 0 trust anchors
/// from this run" is the one thing this log must never do -- it makes the checkbox look broken,
/// because on and off then produce identical output with nothing saying why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectiveTrust {
    /// Anchors were gathered from the run's own material; the count is how many.
    RunAnchors(usize),
    /// The store selector named Windows certificate stores, so the run's trust material *is* the
    /// machine's. The engine consults the same set either way and the checkbox makes no difference
    /// -- which is correct, not a substitution, and is why this is not reported as one.
    CapiStoresAreTheRunsTrust,
    /// The checkbox was off.
    MachineStores,
    /// The checkbox was on, and there was nothing to honour it with.
    NoAnchorsToUse,
}

/// What one target came to.
#[derive(Clone, Debug, PartialEq)]
pub struct CapiTargetOutcome {
    /// The path the target was read from, which is what a reader recognizes it by.
    pub label: String,
    /// The engine's verdict, or why it would not give one.
    pub outcome: Result<CapiVerification, CapiVerifyError>,
}

/// Everything one CAPI run found.
///
/// The structured form is the source and [`to_lines`](Self::to_lines) renders it. Deriving the log
/// from the same value the pane draws is what keeps a log a reader saved and a pane they were
/// looking at from telling different stories about one run.
#[derive(Clone, Debug, PartialEq)]
pub struct CapiRunResult {
    /// Which trust the engine consulted.
    pub trust: EffectiveTrust,
    /// Supporting certificates offered to the builder as candidates.
    pub supporting_count: usize,
    /// The anchor-shaped inputs consulted, whether or not they yielded anything.
    pub anchor_sources: Vec<String>,
    /// Whether revocation was checked, as the run's settings asked.
    pub revocation_checked: bool,
    /// Time of interest in Unix seconds, or `None` for the moment the run started.
    pub time_of_interest: Option<u64>,
    /// One entry per target, in the order the inputs were read.
    pub targets: Vec<CapiTargetOutcome>,
}

impl CapiRunResult {
    /// Whether the run asked for its own anchors and had none to use -- the one state that warns.
    pub fn fell_back(&self) -> bool {
        self.trust == EffectiveTrust::NoAnchorsToUse
    }

    /// Where the run's trust came from, in the words the banner shows.
    pub fn trust_summary(&self) -> String {
        match self.trust {
            EffectiveTrust::RunAnchors(n) => format!("{n} trust anchor(s) from this run"),
            EffectiveTrust::CapiStoresAreTheRunsTrust => {
                "this machine's certificate stores, which are this run's trust material".to_string()
            }
            EffectiveTrust::MachineStores => "this machine's certificate stores".to_string(),
            EffectiveTrust::NoAnchorsToUse => {
                "this machine's certificate stores, NOT this run's anchors".to_string()
            }
        }
    }

    /// The run as log lines, which is what the Save log button writes.
    pub fn to_lines(&self) -> Vec<String> {
        let mut lines = vec![self.header()];

        // Loud, and above the verdicts rather than after them: the run asked one question and
        // answered another, and every line below is about a trust set the reader did not choose.
        if self.fell_back() {
            lines.push(FELL_BACK.to_string());
            lines.push(match self.anchor_sources.is_empty() {
                true => NO_ANCHOR_INPUTS.to_string(),
                false => format!(
                    "CAPI: anchor inputs consulted, none of which yielded a certificate: {}",
                    self.anchor_sources.join(", ")
                ),
            });
        }

        if self.targets.is_empty() {
            lines.push("CAPI: nothing to validate.".to_string());
            return lines;
        }

        for target in &self.targets {
            lines.push(format!("CAPI: {}", target.label));
            match &target.outcome {
                Ok(result) => lines.extend(describe(result)),
                // The rollup first, as for a target the engine did judge, then the refusal in
                // its own words. `TargetNotParsed` is a statement about the file and rolls up to
                // one; the rest are about the run and roll up to nothing, which is what "No
                // verdict" says.
                Err(e) => {
                    lines.push(format!(
                        "  result: {}",
                        rollup_label(rollup(&target.outcome))
                    ));
                    lines.push(format!("  {e}"));
                }
            }
        }

        lines.push(self.summary());
        lines
    }

    /// The opening line, naming what the run did and what it was given.
    fn header(&self) -> String {
        let at = match self.time_of_interest {
            Some(t) => format!(", as at {t}"),
            None => String::new(),
        };
        let revocation = match self.revocation_checked {
            true => "checking revocation over the chain below the root",
            false => "without revocation checking",
        };
        format!(
            "CAPI: validating {} certificate(s) against {}, with {} supporting certificate(s){at}, {revocation}",
            self.targets.len(),
            self.trust_summary(),
            self.supporting_count
        )
    }

    /// The closing line. Counts rather than a verdict: a run over a folder has no single answer.
    ///
    /// Counted by the rollup the pane badges and printed in the same words, so the summary strip on
    /// screen and the last line of a saved log cannot say different things about one run. Outcomes
    /// that did not occur are left out rather than printed as zeros, which is how the strip does it.
    fn summary(&self) -> String {
        let counts = rollup_counts(&self.targets);
        let parts: Vec<String> = counts
            .iter()
            .map(|(status, count)| format!("{count} {}", rollup_label(*status)))
            .collect();
        format!("CAPI: {}", parts.join(", "))
    }
}

/// The fallback warning, as the log words it. The pane states the same fact in its banner, laid
/// out rather than prefixed, so the two are deliberately not one string.
const FELL_BACK: &str = "CAPI: no trust anchors were gathered from this run, so the verdicts \
                             below are this machine's and are the same answer the checkbox off \
                             would give.";

/// The companion line for a run that named no anchor inputs at all.
const NO_ANCHOR_INPUTS: &str = "CAPI: no anchor inputs were named — select a store, or add \
                                    trust anchors on this view, to compare like for like.";

/// Runs CAPI over every target and returns what it found.
///
/// Synchronous and potentially slow: when the run's settings ask for revocation, the engine reaches
/// the network through Windows rather than through certval. Call it off the UI thread.
pub fn execute(args: &Pittv3Args, trust: CapiTrust) -> CapiRunResult {
    let inputs = gather(args, trust);
    let revocation_checked = checks_revocation(args);
    let options = CapiOptions {
        trust_anchors: inputs.trust_anchors,
        additional_certs: inputs.additional_certs,
        time_of_interest: inputs.time_of_interest,
        revocation: match revocation_checked {
            // PITTv2's choice, and the sensible one: a root is trusted by being an anchor rather
            // than by a status check, and asking for one puts
            // CERT_TRUST_REVOCATION_STATUS_UNKNOWN on every otherwise clean path.
            true => RevocationChecking::ChainExcludeRoot,
            false => RevocationChecking::None,
        },
        ..Default::default()
    };

    // The store selector's CAPI entries name live Windows stores rather than files, so a run whose
    // trust material is one of them gathers no anchor *bytes* and is nonetheless using exactly the
    // trust the engine consults by itself. The two really are the same set, so the checkbox making
    // no difference there is the right answer rather than a fallback.
    #[cfg(feature = "capi")]
    let capi_stores_named = !args.capi_ta_stores.is_empty();
    #[cfg(not(feature = "capi"))]
    let capi_stores_named = false;

    let effective = match (trust, options.trust_anchors.len()) {
        (CapiTrust::MachineStores, _) => EffectiveTrust::MachineStores,
        (CapiTrust::RunAnchors, 0) if capi_stores_named => {
            EffectiveTrust::CapiStoresAreTheRunsTrust
        }
        (CapiTrust::RunAnchors, 0) => EffectiveTrust::NoAnchorsToUse,
        (CapiTrust::RunAnchors, n) => EffectiveTrust::RunAnchors(n),
    };

    let targets = inputs
        .targets
        .iter()
        .map(|(label, der)| CapiTargetOutcome {
            label: label.clone(),
            outcome: verify(der, &options),
        })
        .collect();

    CapiRunResult {
        trust: effective,
        supporting_count: options.additional_certs.len(),
        anchor_sources: inputs.anchor_sources,
        revocation_checked,
        time_of_interest: options.time_of_interest,
        targets,
    }
}

/// Error flags the rollup tests for by name, so `pittv3_capi::ERROR_FLAGS` stays the one definition
/// of each: the bit the rollup reads and the chip a reader sees cannot come to disagree.
const REVOKED: &str = "CERT_TRUST_IS_REVOKED";

/// The engine reached no anchor. Not a fault in the certificate -- see [`rollup_verification`].
pub const PARTIAL_CHAIN: &str = "CERT_TRUST_IS_PARTIAL_CHAIN";

/// The two ways the engine says it could not settle a revocation status. Neither is a fault in the
/// certificate, which is the whole reason they are set aside from the rest of the mask.
const REVOCATION_UNDETERMINED: &[&str] = &[
    "CERT_TRUST_REVOCATION_STATUS_UNKNOWN",
    "CERT_TRUST_IS_OFFLINE_REVOCATION",
];

/// The word for an outcome the engine would not produce at all.
pub const NO_VERDICT: &str = "No verdict";

/// Whether an `HRESULT` says the certificate is revoked, by the name this build gives it.
///
/// Used for the policy check's code and for `CERT_REVOCATION_INFO::dwRevocationResult`, which are
/// one namespace.
pub fn says_revoked(err: &CapiError) -> bool {
    matches!(err.name(), Some("CRYPT_E_REVOKED" | "CERT_E_REVOKED"))
}

/// Whether an `HRESULT` says revocation could not be settled, as distinct from a verdict about the
/// certificate.
fn says_revocation_undetermined(err: &CapiError) -> bool {
    matches!(
        err.name(),
        Some("CRYPT_E_REVOCATION_OFFLINE" | "CERT_E_REVOCATION_FAILURE")
    )
}

/// One verdict as the six-value rollup both the pane and the log report it by.
///
/// Not a translation of a CAPI condition into a certval one -- `pittv3_capi::types` is right that
/// there is no such mapping, and nothing here attempts one. It is a rollup of an *outcome* into the
/// six [`TargetStatus`] values, every CAPI outcome does land in one of the six, and the conditions
/// that produced it are reported underneath in Windows' own words either way.
pub fn rollup_verification(verification: &CapiVerification) -> TargetStatus {
    if verification.validated {
        return TargetStatus::Valid;
    }

    // Revoked first and ahead of every other fault: it is the answer people come to this tool for,
    // and a revoked certificate in an otherwise broken chain is still revoked. Read across every
    // chain the engine returned -- a revoked certificate in a chain the engine declined to prefer
    // is still one this run found.
    let revoked_element = verification.chains.iter().any(|chain| {
        chain
            .elements
            .iter()
            .any(|element| element.trust_status.has_named_error(REVOKED))
    });
    if revoked_element
        || verification.trust_status.has_named_error(REVOKED)
        || verification.policy_error.as_ref().is_some_and(says_revoked)
    {
        return TargetStatus::Revoked;
    }

    // Everything below reads the context's own mask, because that is the mask
    // [`CapiVerification::validated`] was computed from: the bits that decided this is not `Valid`
    // are the bits that say why it is not.
    let context = verification.trust_status;

    // A chain that never reached an anchor reports the absence of a result rather than a fault in
    // the certificate, which is what certval's `NoPathsFound` says -- and, like it, sends a reader
    // to the run's trust material rather than to the file. `CERT_TRUST_IS_UNTRUSTED_ROOT` is
    // deliberately not here: the engine got all the way to a root and was refused it, which is a
    // verdict about trust rather than a failure to build.
    if verification.chains.is_empty() || context.has_named_error(PARTIAL_CHAIN) {
        return TargetStatus::NoPathsFound;
    }

    // Nothing wrong but a revocation status the engine could not settle. Windows folds that into
    // the same error mask as a bad signature; certval reports it apart, because a path that is
    // sound except that a responder would not answer is not the claim that the path is unsound. The
    // policy check has to agree, since it runs after the build and can fail for its own reasons.
    let policy_is_revocation_only = match &verification.policy_error {
        None => true,
        Some(err) => says_revocation_undetermined(err),
    };
    if context.errors_besides(REVOCATION_UNDETERMINED) == 0 && policy_is_revocation_only {
        return TargetStatus::ValidExceptRevocationUndetermined;
    }

    TargetStatus::Invalid
}

/// One target's outcome as the rollup, or `None` when the engine was never reached and there is no
/// verdict to roll up.
///
/// `None` is not a seventh status. certval has no counterpart because a certval run cannot fail
/// these ways: a store that would not open or an engine that would not start says nothing about the
/// certificate. [`CapiVerifyError::TargetNotParsed`] is the exception and *is* a statement about the
/// file, which is exactly what certval calls `ParseError`.
pub fn rollup(outcome: &Result<CapiVerification, CapiVerifyError>) -> Option<TargetStatus> {
    match outcome {
        Err(CapiVerifyError::TargetNotParsed(_)) => Some(TargetStatus::ParseError),
        Err(_) => None,
        Ok(verification) => Some(rollup_verification(verification)),
    }
}

/// The word for one rollup, which is the word the pane badges and the word the log prints.
///
/// One definition, taken from the certval results view's own table, so the two surfaces cannot come
/// to describe one outcome differently. Only the colour is the pane's to choose.
pub fn rollup_label(status: Option<TargetStatus>) -> &'static str {
    match status {
        Some(status) => status_parts(status).1,
        None => NO_VERDICT,
    }
}

/// The targets in each rollup as `(rollup, count)`, ordered as [`TargetStatus`] declares them,
/// omitting those that did not occur and putting the refusals last.
///
/// One ordering for both surfaces: the pane renders each row as a badge and the log as a phrase.
/// Counting valid against invalid stopped being an account of a run the moment the rollup gained
/// the outcomes that are neither.
pub fn rollup_counts(targets: &[CapiTargetOutcome]) -> Vec<(Option<TargetStatus>, usize)> {
    let statuses = [
        TargetStatus::Valid,
        TargetStatus::ValidExceptRevocationUndetermined,
        TargetStatus::Revoked,
        TargetStatus::Invalid,
        TargetStatus::NoPathsFound,
        TargetStatus::ParseError,
    ];
    let rolled: Vec<Option<TargetStatus>> = targets.iter().map(|t| rollup(&t.outcome)).collect();

    let mut rows: Vec<(Option<TargetStatus>, usize)> = statuses
        .iter()
        .filter_map(|status| {
            let count = rolled.iter().filter(|r| **r == Some(*status)).count();
            match 0 == count {
                true => None,
                false => Some((Some(*status), count)),
            }
        })
        .collect();

    let refused = rolled.iter().filter(|r| r.is_none()).count();
    if refused > 0 {
        rows.push((None, refused));
    }
    rows
}

/// Where the policy check laid the blame, rendered for a reader.
///
/// `-1` in either position is the structure's "not applicable", which is a different claim from
/// element 0 and is kept as one rather than normalized into a position.
pub fn blame(result: &CapiVerification) -> String {
    match result.policy_error_location {
        Some((c, e)) if c >= 0 && e >= 0 => format!(" at chain {c}, element {e}"),
        Some((c, _)) if c >= 0 => format!(" at chain {c}"),
        _ => String::new(),
    }
}

/// One verification, as indented lines under the target's own.
fn describe(result: &CapiVerification) -> Vec<String> {
    let mut lines = vec![];

    match &result.target {
        Some(cert) => lines.push(format!("  subject: {}", cert.subject)),
        // Worth a line of its own rather than silence: CAPI accepting what certval will not parse
        // is a finding, and it is the kind this tool exists to surface.
        None => lines.push(
            "  subject: unavailable — CAPI accepted bytes that certval would not parse".to_string(),
        ),
    }

    // The rollup the pane badges, in the same words, because a log someone saved and the pane they
    // were reading have to be one account of one run. `VALID`/`INVALID` could not be: it renders
    // `CapiVerification::validated`, which folds a revocation status the engine could not settle in
    // with a bad signature, and a chain that never reached an anchor in with a chain that was
    // faulted. The flags it was rolled up from are on the line below, which is where a reader
    // confirms it.
    lines.push(format!(
        "  result: {}",
        rollup_label(Some(rollup_verification(result)))
    ));
    lines.push(format!(
        "  chain status: {}",
        result.trust_status.describe()
    ));

    if let Some(err) = &result.policy_error {
        lines.push(format!("  policy: {}{}", err.describe(), blame(result)));
    }

    for chain in &result.chains {
        let quality = if chain.lower_quality {
            "lower quality"
        } else {
            "preferred"
        };
        lines.push(format!(
            "  chain {} ({quality}), {} element(s): {}",
            chain.index,
            chain.elements.len(),
            chain.trust_status.describe()
        ));
        for (i, element) in chain.elements.iter().enumerate() {
            let subject = match &element.cert {
                Some(cert) => cert.subject.clone(),
                None => "<unparsed>".to_string(),
            };
            // CAPI orders a chain from the target outward, and the index is printed so a reader
            // comparing this with a certval path -- which runs the other way -- can tell which end
            // they are looking at.
            lines.push(format!("    [{i}] {subject}"));
            lines.push(format!(
                "        status: {}",
                element.trust_status.describe()
            ));
            let info = element.trust_status.describe_info();
            if info != "no additional information" {
                lines.push(format!("        info: {info}"));
            }
            if let Some(rev) = &element.revocation {
                lines.push(format!("        revocation: {}", rev.describe()));
                if let Some(crl) = &rev.crl {
                    if let Some(issuer) = &crl.issuer {
                        lines.push(format!("        revocation source issuer: {issuer}"));
                    }
                    if let Some(entry) = &crl.entry {
                        let when = entry.revocation_date.as_deref().unwrap_or("unknown date");
                        lines.push(format!(
                            "        revoked: serial {} on {when}",
                            entry.serial
                        ));
                    }
                }
            }
            if let Some(extra) = &element.extended_error_info {
                lines.push(format!("        {extra}"));
            }
        }
    }

    lines
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pittv3_capi::{CapiChain, CapiElement, CapiTrustStatus};

    /// The instant the PKITS material is valid at, as the other suites use it.
    const TOI: u64 = 1_648_039_783;

    const PKITS: &str = "../certval/tests/examples/PKITS_data_p256/certs";

    fn pkits_path(name: &str) -> String {
        format!("{PKITS}/{name}")
    }

    /// A settings file turning revocation checking off, which is how these tests stay off the
    /// network: the PKITS distribution points do not resolve, and with checking on the engine
    /// answers `CRYPT_E_REVOCATION_OFFLINE` for every target whatever the path looks like.
    ///
    /// Written to a fixed path rather than a `tempfile` handle so the file outlives the call
    /// without the caller having to hold a guard.
    fn settings_without_revocation() -> String {
        // Written exactly once per process. Every test shares the path, and `FileSettingsStore::save`
        // truncates before it writes, so a plain write-on-every-call let one test read the file
        // another was halfway through -- `load` swallows the parse failure and hands back defaults,
        // which have revocation ON. That turned into an intermittent failure in the one test whose
        // assertion depends on the setting, and it appeared only once a second test started calling
        // this often enough to collide.
        static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            let path = std::env::temp_dir()
                .join("pittv3-capi-run-no-revocation.json")
                .to_string_lossy()
                .to_string();
            let mut cps = certval::CertificationPathSettings::new();
            cps.set_check_revocation_status(false);
            FileSettingsStore::new(&path).save(&cps).expect("save");
            path
        })
        .clone()
    }

    /// Args as the Validate view produces them for a PKITS run.
    fn args_for(targets: &[&str], anchors: &[&str], cas: &[&str]) -> Pittv3Args {
        Pittv3Args {
            ee_inputs: targets.iter().map(|t| pkits_path(t)).collect(),
            ta_inputs: anchors.iter().map(|t| pkits_path(t)).collect(),
            ca_inputs: cas.iter().map(|t| pkits_path(t)).collect(),
            time_of_interest: TOI,
            settings: Some(settings_without_revocation()),
            ..Default::default()
        }
    }

    /// A pool entry naming a file yields one target, labeled by the path it came from.
    #[test]
    fn a_file_is_one_labeled_target() {
        let args = args_for(&["ValidCertificatePathTest1EE.crt"], &[], &[]);
        let inputs = gather(&args, CapiTrust::RunAnchors);
        assert_eq!(inputs.targets.len(), 1);
        assert!(inputs.targets[0]
            .0
            .ends_with("ValidCertificatePathTest1EE.crt"));
        assert!(!inputs.targets[0].1.is_empty());
        assert_eq!(inputs.time_of_interest, Some(TOI));
    }

    /// A folder yields every certificate under it, in a stable order — which is what lets two runs'
    /// logs be compared line by line.
    #[test]
    fn a_folder_is_read_in_a_stable_order() {
        let args = Pittv3Args {
            ee_inputs: vec![PKITS.to_string()],
            time_of_interest: TOI,
            ..Default::default()
        };
        let first = gather(&args, CapiTrust::RunAnchors).targets;
        let second = gather(&args, CapiTrust::RunAnchors).targets;
        assert!(first.len() > 100, "PKITS holds more than this");
        assert_eq!(
            first.iter().map(|(l, _)| l).collect::<Vec<_>>(),
            second.iter().map(|(l, _)| l).collect::<Vec<_>>()
        );
    }

    /// With the run's anchors chosen, anchors become the exclusive root set and CA material stays
    /// separate. This is the split the whole comparison rests on.
    #[test]
    fn run_anchors_become_the_exclusive_root_set() {
        let args = args_for(
            &["ValidCertificatePathTest1EE.crt"],
            &["TrustAnchorRootCertificate.crt"],
            &["GoodCACert.crt"],
        );
        let inputs = gather(&args, CapiTrust::RunAnchors);
        assert_eq!(inputs.trust_anchors.len(), 1);
        assert_eq!(inputs.additional_certs.len(), 1);
    }

    /// With the machine's stores chosen, nothing is trusted by the run — but the anchors still go
    /// in as candidates, so a chain that needs one to reach a machine-trusted root can still be
    /// built.
    #[test]
    fn machine_stores_trust_nothing_from_the_run_but_still_take_its_certificates() {
        let args = args_for(
            &["ValidCertificatePathTest1EE.crt"],
            &["TrustAnchorRootCertificate.crt"],
            &["GoodCACert.crt"],
        );
        let inputs = gather(&args, CapiTrust::MachineStores);
        assert!(inputs.trust_anchors.is_empty());
        assert_eq!(inputs.additional_certs.len(), 2);
    }

    /// The end-to-end shape the button produces for a path that validates.
    #[test]
    fn a_valid_run_reads_as_one() {
        let args = args_for(
            &["ValidCertificatePathTest1EE.crt"],
            &["TrustAnchorRootCertificate.crt"],
            &["GoodCACert.crt"],
        );
        let lines = execute(&args, CapiTrust::RunAnchors).to_lines();
        let text = lines.join("\n");

        assert!(text.contains("1 trust anchor(s) from this run"), "{text}");
        assert!(text.contains("without revocation checking"), "{text}");
        assert!(text.contains("result: Valid"), "{text}");
        assert!(text.contains("chain 0 (preferred), 3 element(s)"), "{text}");
        assert!(text.contains("Valid EE Certificate Test1"), "{text}");
        assert!(text.ends_with("CAPI: 1 Valid"), "{text}");
    }

    /// The same material against this machine's stores, where the PKITS root is not trusted. The
    /// run still has an answer, and the answer names the reason.
    #[test]
    fn an_untrusted_run_says_why() {
        let args = args_for(
            &["ValidCertificatePathTest1EE.crt"],
            &["TrustAnchorRootCertificate.crt"],
            &["GoodCACert.crt"],
        );
        let lines = execute(&args, CapiTrust::MachineStores).to_lines();
        let text = lines.join("\n");

        assert!(text.contains("this machine's certificate stores"), "{text}");
        // An untrusted root is a verdict about trust rather than a failure to build, so it rolls
        // up to `Invalid` and not to the absence of a path.
        assert!(text.contains("result: Invalid"), "{text}");
        assert!(text.contains("CERT_TRUST_IS_UNTRUSTED_ROOT"), "{text}");
        assert!(text.ends_with("CAPI: 1 Invalid"), "{text}");
    }

    /// The header says which way revocation went, because the same target can be valid one way and
    /// `CRYPT_E_REVOCATION_OFFLINE` the other, and a log that did not say would leave a reader
    /// comparing two runs with no way to tell them apart.
    #[test]
    fn the_header_reports_the_revocation_setting() {
        // No targets, so the run stops after the header -- this is about what the header says, and
        // a run with checking left on would otherwise wait on distribution points that do not
        // resolve before saying it.
        let mut args = args_for(&[], &[], &[]);
        assert!(execute(&args, CapiTrust::RunAnchors).to_lines()[0]
            .contains("without revocation checking"));

        // No settings file is certval's default, which is checking on.
        args.settings = None;
        assert!(execute(&args, CapiTrust::RunAnchors).to_lines()[0].contains("checking revocation"));
    }

    /// The regression behind two identical logs: the checkbox asked for this run's anchors, none
    /// were gathered, and `verify` reads an empty anchor set as "use the default chain engine".
    /// The run then answered the question the checkbox was turned on to stop it answering, and the
    /// header said "against 0 trust anchor(s) from this run" while the engine consulted Windows.
    #[test]
    fn asking_for_run_anchors_with_none_gathered_says_so() {
        // A target and no anchor inputs at all, which is what the selector's custom entry with
        // empty pools produces.
        let args = args_for(&["ValidCertificatePathTest1EE.crt"], &[], &[]);
        let lines = execute(&args, CapiTrust::RunAnchors).to_lines();
        let text = lines.join(
            "
",
        );

        // The header must not claim the run's anchors were used.
        assert!(
            !lines[0].contains("0 trust anchor(s) from this run"),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("NOT this run's anchors"), "{}", lines[0]);
        assert!(text.contains("no trust anchors were gathered"), "{text}");
        assert!(text.contains("no anchor inputs were named"), "{text}");
    }

    /// A CAPI store selection gathers no anchor bytes and is still using the run's trust material,
    /// because that material *is* the Windows stores. The checkbox making no difference there is
    /// correct, and reporting it as a substitution would send a reader looking for a bug.
    #[cfg(feature = "capi")]
    #[test]
    fn a_capi_store_selection_is_the_runs_trust_not_a_fallback() {
        let mut args = args_for(&["ValidCertificatePathTest1EE.crt"], &[], &[]);
        args.capi_ta_stores = vec![r"CurrentUser\ROOT".to_string()];
        let lines = execute(&args, CapiTrust::RunAnchors).to_lines();
        let text = lines.join(
            "
",
        );

        assert!(
            lines[0].contains("which are this run's trust material"),
            "{}",
            lines[0]
        );
        assert!(!text.contains("NOT this run's anchors"), "{text}");
        assert!(!text.contains("no trust anchors were gathered"), "{text}");
    }

    /// When anchor inputs were named and still yielded nothing, the log names them -- the reader
    /// needs to tell "no store selected" from "the store selected could not be read".
    #[test]
    fn anchor_inputs_that_yielded_nothing_are_named() {
        let mut args = args_for(&["ValidCertificatePathTest1EE.crt"], &[], &[]);
        args.ta_inputs = vec!["a-path-that-is-not-there.cbor".to_string()];
        let lines = execute(&args, CapiTrust::RunAnchors).to_lines();
        let text = lines.join(
            "
",
        );

        assert!(text.contains("anchor inputs consulted"), "{text}");
        assert!(text.contains("a-path-that-is-not-there.cbor"), "{text}");
    }

    /// The honest case is left alone: anchors present, header says so, no warning.
    #[test]
    fn anchors_present_produces_no_fallback_warning() {
        let args = args_for(
            &["ValidCertificatePathTest1EE.crt"],
            &["TrustAnchorRootCertificate.crt"],
            &["GoodCACert.crt"],
        );
        let lines = execute(&args, CapiTrust::RunAnchors).to_lines();
        let text = lines.join(
            "
",
        );

        assert!(
            lines[0].contains("1 trust anchor(s) from this run"),
            "{text}"
        );
        assert!(!text.contains("no trust anchors were gathered"), "{text}");
    }

    /// The pane badges these counts and the log prints them, so they are one computation rather
    /// than two that can disagree. Bytes CAPI would not read are counted apart from a faulted path,
    /// because the engine declining to judge and the engine faulting a path are different findings.
    #[test]
    fn counts_separate_the_outcomes_the_pane_badges() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.crt");
        fs::write(&junk, [0x30u8, 0x03, 0x02, 0x01, 0x00]).unwrap();

        let mut args = args_for(
            &[
                "ValidCertificatePathTest1EE.crt",
                "InvalidCASignatureTest2EE.crt",
            ],
            &["TrustAnchorRootCertificate.crt"],
            &["GoodCACert.crt", "BadSignedCACert.crt"],
        );
        args.ee_inputs.push(junk.to_string_lossy().to_string());

        let result = execute(&args, CapiTrust::RunAnchors);
        assert_eq!(result.targets.len(), 3);
        assert_eq!(
            rollup_counts(&result.targets),
            vec![
                (Some(TargetStatus::Valid), 1),
                (Some(TargetStatus::Invalid), 1),
                (Some(TargetStatus::ParseError), 1),
            ],
            "{:?}",
            result.to_lines()
        );
        assert!(!result.fell_back());
        assert!(result.trust_summary().contains("1 trust anchor"));

        // The summary line is rendered from the same counts, in the same words.
        assert_eq!(
            result.to_lines().last().unwrap(),
            "CAPI: 1 Valid, 1 Invalid, 1 Not a certificate"
        );
    }

    /// An empty pool is a run that says so rather than an empty log the reader has to interpret.
    #[test]
    fn nothing_to_validate_says_so() {
        let args = Pittv3Args {
            time_of_interest: TOI,
            ..Default::default()
        };
        let lines = execute(&args, CapiTrust::RunAnchors).to_lines();
        assert_eq!(lines.last().unwrap(), "CAPI: nothing to validate.");
    }

    /// Bytes CAPI refuses are counted apart from an invalid path, and are named for what they are:
    /// the file could not be read as a certificate, which says nothing about any certificate's
    /// standing. A summary that merged the two would overstate what the engine said.
    #[test]
    fn a_refused_target_is_counted_apart() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.crt");
        // Leading 0x30 so `certs_in` hands it on as a certificate and CAPI is the one to refuse it.
        fs::write(&junk, [0x30u8, 0x03, 0x02, 0x01, 0x00]).unwrap();

        let args = Pittv3Args {
            ee_inputs: vec![junk.to_string_lossy().to_string()],
            time_of_interest: TOI,
            ..Default::default()
        };
        let lines = execute(&args, CapiTrust::MachineStores).to_lines();
        let text = lines.join("\n");
        assert!(text.contains("result: Not a certificate"), "{text}");
        assert!(
            text.contains("CAPI would not parse the target as a certificate"),
            "{text}"
        );
        assert!(text.ends_with("CAPI: 1 Not a certificate"), "{text}");
    }

    // ------------------------------------------------------------------ the rollup

    const NOT_TIME_VALID: u32 = 0x0000_0001;
    const REVOKED_BIT: u32 = 0x0000_0004;
    const UNTRUSTED_ROOT: u32 = 0x0000_0020;
    const REVOCATION_UNKNOWN_BIT: u32 = 0x0000_0040;
    const PARTIAL_CHAIN_BIT: u32 = 0x0001_0000;
    const OFFLINE_REVOCATION: u32 = 0x0100_0000;

    const CRYPT_E_REVOKED: u32 = 0x8009_2010;
    const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
    const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;

    pub(crate) fn element(error: u32) -> CapiElement {
        CapiElement {
            cert: None,
            der: vec![],
            trust_status: CapiTrustStatus::new(error, 0),
            revocation: None,
            extended_error_info: None,
        }
    }

    /// One chain of one element, both carrying `error` in a context that carries it too, which is
    /// the shape the engine reports a single fault in. Shared with the results pane's own tests, so
    /// the badge and the rollup are exercised against one fixture.
    pub(crate) fn faulted(error: u32) -> CapiVerification {
        CapiVerification {
            target: None,
            target_der: vec![],
            chains: vec![CapiChain {
                index: 0,
                lower_quality: false,
                trust_status: CapiTrustStatus::new(error, 0),
                elements: vec![element(error)],
            }],
            trust_status: CapiTrustStatus::new(error, 0),
            policy_error: None,
            policy_error_location: None,
            validated: 0 == error,
        }
    }

    fn status_of(verification: CapiVerification) -> Option<TargetStatus> {
        rollup(&Ok(verification))
    }

    /// A clean run is `Valid`, which is the one outcome the two surfaces always agreed on.
    #[test]
    fn a_clean_run_is_valid() {
        assert_eq!(status_of(faulted(0)), Some(TargetStatus::Valid));
    }

    /// The divergence this read backwards. Windows folds "no revocation status" into the same error
    /// mask as a bad signature, so a chain that is sound except that a responder would not answer
    /// badged flat red and logged `INVALID`, while the certval tab called it amber. Either flag,
    /// and both.
    #[test]
    fn revocation_alone_is_not_invalid() {
        for error in [
            REVOCATION_UNKNOWN_BIT,
            OFFLINE_REVOCATION,
            REVOCATION_UNKNOWN_BIT | OFFLINE_REVOCATION,
        ] {
            assert_eq!(
                status_of(faulted(error)),
                Some(TargetStatus::ValidExceptRevocationUndetermined),
                "0x{error:08X}"
            );
        }
    }

    /// Anything else in the mask is a real fault and outranks an unsettled revocation status.
    #[test]
    fn revocation_plus_a_real_fault_is_invalid() {
        assert_eq!(
            status_of(faulted(REVOCATION_UNKNOWN_BIT | NOT_TIME_VALID)),
            Some(TargetStatus::Invalid)
        );
    }

    /// A bit no table names must not be masked away into a revocation-only reading: a flag Windows
    /// adds after this build would otherwise turn an unknown fault into an almost-clean result.
    #[test]
    fn an_unnamed_bit_is_not_a_clean_revocation_result() {
        assert_eq!(
            status_of(faulted(REVOCATION_UNKNOWN_BIT | 0x8000_0000)),
            Some(TargetStatus::Invalid)
        );
    }

    /// The policy check runs after the build and can fail for its own reasons, so it has to agree
    /// before a revocation-only mask reads as one.
    #[test]
    fn the_policy_check_has_to_agree() {
        let mut its_own_complaint = faulted(REVOCATION_UNKNOWN_BIT);
        its_own_complaint.policy_error = Some(CapiError(CERT_E_UNTRUSTEDROOT));
        assert_eq!(status_of(its_own_complaint), Some(TargetStatus::Invalid));

        let mut the_same_story = faulted(REVOCATION_UNKNOWN_BIT);
        the_same_story.policy_error = Some(CapiError(CRYPT_E_REVOCATION_OFFLINE));
        assert_eq!(
            status_of(the_same_story),
            Some(TargetStatus::ValidExceptRevocationUndetermined)
        );
    }

    /// Revoked outranks every other fault, from whichever of the three places says so.
    #[test]
    fn revoked_outranks_every_other_fault() {
        assert_eq!(
            status_of(faulted(REVOKED_BIT | NOT_TIME_VALID)),
            Some(TargetStatus::Revoked)
        );

        let mut on_an_element = faulted(NOT_TIME_VALID);
        on_an_element.chains[0].elements.push(element(REVOKED_BIT));
        assert_eq!(status_of(on_an_element), Some(TargetStatus::Revoked));

        let mut from_the_policy_check = faulted(NOT_TIME_VALID);
        from_the_policy_check.policy_error = Some(CapiError(CRYPT_E_REVOKED));
        assert_eq!(
            status_of(from_the_policy_check),
            Some(TargetStatus::Revoked)
        );
    }

    /// A revoked certificate in a chain the engine built and declined to prefer is still one this
    /// run found, which is the predicate the pane has always used.
    #[test]
    fn revoked_in_a_lower_quality_chain_still_counts() {
        let mut verification = faulted(NOT_TIME_VALID);
        verification.chains.push(CapiChain {
            index: 1,
            lower_quality: true,
            trust_status: CapiTrustStatus::new(REVOKED_BIT, 0),
            elements: vec![element(REVOKED_BIT)],
        });
        assert_eq!(status_of(verification), Some(TargetStatus::Revoked));
    }

    /// A chain that never reached an anchor reports the absence of a result rather than a fault in
    /// the certificate, and sends a reader to the run's trust material. So does a run that built no
    /// chain at all.
    #[test]
    fn a_partial_chain_is_no_paths_found() {
        assert_eq!(
            status_of(faulted(PARTIAL_CHAIN_BIT | REVOCATION_UNKNOWN_BIT)),
            Some(TargetStatus::NoPathsFound)
        );

        let mut nothing_built = faulted(PARTIAL_CHAIN_BIT);
        nothing_built.chains.clear();
        assert_eq!(status_of(nothing_built), Some(TargetStatus::NoPathsFound));
    }

    /// An untrusted root goes the other way on purpose: the engine got all the way to a root and
    /// was refused it, which is a verdict about trust rather than a failure to build.
    #[test]
    fn an_untrusted_root_is_invalid() {
        assert_eq!(
            status_of(faulted(UNTRUSTED_ROOT)),
            Some(TargetStatus::Invalid)
        );
    }

    /// Bytes CAPI would not read are a statement about the file, which is what certval calls a
    /// parse error. Every other refusal is about the run and has no rollup at all.
    #[test]
    fn a_refusal_is_a_parse_error_or_no_verdict_at_all() {
        assert_eq!(
            rollup(&Err(CapiVerifyError::TargetNotParsed(0x8009_2002))),
            Some(TargetStatus::ParseError)
        );

        for error in [
            CapiVerifyError::ChainBuildFailed(0x800B_010A),
            CapiVerifyError::PolicyCheckFailed(0x8009_2002),
            CapiVerifyError::StoreFailed(0x8009_2002),
            CapiVerifyError::EngineFailed(0x8009_2002),
            CapiVerifyError::InvalidOid("2.5.29".to_string()),
            CapiVerifyError::Unsupported,
        ] {
            assert_eq!(rollup(&Err(error.clone())), None, "{error}");
            assert_eq!(rollup_label(rollup(&Err(error.clone()))), "No verdict");
        }
    }

    /// The counts are ordered as the statuses are declared, omit what did not occur and put the
    /// refusals last, so the strip on screen and the log's closing line read the same run the same
    /// way round.
    #[test]
    fn counts_are_ordered_and_omit_what_did_not_occur() {
        let outcome = |outcome| CapiTargetOutcome {
            label: "target".to_string(),
            outcome,
        };
        let targets = vec![
            outcome(Ok(faulted(UNTRUSTED_ROOT))),
            outcome(Err(CapiVerifyError::Unsupported)),
            outcome(Ok(faulted(PARTIAL_CHAIN_BIT))),
            outcome(Ok(faulted(REVOCATION_UNKNOWN_BIT))),
            outcome(Ok(faulted(0))),
            outcome(Err(CapiVerifyError::TargetNotParsed(0))),
            outcome(Ok(faulted(REVOKED_BIT))),
        ];

        let labels: Vec<&str> = rollup_counts(&targets)
            .iter()
            .map(|(status, _)| rollup_label(*status))
            .collect();
        assert_eq!(
            labels,
            vec![
                "Valid",
                "Valid (revocation undetermined)",
                "Revoked",
                "Invalid",
                "No paths found",
                "Not a certificate",
                "No verdict",
            ]
        );
        assert!(rollup_counts(&targets).iter().all(|(_, n)| 1 == *n));
    }
}

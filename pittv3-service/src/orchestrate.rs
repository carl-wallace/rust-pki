//! Server-side validation: the same synchronous path the browser runs, with the retrieving done
//! here instead of through a relay.
//!
//! Nothing in this module is an HTTP type. A test calls [`validate`] with byte strings and gets a
//! report back, which is the same shape the browser calls the shared path with -- and the reason
//! the two tiers cannot drift apart is that they call the same functions with the same certval
//! build. What differs is only who fetches.

use std::collections::BTreeSet;
use std::time::Instant;

use log::debug;

use certval::{collect_uris_from_aia_and_sia, parse_cert, CertificationPathSettings};
// The fold half of a retrieving run is shared with the browser rather than kept here: the two tiers
// have to agree about what a retrieved body contained, and the surest way for them to agree is for
// there to be one implementation of it.
use pittv3_gui_lib::retrieval::{certificates_in, harvest_revocation_work};
use pittv3_gui_lib::validate::{prepare_validation, validate_prepared, PreparedValidation};
use pittv3_lib::report::{TargetReport, ValidationReport};
use pittv3_relay::{ChaseBudget, FetchRequest, Relay};

use crate::config::{RequestLimits, ServiceState};
use crate::settings::sanitize;

/// A validation request in plain Rust: certificates as bytes, each with the name to report it
/// under.
#[derive(Clone, Debug, Default)]
pub struct ValidationInput {
    /// Certificates to validate.
    pub targets: Vec<(String, Vec<u8>)>,
    /// Trust anchors supplied by the caller, merged with any named store.
    pub trust_anchors: Vec<(String, Vec<u8>)>,
    /// CA certificates supplied by the caller, merged with any named store.
    pub cas: Vec<(String, Vec<u8>)>,
    /// Identifier of a store the service holds.
    pub store_id: Option<String>,
    /// Path settings for the run, before sanitization.
    pub settings: CertificationPathSettings,
    /// Validates every path found for a target rather than stopping at the first that validates.
    pub validate_all: bool,
}

/// A report plus what the run has to say about itself.
#[derive(Clone, Debug)]
pub struct ValidationOutcome {
    /// Result of the run.
    pub report: ValidationReport,
    /// Remarks: settings that were not honored, retrievals a budget cut short, certificates that
    /// could not be parsed.
    pub notes: Vec<String>,
}

impl ValidationOutcome {
    /// Builds an outcome describing a run that could not be carried out.
    pub fn failed(message: impl Into<String>) -> Self {
        ValidationOutcome {
            report: ValidationReport::failed(message),
            notes: vec![],
        }
    }
}

/// Validates the certificates in `input`.
///
/// The run is: check the request against the caps, sanitize the settings, assemble the trust
/// material, prepare the environment, validate. When nothing validated and the deployment permits
/// chasing, authority and subject information access URIs are followed and the environment is
/// prepared again with what came back -- deliberately as a second attempt rather than interleaved
/// with path building, since preparing is the expensive step and most runs never need the retry.
///
/// Revocation status is determined where the certificates say how: the shared path's
/// `check_revocation` consults a registered CRL source and the responses stapled into a path, and
/// this service fills both by retrieving the distribution points and querying the responders named
/// on the paths it built — through the relay, so the same policy and budgets govern it. See
/// [`retrieve_revocation_data`].
pub async fn validate(state: &ServiceState, input: ValidationInput) -> ValidationOutcome {
    let started = Instant::now();

    if let Err(message) = check_limits(&state.config.limits, &input) {
        return ValidationOutcome::failed(message);
    }

    let mut settings = input.settings.clone();
    let mut notes = sanitize(&mut settings, &state.config);

    let store = match &input.store_id {
        Some(id) => match state.stores.get(id) {
            Some(entry) => Some((
                entry.label.as_str(),
                entry.ta_cbor.as_ref(),
                entry.ca_cbor.as_ref(),
            )),
            None => return ValidationOutcome::failed(format!("unknown store: {id}")),
        },
        None => None,
    };

    let mut cas = input.cas.clone();
    let (targets, mut lines) = run(state, &input, store, &cas, &settings, &mut notes).await;
    let mut targets = targets;

    let chased = state.config.allow_dynamic_build && !anything_validated(&targets);
    if chased {
        let mut budget = ChaseBudget::new(state.config.chase_budget.clone());
        let seeds = input
            .targets
            .iter()
            .chain(input.cas.iter())
            .cloned()
            .collect::<Vec<(String, Vec<u8>)>>();
        let added = chase(&state.relay, &mut budget, &seeds, &mut cas, &mut notes).await;
        if added > 0 {
            notes.push(format!(
                "retrieved {added} certificate(s) in {} fetch(es) and validated again",
                budget.fetches()
            ));
            let (retried, retry_lines) =
                run(state, &input, store, &cas, &settings, &mut notes).await;
            targets = retried;
            lines = retry_lines;
        }
    }

    notes.extend(lines);
    let toi = time_of_interest(&settings);
    let mut report = ValidationReport::from_targets(&targets, toi);
    report.duration_ms = started.elapsed().as_millis() as u64;
    ValidationOutcome { report, notes }
}

/// Prepares an environment, retrieves the revocation data the paths through it call for, and
/// validates every target against it. Returns the reports and the notes worth keeping: everything
/// preparation had to say, since that is where a run explains why it has no trust material, and the
/// complaints from validation, since its progress lines say nothing the report does not already
/// carry.
///
/// Asynchronous only for the retrieval in the middle. Preparing and validating are the same
/// synchronous calls the browser makes, which is what keeps the two tiers from disagreeing.
async fn run(
    state: &ServiceState,
    input: &ValidationInput,
    store: Option<(&str, &[u8], &[u8])>,
    cas: &[(String, Vec<u8>)],
    settings: &CertificationPathSettings,
    notes: &mut Vec<String>,
) -> (Vec<TargetReport>, Vec<String>) {
    let (prepared, mut lines) = match prepare_validation(store, &input.trust_anchors, cas, settings)
    {
        Ok((prepared, lines)) => (
            prepared,
            lines
                .iter()
                .map(|l| l.text.clone())
                .collect::<Vec<String>>(),
        ),
        Err(lines) => {
            return (
                vec![],
                lines
                    .iter()
                    .map(|l| l.text.clone())
                    .collect::<Vec<String>>(),
            )
        }
    };

    if state.config.fetch_revocation_data && settings.get_check_revocation_status() {
        retrieve_revocation_data(state, &prepared, input, settings, notes).await;
    }

    let (targets, validation_lines) =
        validate_prepared(&prepared, settings, &input.targets, input.validate_all);
    lines.extend(
        validation_lines
            .iter()
            .filter(|l| l.class == "err")
            .map(|l| l.text.clone()),
    );
    (targets, lines)
}

/// Retrieves the revocation data the certificates on the paths this environment builds call for:
/// the CRLs they name, and an OCSP response per certificate whose issuer runs a responder.
///
/// The work comes from the paths rather than from the request, so what is retrieved is what the
/// certificates actually being validated call for. Retrieval goes through the relay like every
/// other outbound request this service makes: certval here is built without `remote` and cannot
/// open a socket of its own, so the network policy and the budgets cannot be gone around.
///
/// CRLs are retrieved first because one covers every certificate its issuer published it for,
/// while an OCSP request answers about exactly one — so a distribution point can settle several
/// positions at the price of one retrieval, and every certificate it settles is one this then does
/// not have to ask a responder about.
///
/// A failure is a note rather than an error. Revocation status that cannot be determined is already
/// an outcome the report expresses, and one unreachable repository should not turn a run into a
/// failure.
async fn retrieve_revocation_data(
    state: &ServiceState,
    prepared: &PreparedValidation,
    input: &ValidationInput,
    settings: &CertificationPathSettings,
    notes: &mut Vec<String>,
) -> usize {
    let work = harvest_revocation_work(prepared, settings, &input.targets);
    if work.is_empty() {
        return 0;
    }

    let mut budget = ChaseBudget::new(state.config.chase_budget.clone());
    let mut added = 0;

    let crl_sink = prepared.crl_source();
    for uri in &work.crl_dp {
        if let Err(exhausted) = budget.check() {
            notes.push(format!("stopped retrieving CRLs: {exhausted}"));
            break;
        }
        let request = FetchRequest {
            max_response_bytes: Some(budget.remaining_bytes()),
            timeout: Some(budget.remaining_time()),
            ..FetchRequest::get(uri.clone())
        };
        match state.relay.fetch(&request).await {
            Ok(response) => {
                budget.spend(response.body.len() as u64);
                if response.status != 200 {
                    notes.push(format!("{uri} answered with status {}", response.status));
                    continue;
                }
                match crl_sink.add(&response.body) {
                    true => added += 1,
                    false => notes.push(format!("{uri} did not serve a CRL")),
                }
            }
            Err(e) => {
                budget.spend(0);
                notes.push(format!("could not retrieve {uri}: {e}"));
            }
        }
    }
    if added > 0 {
        notes.push(format!("retrieved {added} CRL(s)"));
    }

    // A certificate a CRL already answered for is not asked about again, and neither is one whose
    // second responder would repeat a question the first has settled.
    let ocsp_sink = prepared.ocsp_responses();
    let mut responses = 0;
    for item in &work.ocsp {
        if ocsp_sink.contains(&item.key) {
            continue;
        }
        if let Err(exhausted) = budget.check() {
            notes.push(format!("stopped sending OCSP requests: {exhausted}"));
            break;
        }
        let request = FetchRequest {
            max_response_bytes: Some(budget.remaining_bytes()),
            timeout: Some(budget.remaining_time()),
            ..FetchRequest::ocsp(item.uri.clone(), item.request.clone())
        };
        match state.relay.fetch(&request).await {
            Ok(response) => {
                budget.spend(response.body.len() as u64);
                if response.status != 200 {
                    notes.push(format!(
                        "{} answered with status {}",
                        item.uri, response.status
                    ));
                    continue;
                }
                ocsp_sink.insert(item.key.clone(), response.body);
                responses += 1;
            }
            Err(e) => {
                budget.spend(0);
                notes.push(format!("could not reach {}: {e}", item.uri));
            }
        }
    }
    if responses > 0 {
        notes.push(format!("retrieved {responses} OCSP response(s)"));
    }

    added + responses
}

/// Reports whether any target produced a path that validated, which is what decides whether a
/// chase is worth attempting.
fn anything_validated(targets: &[TargetReport]) -> bool {
    targets.iter().any(|t| {
        t.paths
            .iter()
            .any(|p| p.error.is_none() && p.status == Some(certval::PathValidationStatus::Valid))
    })
}

/// Follows the authority and subject information access URIs named by `seeds`, and by whatever they
/// lead to, adding the certificates retrieved to `cas` and returning how many were added.
///
/// The loop stops when a round retrieves nothing new -- a round that produced only certificates
/// already in hand cannot produce new URIs next time around -- or when a budget is exhausted. A
/// path found within budget is a good answer and no path found within budget is an incomplete search
/// rather than an error.
async fn chase(
    relay: &Relay,
    budget: &mut ChaseBudget,
    seeds: &[(String, Vec<u8>)],
    cas: &mut Vec<(String, Vec<u8>)>,
    notes: &mut Vec<String>,
) -> usize {
    let mut retrieved = BTreeSet::new();
    let mut added = 0;

    loop {
        let mut uris = vec![];
        for (name, der) in seeds.iter().chain(cas.iter()) {
            match parse_cert(der, name) {
                Ok(cert) => collect_uris_from_aia_and_sia(&cert, &mut uris),
                Err(e) => debug!("Skipped {name} while harvesting URIs: {e:?}"),
            }
        }
        uris.retain(|uri| !retrieved.contains(uri));
        if uris.is_empty() {
            return added;
        }

        let mut added_this_round = 0;
        for uri in uris {
            if let Err(exhausted) = budget.check() {
                notes.push(format!("stopped retrieving: {exhausted}"));
                return added;
            }
            retrieved.insert(uri.clone());

            let request = FetchRequest {
                max_response_bytes: Some(budget.remaining_bytes()),
                timeout: Some(budget.remaining_time()),
                ..FetchRequest::get(uri.clone())
            };
            let response = match relay.fetch(&request).await {
                Ok(r) => r,
                Err(e) => {
                    budget.spend(0);
                    notes.push(format!("could not retrieve {uri}: {e}"));
                    continue;
                }
            };
            budget.spend(response.body.len() as u64);
            if response.status != 200 {
                notes.push(format!("{uri} answered with status {}", response.status));
                continue;
            }

            for (index, der) in certificates_in(&response.body).into_iter().enumerate() {
                if cas.iter().any(|(_, existing)| *existing == der) {
                    continue;
                }
                cas.push((format!("{uri}#{index}"), der));
                added += 1;
                added_this_round += 1;
            }
        }

        // A round that retrieved only certificates already in hand cannot produce new URIs next
        // time around, so stopping here avoids a pass that reharvests the same set.
        if added_this_round == 0 {
            return added;
        }
    }
}

/// Rejects a request that exceeds the caps before any work is scheduled for it.
fn check_limits(limits: &RequestLimits, input: &ValidationInput) -> Result<(), String> {
    if input.targets.is_empty() {
        return Err("no target certificates were supplied".to_string());
    }
    if input.targets.len() > limits.max_targets {
        return Err(format!(
            "too many targets: {} exceeds the limit of {}",
            input.targets.len(),
            limits.max_targets
        ));
    }
    if input.trust_anchors.len() > limits.max_trust_anchors {
        return Err(format!(
            "too many trust anchors: {} exceeds the limit of {}",
            input.trust_anchors.len(),
            limits.max_trust_anchors
        ));
    }
    if input.cas.len() > limits.max_cas {
        return Err(format!(
            "too many CA certificates: {} exceeds the limit of {}",
            input.cas.len(),
            limits.max_cas
        ));
    }
    for (name, der) in input
        .targets
        .iter()
        .chain(input.trust_anchors.iter())
        .chain(input.cas.iter())
    {
        if der.len() > limits.max_certificate_bytes {
            return Err(format!(
                "{name} is {} bytes, over the {}-byte limit for one certificate",
                der.len(),
                limits.max_certificate_bytes
            ));
        }
    }
    Ok(())
}

/// Returns the time the run validated against, for stamping the report: the time of interest from
/// the settings, or the current time when validity checking was left at its default.
fn time_of_interest(settings: &CertificationPathSettings) -> u64 {
    let toi = settings.get_time_of_interest();
    if !toi.is_disabled() {
        return toi.as_unix_secs();
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use certval::TimeOfInterest;

    #[test]
    fn a_bare_certificate_and_a_message_both_yield_certificates() {
        // Neither parses as a message, so the SEQUENCE fallback applies to the first and the
        // second is not a certificate at all.
        assert_eq!(certificates_in(&[0x30, 0x03, 0x02, 0x01, 0x01]).len(), 1);
        assert!(certificates_in(b"<html>not a certificate</html>").is_empty());
        assert!(certificates_in(&[]).is_empty());
    }

    #[test]
    fn limits_reject_before_work_is_scheduled() {
        let limits = RequestLimits {
            max_targets: 1,
            max_certificate_bytes: 4,
            ..Default::default()
        };

        let empty = ValidationInput::default();
        assert!(check_limits(&limits, &empty).is_err());

        let two = ValidationInput {
            targets: vec![("a".to_string(), vec![0x30]), ("b".to_string(), vec![0x30])],
            ..Default::default()
        };
        assert!(check_limits(&limits, &two).is_err());

        let large = ValidationInput {
            targets: vec![("a".to_string(), vec![0x30; 5])],
            ..Default::default()
        };
        assert!(check_limits(&limits, &large).is_err());

        let acceptable = ValidationInput {
            targets: vec![("a".to_string(), vec![0x30; 4])],
            ..Default::default()
        };
        assert!(check_limits(&limits, &acceptable).is_ok());
    }

    #[test]
    fn an_absent_time_of_interest_stamps_the_report_with_now() {
        let mut settings = CertificationPathSettings::default();
        assert!(time_of_interest(&settings) > 0);

        settings.set_time_of_interest(TimeOfInterest::from_unix_secs(1_700_000_000).unwrap());
        assert_eq!(time_of_interest(&settings), 1_700_000_000);
    }
}

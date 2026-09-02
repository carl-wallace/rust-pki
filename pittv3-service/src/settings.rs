//! The settings a validation request runs under: the service's own defaults, and the sanitizing of
//! what a client sends.
//!
//! `CertificationPathSettings` is the tool's own configuration structure, not a wire format. It
//! carries folder and file names that mean nothing on the far side of an HTTP request and that a
//! service must not act on, and it carries retrieval ceilings sized for a command-line run rather
//! than for a shared server. Both are dealt with here, on arrival, rather than by trusting a client
//! to have omitted them.
//!
//! What a request *omits* is settled here too, and by this service rather than by its dependencies.
//! certval is built here without `std`, which is a build with no clock — `SystemTime` does not
//! exist in `no_std` — so `TimeOfInterest` has nothing to default to and the time a run validates
//! against is the caller's to supply. This service is that caller. Leaving it unstated is not a
//! narrower check but no check: `check_validity` returns `Ok(())` when the time of interest is
//! disabled, so an omitted value meant a certificate's validity period was never consulted.
//! [`defaults`] states what a run means instead of leaving an obligation unmet.

use certval::*;

use crate::config::ServiceConfig;

/// The settings a request runs under before anything the client sent is applied.
///
/// Written as a profile rather than as one fix, so the next value a `no_std` build leaves to its
/// caller does not have to be discovered the way this one was — by an expired certificate coming
/// back valid.
///
/// **Time of interest: now.** A `no_std` build has no clock, so certval cannot supply this and does
/// not pretend to; the time a run validates against is the caller's to state, and `check_validity`
/// returns `Ok(())` when none was. Leaving it unstated is therefore not a wider validity window but
/// the absence of the check. The browser frontend states the same value for the same reason
/// (`pittv3-wasm`'s `run_settings`), which is what keeps a served run and a page run answering
/// alike.
pub fn defaults() -> CertificationPathSettings {
    let mut settings = CertificationPathSettings::default();
    if let Ok(toi) = TimeOfInterest::from_unix_secs(now_as_unix_secs()) {
        settings.set_time_of_interest(toi);
    }
    settings
}

/// Applies `requested` over the service's [`defaults`], returning what the run should use.
///
/// An overlay rather than a replacement: a client that states one preference is saying what it
/// wants *differently*, not asking every other value to revert to unstated. Without this, sending
/// any settings at all would reintroduce the unstated time of interest that sending none used to
/// produce.
pub fn with_defaults(requested: Option<CertificationPathSettings>) -> CertificationPathSettings {
    let mut settings = defaults();
    if let Some(requested) = requested {
        settings.0.extend(requested.0);
    }
    settings
}

fn now_as_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Settings naming a location in the filesystem. A client cannot see the service's filesystem and
/// has no business steering it there, so these are removed outright rather than validated.
pub const PATH_BEARING_SETTINGS: &[&str] = &[
    PS_TRUST_ANCHOR_FOLDER,
    PS_CERTIFICATION_AUTHORITY_FOLDER,
    PS_DOWNLOAD_FOLDER,
    // Retired settings, kept on the list by name rather than by constant. They no longer steer
    // anything -- the last-modified map and the URI blocklist live in the folder they describe --
    // but a client that still sends one gets a note saying it was dropped, which is better than
    // retaining a key that silently does nothing.
    "psLastModifiedMapFile",
    "psUriBlocklistFile",
    PS_CBOR_TA_STORE,
];

/// Removes the settings a client may not steer and lowers the ones it may only lower, returning a
/// note for each change so the response can say what was ignored instead of silently doing
/// something other than what was asked.
///
/// The retrieval ceilings are clamped rather than removed: a client asking for less than the
/// service allows gets what it asked for, which is how a caller says "do not spend much on my
/// behalf". Only a request for more is refused. certval does no retrieving in this build, so today
/// the clamp guards a path that is not yet wired; it belongs here rather than at the fetch site
/// because that is where the client's value arrives.
pub fn sanitize(settings: &mut CertificationPathSettings, config: &ServiceConfig) -> Vec<String> {
    let mut notes = vec![];

    for key in PATH_BEARING_SETTINGS {
        if settings.0.remove(*key).is_some() {
            notes.push(format!(
                "ignored {key}: filesystem settings are not accepted"
            ));
        }
    }

    // Chasing costs outbound retrieval, so a client may ask for it only where the deployment has
    // said yes. Removing the setting leaves certval's default, which is off.
    if !config.allow_dynamic_build && settings.0.remove(PS_RETRIEVE_FROM_AIA_SIA_HTTP).is_some() {
        notes.push(format!(
            "ignored {PS_RETRIEVE_FROM_AIA_SIA_HTTP}: this service does not chase AIA and SIA URIs"
        ));
    }

    let per_fetch = config.fetch_budget.max_response_bytes;
    for key in [
        PS_MAX_AIA_FETCH_BYTES,
        PS_MAX_CRL_FETCH_BYTES,
        PS_MAX_OCSP_FETCH_BYTES,
    ] {
        if let Some(note) = clamp_u64(settings, key, per_fetch) {
            notes.push(note);
        }
    }

    if let Some(note) = clamp_u64(
        settings,
        PS_MAX_AIA_SIA_CERTS,
        config.chase_budget.max_fetches as u64,
    ) {
        notes.push(note);
    }

    notes
}

/// Lowers a `u64` setting to `cap` when the request asked for more, returning a note when it did.
fn clamp_u64(settings: &mut CertificationPathSettings, key: &str, cap: u64) -> Option<String> {
    let requested = match settings.0.get(key) {
        Some(CertificationPathProcessingTypes::U64(v)) => *v,
        // A value of another type is not something this service can lower, and certval's accessor
        // will ignore it; leaving it alone keeps the sanitizer from inventing values.
        _ => return None,
    };
    if requested <= cap {
        return None;
    }
    settings
        .0
        .insert(key.to_string(), CertificationPathProcessingTypes::U64(cap));
    Some(format!("lowered {key} from {requested} to {cap}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with(
        pairs: Vec<(&str, CertificationPathProcessingTypes)>,
    ) -> CertificationPathSettings {
        let mut cps = CertificationPathSettings::new();
        for (k, v) in pairs {
            cps.0.insert(k.to_string(), v);
        }
        cps
    }

    /// A run has to validate against a time, and in a build with no clock that time arrives from
    /// here or not at all. An unstated one is not a wider window: `check_validity` returns without
    /// consulting a validity period.
    #[test]
    fn a_request_that_states_no_settings_still_validates_against_a_time() {
        let bare = CertificationPathSettings::default();
        assert!(
            bare.get_time_of_interest().is_disabled(),
            "the premise of this test is that the bare default states no time"
        );

        let settings = with_defaults(None);
        assert!(!settings.get_time_of_interest().is_disabled());
    }

    /// Stating one preference says what a run should do differently; it does not withdraw the rest.
    /// Replacing rather than overlaying would have put the unstated time of interest back for every
    /// caller who sent any settings at all.
    #[test]
    fn stated_settings_ride_on_top_of_the_defaults_rather_than_replacing_them() {
        let requested = settings_with(vec![(
            PS_CHECK_REVOCATION_STATUS,
            CertificationPathProcessingTypes::Bool(false),
        )]);

        let settings = with_defaults(Some(requested));
        assert!(!settings.get_check_revocation_status());
        assert!(!settings.get_time_of_interest().is_disabled());
    }

    /// The defaults are a floor, not a ceiling: a caller asking about a certificate as of some past
    /// date gets that date, which is the whole point of the setting.
    #[test]
    fn a_stated_time_of_interest_wins() {
        let mut requested = CertificationPathSettings::new();
        requested.set_time_of_interest(TimeOfInterest::from_unix_secs(1_647_264_981).unwrap());

        let settings = with_defaults(Some(requested));
        assert_eq!(
            settings.get_time_of_interest().as_unix_secs(),
            1_647_264_981
        );
    }

    #[test]
    fn removes_filesystem_settings_and_leaves_the_rest() {
        let mut cps = settings_with(vec![
            (
                PS_TRUST_ANCHOR_FOLDER,
                CertificationPathProcessingTypes::String("/etc".to_string()),
            ),
            (
                PS_CBOR_TA_STORE,
                CertificationPathProcessingTypes::String("/tmp/ta.cbor".to_string()),
            ),
            (
                PS_CHECK_REVOCATION_STATUS,
                CertificationPathProcessingTypes::Bool(true),
            ),
        ]);

        let notes = sanitize(&mut cps, &ServiceConfig::default());

        assert_eq!(notes.len(), 2);
        assert!(!cps.0.contains_key(PS_TRUST_ANCHOR_FOLDER));
        assert!(!cps.0.contains_key(PS_CBOR_TA_STORE));
        assert!(cps.0.contains_key(PS_CHECK_REVOCATION_STATUS));
    }

    #[test]
    fn clamps_ceilings_upward_only() {
        let config = ServiceConfig::default();
        let cap = config.fetch_budget.max_response_bytes;
        let mut cps = settings_with(vec![
            (
                PS_MAX_CRL_FETCH_BYTES,
                CertificationPathProcessingTypes::U64(cap * 8),
            ),
            (
                PS_MAX_OCSP_FETCH_BYTES,
                CertificationPathProcessingTypes::U64(1024),
            ),
        ]);

        let notes = sanitize(&mut cps, &config);

        assert_eq!(notes.len(), 1);
        assert_eq!(
            cps.0.get(PS_MAX_CRL_FETCH_BYTES),
            Some(&CertificationPathProcessingTypes::U64(cap))
        );
        // A client asking for less than the service allows keeps its own smaller ceiling.
        assert_eq!(
            cps.0.get(PS_MAX_OCSP_FETCH_BYTES),
            Some(&CertificationPathProcessingTypes::U64(1024))
        );
    }

    #[test]
    fn chasing_requires_the_deployment_to_permit_it() {
        let mut cps = settings_with(vec![(
            PS_RETRIEVE_FROM_AIA_SIA_HTTP,
            CertificationPathProcessingTypes::Bool(true),
        )]);
        assert_eq!(sanitize(&mut cps, &ServiceConfig::default()).len(), 1);
        assert!(!cps.0.contains_key(PS_RETRIEVE_FROM_AIA_SIA_HTTP));

        let permissive = ServiceConfig {
            allow_dynamic_build: true,
            ..Default::default()
        };
        let mut cps = settings_with(vec![(
            PS_RETRIEVE_FROM_AIA_SIA_HTTP,
            CertificationPathProcessingTypes::Bool(true),
        )]);
        assert!(sanitize(&mut cps, &permissive).is_empty());
        assert!(cps.0.contains_key(PS_RETRIEVE_FROM_AIA_SIA_HTTP));
    }
}

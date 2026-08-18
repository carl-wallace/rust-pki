//! Sanitizing the path settings that arrive with a validation request.
//!
//! `CertificationPathSettings` is the tool's own configuration structure, not a wire format. It
//! carries folder and file names that mean nothing on the far side of an HTTP request and that a
//! service must not act on, and it carries retrieval ceilings sized for a command-line run rather
//! than for a shared server. Both are dealt with here, on arrival, rather than by trusting a client
//! to have omitted them.

use certval::*;

use crate::config::ServiceConfig;

/// Settings naming a location in the filesystem. A client cannot see the service's filesystem and
/// has no business steering it there, so these are removed outright rather than validated.
pub const PATH_BEARING_SETTINGS: &[&str] = &[
    PS_TRUST_ANCHOR_FOLDER,
    PS_CERTIFICATION_AUTHORITY_FOLDER,
    PS_DOWNLOAD_FOLDER,
    PS_LAST_MODIFIED_MAP_FILE,
    PS_URI_BLOCKLIST_FILE,
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

//! Temporary host-side harness to exercise validate_hackathon_zip against a real archive

// the app module is included wholesale; items unused by this harness are expected
#[allow(dead_code)]
#[path = "../validate.rs"]
mod validate;

use validate::{validate_hackathon_zip, ValidationSettings};

fn main() {
    let path = std::env::args().nth(1).expect("usage: ziptest <zip>");
    let bytes = std::fs::read(&path).expect("failed to read zip");
    let vs = ValidationSettings {
        toi: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        toi_custom: false,
        validate_all: true,
        initial_explicit_policy: false,
        initial_policy_mapping_inhibit: false,
        initial_inhibit_any_policy: false,
        initial_policy_set: "2.5.29.32.0".to_string(),
        enforce_trust_anchor_constraints: false,
        enforce_trust_anchor_validity: true,
        permitted_subtrees: Default::default(),
        excluded_subtrees: Default::default(),
    };
    let (reports, lines) = validate_hackathon_zip(&path, bytes, &vs);
    for line in lines {
        println!("[{}] {}", line.class, line.text);
    }
    for report in reports {
        println!(
            "[report] {}: {:?} ({} path(s))",
            report.name,
            report.status,
            report.paths.len()
        );
    }
}

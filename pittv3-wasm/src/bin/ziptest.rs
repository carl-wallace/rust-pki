//! Temporary host-side harness to exercise validate_hackathon_zip against a real archive

// the app module is included wholesale; items unused by this harness are expected
#[allow(dead_code)]
#[path = "../validate.rs"]
mod validate;

use certval::{CertificationPathSettings, TimeOfInterest};
use validate::validate_hackathon_zip;

fn main() {
    let path = std::env::args().nth(1).expect("usage: ziptest <zip>");
    let bytes = std::fs::read(&path).expect("failed to read zip");
    // certval defaults, with the time of interest pinned to now: an absent value means
    // TimeOfInterest::disabled() in this no-std configuration, which would skip validity checking.
    let mut cps = CertificationPathSettings::default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(now).expect("valid time"));
    let (reports, lines) = validate_hackathon_zip(&path, bytes, &cps, true);
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

//! Provides the basic capabilities supported by Pittv3 in no-std contexts using TA, intermediate CA
//! and end entity certificates that are baked into the app.
//!
//! PITTv3 can built without standard library support with or without revocation support:
//! - `cargo build --release --bin pittv3 --no-default-features`
//! - `cargo build --release --bin pittv3 --no-default-features --features revocation`
//!
//! The options shown below are available with either of these builds. Note, there is no additional
//! functionality made available via PITTv3 for `--no-default-features --features revocation` vs.
//! `--no-default-features` at present. At some point, specifying files containing revocation information
//! may be added for this mode.
//!
//! ```text
//! $ ./target/release/pittv3 -h
//! pittv3 0.1.1
//! PKI Interoperability Test Tool v3 (PITTv3)
//!
//! USAGE:
//!     pittv3 [OPTIONS]
//!
//! OPTIONS:
//!     -h, --help       Print help information
//!     -V, --version    Print version information
//!
//! COMMON OPTIONS:
//!     -i, --time-of-interest <TIME_OF_INTEREST>
//!             Time to use for path validation expressed as the number of seconds since Unix epoch
//!             (defaults to current system time) [default: 0]
//!
//! VALIDATION:
//!     -v, --validate-all    Flag that indicates all available certification paths compiled into the
//!                           app should be validated for each target, instead of stopping after finding
//!                           first valid path
//! ```
#![cfg(any(not(feature = "std_app"), doc))]

use alloc::collections::BTreeMap;

use ciborium::de::from_reader;

use certval::*;

use crate::args::Pittv3Args;
use crate::no_std_utils::validate_cert;
use crate::stats::{PVStats, PathValidationStats, PathValidationStatsGroup};

/// The `options_std` function provides argument parsing and corresponding actions when `PITTv3` is built
/// with standard library support (i.e., with `std`, `revocation,std` or `remote` features).
pub fn options_no_std(args: &Pittv3Args) {
    let cps = CertificationPathSettings::default();

    let ca_cbor = include_bytes!("../resources/ca.cbor");
    let mut cert_source = CertSource::new();
    match from_reader(ca_cbor.as_slice()) {
        Ok(cbor_data) => {
            cert_source.buffers_and_paths = cbor_data;
        }
        Err(e) => {
            panic!("Failed to parse embedded CA CBOR with: {}", e)
        }
    }
    let r =
        populate_parsed_cert_vector(&cert_source.buffers_and_paths, &cps, &mut cert_source.certs);
    if let Err(e) = r {
        log_message(
            &PeLogLevels::PeError,
            format!("Failed to populate cert vector with: {:?}", e).as_str(),
        );
    }
    for (i, cert) in cert_source.certs.iter().enumerate() {
        if let Some(cert) = cert {
            let hex_skid = hex_skid_from_cert(cert);
            if cert_source.skid_map.contains_key(&hex_skid) {
                let mut v = cert_source.skid_map[&hex_skid].clone();
                v.push(i);
                cert_source.skid_map.insert(hex_skid, v);
            } else {
                cert_source.skid_map.insert(hex_skid, vec![i]);
            }

            let name_str = name_to_string(&cert.decoded_cert.tbs_certificate.subject);
            if cert_source.name_map.contains_key(&name_str) {
                let mut v = cert_source.name_map[&name_str].clone();
                v.push(i);
                cert_source.name_map.insert(name_str, v);
            } else {
                cert_source.name_map.insert(name_str, vec![i]);
            }
        }
    }

    let ta_cbor = include_bytes!("../resources/ta.cbor");
    let ta_bap: BuffersAndPaths = match from_reader(ta_cbor.as_slice()) {
        Ok(cbor_data) => cbor_data,
        Err(e) => {
            panic!("Failed to parse embedded TA CBOR with: {}", e)
        }
    };

    let mut ta_store = TaSource::new();
    ta_store.buffers = ta_bap.buffers;
    populate_parsed_ta_vector(&ta_store.buffers, &mut ta_store.tas);
    ta_store.index_tas();

    let ee_cbor = include_bytes!("../resources/ee.cbor");
    let ee_bap: BuffersAndPaths = match from_reader(ee_cbor.as_slice()) {
        Ok(cbor_data) => cbor_data,
        Err(e) => {
            panic!("Failed to parse embedded EE CBOR with: {}", e)
        }
    };

    let mut pe = PkiEnvironment::default();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(&ta_store);
    pe.add_certificate_source(&cert_source);
    pe.add_path_builder(&cert_source);

    let mut stats = PathValidationStatsGroup::new();

    for ee in ee_bap.buffers {
        stats.init_for_target(ee.filename.as_str());
        if let Some(stats_for_file) = stats.get_mut(ee.filename.as_str()) {
            validate_cert(
                &pe,
                &cps,
                ee.filename.as_str(),
                ee.bytes.as_slice(),
                stats_for_file,
                &args,
            );
        }
    }

    let mut error_indices: BTreeMap<&String, BTreeMap<PathValidationStatus, Vec<usize>>> =
        BTreeMap::new();
    let mut error_counts: BTreeMap<&String, BTreeMap<PathValidationStatus, i32>> = BTreeMap::new();
    for key in stats.keys() {
        let stats = &stats[key];
        let mut index_map: BTreeMap<PathValidationStatus, Vec<usize>> = BTreeMap::new();
        let mut count_map: BTreeMap<PathValidationStatus, i32> = BTreeMap::new();
        for (i, cpr) in stats.results.iter().enumerate() {
            if let Some(status) = get_validation_status(cpr) {
                if index_map.contains_key(&status) {
                    let mut v = index_map[&status].clone();
                    v.push(i);
                    index_map.insert(status, v);
                } else {
                    index_map.insert(status, vec![i]);
                }

                match count_map.entry(status) {
                    std::collections::btree_map::Entry::Occupied(mut e) => {
                        e.insert(e.get() + 1);
                    }
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(1);
                    }
                }
            }
        }
        error_counts.insert(key, count_map);
        error_indices.insert(key, index_map);
    }

    let mut totals = PathValidationStats::default();
    for k in stats.keys() {
        let s = &stats[k];
        log_message(&PeLogLevels::PeInfo, format!("Stats for {}", k).as_str());
        log_message(
            &PeLogLevels::PeInfo,
            format!("\t * Paths found: {}", s.paths_per_target).as_str(),
        );
        log_message(
            &PeLogLevels::PeInfo,
            format!("\t * Valid paths found: {}", s.valid_paths_per_target).as_str(),
        );
        log_message(
            &PeLogLevels::PeInfo,
            format!("\t * Invalid paths found: {}", s.invalid_paths_per_target).as_str(),
        );
        totals.paths_per_target += s.paths_per_target;
        totals.valid_paths_per_target += s.valid_paths_per_target;
        totals.invalid_paths_per_target += s.invalid_paths_per_target;

        if 0 < s.paths_per_target {
            log_message(&PeLogLevels::PeInfo, "\t * Status codes");
            let ec = &error_counts[k];
            for ekey in ec {
                log_message(
                    &PeLogLevels::PeInfo,
                    format!(
                        "\t\t - {:?}: {} - Result folder indices: {:?}",
                        ekey.0, ekey.1, &error_indices[k][ekey.0]
                    )
                    .as_str(),
                );
            }
        }
    }
    log_message(
        &PeLogLevels::PeInfo,
        format!("Total paths found: {}", totals.paths_per_target).as_str(),
    );
    log_message(
        &PeLogLevels::PeInfo,
        format!("Total valid paths found: {}", totals.valid_paths_per_target).as_str(),
    );
    log_message(
        &PeLogLevels::PeInfo,
        format!(
            "Total invalid paths found: {}",
            totals.invalid_paths_per_target
        )
        .as_str(),
    );
}

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

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use ciborium::de::from_reader;

use certval::*;
use log::{error, info};

use crate::args::Pittv3Args;
use crate::no_std_utils::validate_cert;
use crate::stats::{PVStats, PathValidationStats, PathValidationStatsGroup};

/// The `options_std` function provides argument parsing and corresponding actions when `PITTv3` is built
/// with standard library support (i.e., with `std`, `revocation,std` or `remote` features).
pub fn options_no_std(args: &Pittv3Args) {
    let cps = CertificationPathSettings::default();

    let ca_cbor = include_bytes!("../resources/ca.cbor");
    let mut cert_source = match CertSource::new_from_cbor(ca_cbor.as_slice()) {
        Ok(cbor_data) => cbor_data,
        Err(e) => {
            panic!("Failed to parse embedded CA CBOR with: {}", e)
        }
    };
    let r = cert_source.initialize(&cps);
    if let Err(e) = r {
        error!("Failed to populate cert vector with: {:?}", e);
    }

    let ta_cbor = include_bytes!("../resources/ta.cbor");
    let mut ta_store = match TaSource::new_from_cbor(ta_cbor) {
        Ok(ta_store) => ta_store,
        Err(e) => {
            panic!("Failed to parse embedded TA CBOR with: {}", e)
        }
    };
    if let Err(e) = ta_store.initialize() {
        panic!("Failed to initialize TA source with: {}", e)
    }

    let ee_cbor = include_bytes!("../resources/ee.cbor");
    let ee_bap: BuffersAndPaths = match from_reader(ee_cbor.as_slice()) {
        Ok(cbor_data) => cbor_data,
        Err(e) => {
            panic!("Failed to parse embedded EE CBOR with: {}", e)
        }
    };

    let mut pe = PkiEnvironment::default();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
    pe.add_certificate_source(Box::new(cert_source.clone()));

    let mut stats = PathValidationStatsGroup::new();

    for ee in ee_bap.buffers {
        stats.init_for_target(ee.filename.as_str());
        if let Some(stats_for_file) = stats.get_mut(ee.filename.as_str()) {
            let b = if ee.bytes[0] != 0x30 {
                match pem_rfc7468::decode_vec(&ee.bytes) {
                    Ok(b) => b.1,
                    Err(e) => {
                        error!("Failed to parse certificate from {}: {}", ee.filename, e);
                        return;
                    }
                }
            } else {
                ee.bytes
            };

            let _ = validate_cert(&pe, &cps, ee.filename.as_str(), &b, stats_for_file, &args);
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
                    alloc::collections::btree_map::Entry::Occupied(mut e) => {
                        e.insert(e.get() + 1);
                    }
                    alloc::collections::btree_map::Entry::Vacant(e) => {
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
        info!("Stats for {}", k);
        info!("\t * Paths found: {}", s.paths_per_target);
        info!("\t * Valid paths found: {}", s.valid_paths_per_target);
        info!("\t * Invalid paths found: {}", s.invalid_paths_per_target);
        totals.paths_per_target += s.paths_per_target;
        totals.valid_paths_per_target += s.valid_paths_per_target;
        totals.invalid_paths_per_target += s.invalid_paths_per_target;

        if 0 < s.paths_per_target {
            info!("\t * Status codes");
            let ec = &error_counts[k];
            for ekey in ec {
                info!(
                    "\t\t - {:?}: {} - Result folder indices: {:?}",
                    ekey.0, ekey.1, &error_indices[k][ekey.0]
                );
            }
        }
    }
    info!("Total paths found: {}", totals.paths_per_target);
    info!("Total valid paths found: {}", totals.valid_paths_per_target);
    info!(
        "Total invalid paths found: {}",
        totals.invalid_paths_per_target
    );
}

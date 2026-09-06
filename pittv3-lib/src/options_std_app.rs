//! Provides support for using PITTv3 to specify end entity certificate files relative to certval
//! library built with no-default features and baked in TA and intermediate CA CBOR files.
//!
//! PITTv3 can built with standard library support while building certval without standard library support.
//! When built this way, certval includes revocation support. At present, building PITTv3 in this
//! manner adds only the ability to specify an end entity certificate for validation and means to dump
//! results relative to the [no-std](crate::options_no_std) build options.
//! - `cargo build --release --bin pittv3 --no-default-features --features std_app`
//!
//! The options shown below are available when PITT is built this way.
//!
//! ```text
//! $ pittv3 -h
//! PKI Interoperability Test Tool v3 (PITTv3) can be used to build and validate certification paths using different sets
//! of trust anchors, intermediate CA certificates and end entity certificates.
//!
//!
//! Usage: pittv3 [OPTIONS]
//!
//! Options:
//!   -h, --help     Print help
//!   -V, --version  Print version
//!
//! COMMON OPTIONS:
//!   -i, --time-of-interest <TIME_OF_INTEREST>
//!           Time to use for path validation expressed as the number of seconds since Unix epoch (defaults to current system time) [default: 1787579866]
//!   -l, --logging-config <LOGGING_CONFIG>
//!           Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See <https://docs.rs/log4rs/latest/log4rs/> for details
//!   -o, --error-folder <ERROR_FOLDER>
//!           Full path of folder to receive binary DER-encoded certificates from paths that fail path validation. If absent, errant files are not saved for review
//!
//! VALIDATION:
//!   -v, --validate-all
//!           Flag that indicates all available certification paths should be validated for each target
//!       --validate-self-signed
//!           Check if certificate passed as end_entity_file is self-signed
//!   -e, --end-entity-file <END_ENTITY_FILE>
//!           Full path and filename of a binary DER-encoded certificate to validate
//!   -r, --results-folder <RESULTS_FOLDER>
//!           Full path and filename of folder to receive binary DER-encoded certificates from certification paths. Folders will be created beneath this using a hash of the target certificate. Within that folder, folders will be created with a number indicating each path, i.e., the number indicates the order in which the path was returned for consideration. For best results, this folder should be cleaned in between runs. PITTv3 does not perform hygiene on this folder or its contents
//! ```

#![cfg(any(all(feature = "std_app", not(feature = "std")), doc))]

use alloc::collections::BTreeMap;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use certval::*;

use crate::args::Pittv3Args;
use crate::der_or_pem::maybe_pem;
use crate::no_std_utils::validate_cert;
use crate::stats::{PVStats, PathValidationStats, PathValidationStatsGroup};

#[cfg(feature = "sha1_sig")]
use crate::sha1_sig::verify_signature_message_rust_crypto_sha1;

use log::{error, info};

/// `get_file_as_byte_vec` provides support for reading artifacts from file when PITTv3 is built using
/// the `std_app` feature.
fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    match File::open(filename) {
        Ok(mut f) => match std::fs::metadata(filename) {
            Ok(metadata) => {
                let mut buffer = vec![0; metadata.len() as usize];
                match f.read_exact(&mut buffer) {
                    Ok(_) => Ok(buffer),
                    Err(_e) => Err(Error::Unrecognized),
                }
            }
            Err(_e) => Err(Error::Unrecognized),
        },
        Err(_e) => Err(Error::Unrecognized),
    }
}

/// The `options_std_app` function provides argument parsing and corresponding actions when `PITTv3` is built
/// with standard library support but [`certval`] is not.
pub fn options_std_app(args: &Pittv3Args) {
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

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    // The graph and the paths built over it re-present the same CA signatures many times;
    // caching them is sound because a hit means this exact signature already verified under
    // this exact key.
    pe.add_signature_cache(Box::new(DefaultSignatureVerificationCache::new()));
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
    pe.add_certificate_source(Box::new(cert_source.clone()));

    #[cfg(feature = "sha1_sig")]
    pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto_sha1);

    let mut stats = PathValidationStatsGroup::new();

    // perform validation of end entity certificate file or folder. pass in fresh_uris to collect
    // URIs from any relevant trust anchors.
    if let Some(filename) = &args.end_entity_file {
        stats.init_for_target(filename);
        if let Some(stats_for_file) = stats.get_mut(filename) {
            match get_file_as_byte_vec(Path::new(filename)) {
                // maybe_pem rather than a strict decoder, as file may be DER, PEM or raw base64.
                // It also handles for an empty file, which indexing the first byte here did not.
                Ok(target) => match maybe_pem(&target) {
                    // validate when validating all or we don't have a definitive answer yet
                    Ok(b) => {
                        let _ =
                            validate_cert(&pe, &cps, filename.as_str(), &b, stats_for_file, args);
                    }
                    // Report rather than return: the stats below are the run's only output, and
                    // ending here left a target named on the command line with no result at all.
                    Err(_e) => {
                        error!(
                            "Failed to parse certificate from {filename}: the file is not DER, PEM or base64"
                        );
                    }
                },
                Err(e) => {
                    println!("Failed to read file at {} with {}", filename, e);
                }
            }
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
            if let Some(status) = cpr.get_validation_status() {
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
                    ekey.0, ekey.1, error_indices[k][ekey.0]
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

//! Provides support for using PITTv3 to specify end entity certificate files relative to certval
//! library built with no-default features and baked in TA and intermediate CA CBOR files.
//!
//! PITTv3 can built with standard library support while building certval without standard library support.
//! When built this way, certval includes revocation support. At present, building PITTv3 in this
//! manner adds only the ability to specify an end entity certificate for validation and means to dump
//! results relative to the [no-std](./options_no_std.html) build options.
//! - `cargo build --release --bin pittv3 --no-default-features --features std_app`
//!
//! The options shown below are available when PITT is built this way.
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
//!             (defaults to current system time) [default: 1648038820]
//!
//!     -l, --logging-config <LOGGING_CONFIG>
//!             Full path and filename of YAML-formatted configuration file for log4rs logging
//!             mechanism. See <https://docs.rs/log4rs/latest/log4rs/> for details
//!
//!     -o, --error-folder <ERROR_FOLDER>
//!             Full path of folder to receive binary DER-encoded certificates from paths that fail path
//!             validation. If absent, errant files are not saved for review
//!
//! VALIDATION:
//!     -e, --end-entity-file <END_ENTITY_FILE>
//!             Full path and filename of a binary DER-encoded certificate to validate
//!
//!     -r, --results-folder <RESULTS_FOLDER>
//!             Full path and filename of folder to receive binary DER-encoded certificates from
//!             certification paths. Folders will be created beneath this using a hash of the target
//!             certificate. Within that folder, folders will be created with a number indicating each
//!             path, i.e., the number indicates the order in which the path was returned for
//!             consideration. For best results, this folder should be cleaned in between runs. PITTv3
//!             does not perform hygiene on this folder or its contents
//!
//!     -v, --validate-all
//!             Flag that indicates all available certification paths should be validated for each
//!             target
//! ```

#![cfg(any(all(feature = "std_app", not(feature = "std")), doc))]

use alloc::collections::BTreeMap;

use ciborium::de::from_reader;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use certval::*;

use crate::args::Pittv3Args;
use crate::no_std_utils::validate_cert;
use crate::stats::{PVStats, PathValidationStats, PathValidationStatsGroup};

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
/// with standard library support but [`certval`](../../certval/index.html) is not.
pub fn options_std_app(args: &Pittv3Args) {
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
        error!("Failed to populate cert vector with: {:?}", e);
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

    let mut pe = PkiEnvironment::default();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
     pe.add_certificate_source(Box::new(cert_source.clone()));
     pe.add_path_builder(Box::new(cert_source.clone()));

    let mut stats = PathValidationStatsGroup::new();

    // perform validation of end entity certificate file or folder. pass in fresh_uris to collect
    // URIs from any relevant trust anchors.
    if let Some(filename) = &args.end_entity_file {
        stats.init_for_target(filename);
        if let Some(stats_for_file) = stats.get_mut(filename) {
            match get_file_as_byte_vec(Path::new(filename)) {
                Ok(target) => {
                    let b = if target[0] != 0x30 {
                        match pem_rfc7468::decode_vec(&target) {
                            Ok(b) => b.1,
                            Err(e) => {
                                error!("Failed to parse certificate from {}: {}", filename, e);
                                return;
                            }
                        }
                    } else {
                        target
                    };

                    // validate when validating all or we don't have a definitive answer yet
                    validate_cert(&pe, &cps, filename.as_str(), &b, stats_for_file, args);
                }
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

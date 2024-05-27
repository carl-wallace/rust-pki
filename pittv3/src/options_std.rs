//! Provides the highest level capabilities supported by Pittv3 and is used relative to the std,
//! revocation,std and remote features.
//!
//! PITTv3 can built without standard library support with or without revocation support:
//! - `cargo build --release --bin pittv3 --no-default-features --features std`
//! - `cargo build --release --bin pittv3 --no-default-features --features revocation,std`
//! - `cargo build --release --bin pittv3`
//!
//! The default build is the same as `--no-default-features --features remote`.
//!
//! The options shown below are available when remote support is not available:
//!
//! ```text
//! $ ./target/release/pittv3
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
//!     -b, --cbor <CBOR>
//!             Full path and filename of file to provide and/or receive CBOR-formatted representation
//!             of buffers containing binary DER-encoded CA certificates and map containing set of
//!             partial certification paths
//!
//!     -c, --ca-folder <CA_FOLDER>
//!             Full path of folder containing binary, DER-encoded intermediate CA certificates.
//!             Required when generate action is performed. This is not used when path validation is
//!             performed other than as a place to store downloaded files when dynamic building is used
//!             and download_folder is not specified
//!
//!     -d, --download-folder <DOWNLOAD_FOLDER>
//!             Full path and filename of folder to receive downloaded binary DER-encoded certificates,
//!             if absent at generate time, the ca_folder is used. Additionally, this is used to
//!             designate where exported buffers are written by dump_cert_at_index or list_buffers
//!
//!     -i, --time-of-interest <TIME_OF_INTEREST>
//!             Time to use for path validation expressed as the number of seconds since Unix epoch
//!             (defaults to current system time) [default: 1648039783]
//!
//!     -l, --logging-config <LOGGING_CONFIG>
//!             Full path and filename of YAML-formatted configuration file for log4rs logging
//!             mechanism. See <https://docs.rs/log4rs/latest/log4rs/> for details
//!
//!     -o, --error-folder <ERROR_FOLDER>
//!             Full path of folder to receive binary DER-encoded certificates from paths that fail path
//!             validation. If absent, errant files are not saved for review
//!
//!     -t, --ta-folder <TA_FOLDER>
//!             Full path of folder containing binary DER-encoded trust anchors to use when generating
//!             CBOR file containing partial certification paths and when validating certification paths
//!
//! GENERATION:
//!         --cbor-ta-store    Flag that indicates generated CBOR file will contain only trust anchors
//!                            (so no need for partial paths and no need to exclude self-signed
//!                            certificates)
//!     -g, --generate         Flag that indicates a fresh CBOR-formatted file containing buffers of CA
//!                            certificates and map containing set of partial certification paths should
//!                            be generated and saved to location indicated by cbor parameter
//!
//! VALIDATION:
//!         --crl-folder <CRL_FOLDER>
//!             Full path of folder containing binary, DER-encoded intermediate CA certificates.
//!             Required when generate action is performed. This is not used when path validation is
//!             performed other than as a place to store downloaded files when dynamic building is used
//!             and download_folder is not specified
//!
//!     -e, --end-entity-file <END_ENTITY_FILE>
//!             Full path and filename of a binary DER-encoded certificate to validate
//!
//!     -f, --end-entity-folder <END_ENTITY_FOLDER>
//!             Full path folder to recursively traverse for binary DER-encoded certificates to
//!            validate. Only files with .der, .crt or cert as file extension are processed
//!
//!     -r, --results-folder <RESULTS_FOLDER>
//!             Full path and filename of folder to receive binary DER-encoded certificates from
//!             certification paths. Folders will be created beneath this using a hash of the target
//!             certificate. Within that folder, folders will be created with a number indicating each
//!             path, i.e., the number indicates the order in which the path was returned for
//!             consideration. For best results, this folder should be cleaned in between runs. PITTv3
//!             does not perform hygiene on this folder or its contents
//!
//!     -s, --settings <SETTINGS>
//!             Full path and filename of JSON-formatted certification path validation settings
//!
//!     -v, --validate-all
//!             Flag that indicates all available certification paths should be validated for each
//!             target
//!
//! CLEANUP:
//!         --cleanup        Paired with ca_folder to remove expired, unparseable certificates, self-
//!                          signed certificates and non-CA certificates from consideration. When paired
//!                          with error_folder, the errant files are moved instead of deleted. After
//!                          cleanup completes, the application exits with no other parameters acted
//!                          upon
//!         --report-only    Pair with cleanup to generate list of files that would be cleaned up by
//!                          cleanup operation without actually deleting or moving files
//!         --ta-cleanup     Paired with ta_folder to remove expired or unparseable certificatesfrom
//!                          consideration. When paired with error_folder, the errant files are moved
//!                          instead of deleted. After cleanup completes, the application exits with no
//!                          other parameters acted upon
//!
//! DIAGNOSTICS:
//!         --dump-cert-at-index <DUMP_CERT_AT_INDEX>
//!             Outputs the certificate at the specified index to a file names <index>.der in the
//!             download_folder if specified, else current working directory
//!
//!         --list-aia-and-sia
//!             Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file.
//!             Add downloads_folder to save certificates that are valid as of time_of_interest from the
//!             downloaded artifacts (use time_of_interest=0 to download all). Specify a blocklist or
//!             last_modified_map if desired via CertificationPathSettings or rely on default files that
//!            will be generated and managed in folder used to download artifacts
//!
//!         --list-buffers
//!             Outputs all buffers present in CBOR file
//!
//!         --list-name-constraints
//!             Outputs all name constraints found in certificates present in CBOR file
//!
//!         --list-partial-paths
//!             Outputs all partial paths present in CBOR file. If a ta_folder is provided, the CBOR
//!             file will be re-evaluated using ta_folder and time_of_interest (possibly changing the
//!             set of partial paths relative to that read from CBOR). Use of a logging-config option is
//!             recommended for large CBOR files
//!
//!         --list-trust-anchors
//!             Outputs all buffers present in trust anchors folder
//!
//!     -p, --list-partial-paths-for-leaf-ca <LIST_PARTIAL_PATHS_FOR_LEAF_CA>
//!             Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If a
//!             ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
//!             time_of_interest (possibly changing the set of partial paths relative to that read from
//!             CBOR)
//!
//!     -z, --list-partial-paths-for-target <LIST_PARTIAL_PATHS_FOR_TARGET>
//!             Outputs all partial paths present in CBOR file relative to the indicated target. If a
//!             ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
//!             time_of_interest (possibly changing the set of partial paths relative to that read from
//!             CBOR)
//!
//! TOOLS:
//!         --mozilla-csv <MOZILLA_CSV>    Parses the given CSV file and saves files to folder indicated
//!                                        by the ca_folder parameter. The CSV file is assumed to be as
//!                                        posted as the "Non-revoked, non-expired Intermediate CA
//!                                        Certificates chaining up to roots in Mozilla's program with
//!                                        the Websites trust bit set (CSV with PEM of raw certificate
//!                                        data)" report available on the Mozilla wiki page at
//!                                        <https://wiki.mozilla.org/CA/Intermediate_Certificates>
//! ```
//!
//! Options with remote support are the same as above with the two additions to the indicated shown below:
//!
//! ```text
//! GENERATION:
//!     -a, --chase-aia-and-sia    Flag that indicates whether AIA and SIA URIs should be consulted when
//!                                performing generate action
//! VALIDATION:
//!     -y, --dynamic-build
//!             Process AIA and SIA during path validation, as appropriate. Either ca_folder or
//!             download_folder must be specified when using this flag to provide a place to store
//!             downloaded artifacts
//! ```

#![cfg(feature = "std")]

extern crate alloc;

// let the compiler choose what to pull in based on feature
use certval::*;

use alloc::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

use log::{debug, error, info};

use crate::args::Pittv3Args;
use crate::stats::{PVStats, PathValidationStats, PathValidationStatsGroup};
use crate::std_utils::*;

/// The `options_std` function provides argument parsing and corresponding actions when `PITTv3` and
/// `certval` are built with standard library support (i.e., with `std`, `revocation,std` or `remote` features).
pub async fn options_std(args: &Pittv3Args) {
    if args.cleanup {
        // Cleanup runs in isolation before other actions
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        cleanup(&pe, args);
    }

    if args.ta_cleanup {
        // TA cleanup runs in isolation before other actions
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        ta_cleanup(&pe, args);
    }

    #[cfg(feature = "std")]
    if args.list_trust_anchors {
        let pe = PkiEnvironment::default();

        // Load up the trust anchors. This occurs once and is not effected by the dynamic_build flag.
        if let Some(ta_folder) = &args.ta_folder {
            let mut ta_store = TaSource::new();
            let r = ta_folder_to_vec(&pe, ta_folder, &mut ta_store, args.time_of_interest);
            if let Err(e) = r {
                println!(
                    "Failed to load trust anchors from {} with error {:?}",
                    ta_folder, e
                );
                return;
            }

            if let Err(e) = ta_store.initialize() {
                println!(
                    "Failed to initialize trust anchor source from {} with error {:?}",
                    ta_folder, e
                );
                return;
            }

            ta_store.log_tas();
        }

        #[cfg(feature = "webpki")]
        if args.webpki_tas {
            match TaSource::new_from_webpki() {
                Ok(mut ta_store) => {
                    if let Err(e) = ta_store.initialize() {
                        println!(
                            "Failed to initialize trust anchor source from webpki-roots with error {:?}",
                            e
                        );
                        return;
                    }

                    ta_store.log_tas();
                }
                Err(e) => {
                    println!(
                        "Failed to create trust anchor source from webpki-roots with error {:?}",
                        e
                    );
                    return;
                }
            }
        }
    }

    #[cfg(feature = "std")]
    if args.list_partial_paths
        || args.list_buffers
        || args.list_partial_paths_for_target.is_some()
        || args.list_partial_paths_for_leaf_ca.is_some()
        || args.dump_cert_at_index.is_some()
        || args.list_aia_and_sia
        || args.list_name_constraints
    {
        let cbor_file: &String = if let Some(cbor) = &args.cbor {
            cbor
        } else {
            panic!("cbor argument must be provided when using a diagnostic command")
        };

        let download_folder = if let Some(download_folder) = &args.download_folder {
            download_folder.clone()
        } else {
            "./".to_string()
        };

        let mut cps = CertificationPathSettings::new();
        cps.set_time_of_interest(args.time_of_interest);

        let mut pe = PkiEnvironment::default();

        let cbor = read_cbor(&args.cbor);
        if cbor.is_empty() {
            println!(
                "Failed to read CBOR data from file located at {}",
                cbor_file
            );
            return;
        }

        let mut cert_source = match CertSource::new_from_cbor(cbor.as_slice()) {
            Ok(cbor_data) => cbor_data,
            Err(e) => {
                panic!("Failed to parse CBOR file at {} with: {}", cbor_file, e)
            }
        };
        let r = cert_source.initialize(&cps);
        if let Err(e) = r {
            error!("Failed to populate cert vector with: {:?}", e);
        }

        pe.populate_5280_pki_environment();

        #[cfg(feature = "webpki")]
        if args.webpki_tas {
            // the TAs read from webpki-roots do not assert a validity do turn off this check
            cps.set_enforce_trust_anchor_validity(false);

            match TaSource::new_from_webpki() {
                Ok(ta_store) => {
                    pe.add_trust_anchor_source(Box::new(ta_store));
                }
                Err(e) => {
                    error!(
                        "Failed to initialize TA store from webpki-roots: {:?}. Continuing...",
                        e
                    );
                }
            };
        }

        let mut ta_store = TaSource::new();

        if let Some(ta_folder) = &args.ta_folder {
            let r = ta_folder_to_vec(&pe, ta_folder, &mut ta_store, args.time_of_interest);
            if let Err(e) = r {
                println!(
                    "Failed to load trust anchors from {} with error {:?}",
                    ta_folder, e
                );
                return;
            }
            if let Err(e) = ta_store.initialize() {
                println!(
                    "Failed to initialize trust anchor source from {} with error {:?}",
                    ta_folder, e
                );
                return;
            }

            pe.add_trust_anchor_source(Box::new(ta_store));
            cert_source.clear_paths();
            cert_source.find_all_partial_paths(&pe, &cps);
        }
        #[cfg(feature = "webpki")]
        if args.webpki_tas && args.ta_folder.is_none() {
            cert_source.clear_paths();
            cert_source.find_all_partial_paths(&pe, &cps);
        }

        if let Some(index) = args.dump_cert_at_index {
            if index >= cert_source.num_certs() {
                println!(
                    "Requested index does not exist. Try again with an index value less than {}",
                    cert_source.num_certs()
                );
                return;
            }
            let c = &cert_source.get_cert_at_index(index);
            if let Some(cert) = c {
                let p = Path::new(&download_folder);
                let fname = format!("{}.der", index);
                let f = p.join(fname);
                fs::write(f, cert.encoded_cert.as_slice())
                    .expect("Unable to write certificate file");
            } else {
                println!("Requested index does not exist, possibly due to a parsing or validity check error when deserializing the CBOR file");
                return;
            }
        }

        #[cfg(feature = "std")]
        if args.list_aia_and_sia {
            let mut fresh_uris = vec![];
            cert_source.log_all_aia_and_sia(&mut fresh_uris);

            #[cfg(feature = "remote")]
            {
                let p = Path::new(&download_folder);
                let blp = p.join("last_modified_map.json");
                let lmm_file = if let Some(bl) = blp.to_str() { bl } else { "" };

                let blp = p.join("blocklist.json");
                let blocklist_file = if let Some(bl) = blp.to_str() { bl } else { "" };

                if let Some(download_folder) = &args.download_folder {
                    //let mut buffers: Vec<CertFile> = vec![];

                    let mut blocklist = read_blocklist(blocklist_file);
                    let mut lmm = read_last_modified_map(lmm_file);

                    let r = fetch_to_buffer(
                        &pe,
                        &fresh_uris,
                        download_folder,
                        &mut CertSource::default(),
                        0,
                        &mut lmm,
                        &mut blocklist,
                        args.time_of_interest,
                    )
                    .await;
                    if let Err(e) = r {
                        error!("Encountered error downloading URIs: {}", e);
                    }
                    let json_lmm = serde_json::to_string(&lmm);
                    if !lmm_file.is_empty() {
                        if let Ok(json_lmm) = &json_lmm {
                            fs::write(lmm_file, json_lmm)
                                .expect("Unable to write last modified map file");
                        }
                    }

                    let json_blocklist = serde_json::to_string(&blocklist);
                    if !blocklist_file.is_empty() {
                        if let Ok(json_blocklist) = &json_blocklist {
                            fs::write(blocklist_file, json_blocklist)
                                .expect("Unable to write blocklist file");
                        }
                    }
                }
            }
        }

        if args.list_name_constraints {
            cert_source.log_all_name_constraints();
        }

        if args.list_buffers {
            cert_source.log_certs();

            if let Some(download_folder) = &args.download_folder {
                let buffers = cert_source.get_buffers();
                for (i, buffer) in buffers.iter().enumerate() {
                    let p = Path::new(download_folder);
                    let fname = format!("{}.der", i);
                    let pbuf = p.join(fname);
                    if let Err(e) = fs::write(pbuf, &buffer.bytes) {
                        error!("Failed to write certificate #{} to file: {}", i, e);
                    }
                }
            }
        }
        if args.list_partial_paths {
            cert_source.log_partial_paths();
        }
        if let Some(cert_filename) = &args.list_partial_paths_for_target {
            let target = if let Ok(t) = get_file_as_byte_vec_pem(Path::new(&cert_filename)) {
                t
            } else {
                error!("Failed to read file at {}", cert_filename);
                return;
            };

            let parsed_cert = parse_cert(target.as_slice(), cert_filename.as_str());
            if let Ok(target_cert) = parsed_cert {
                cert_source.log_paths_for_target(&target_cert, args.time_of_interest);
            }
        }
        if let Some(leaf_ca_index) = args.list_partial_paths_for_leaf_ca {
            if leaf_ca_index >= cert_source.num_certs() {
                println!(
                    "Requested index does not exist. Try again with an index value less than {}",
                    cert_source.num_certs()
                );
                return;
            }
            let c = &cert_source.get_cert_at_index(leaf_ca_index);
            if let Some(leaf_ca_cert) = c {
                cert_source.log_paths_for_leaf_ca(leaf_ca_cert);
            } else {
                println!("Requested index does not exist, possibly due to a parsing or validity check error when deserializing the CBOR file");
            }
        }
    } else if let Some(mozilla_csv) = &args.mozilla_csv {
        let ca_folder = if let Some(ca_folder) = &args.ca_folder {
            ca_folder.clone()
        } else {
            panic!("The ca-folder option is required when parsing a Mozilla CSV file (to receive the certificate files)");
        };

        use csv::ReaderBuilder;
        use der::pem;
        use der::Decode;
        use x509_cert::Certificate;

        match get_file_as_byte_vec(Path::new(mozilla_csv)) {
            Ok(data) => {
                let mut rdr = ReaderBuilder::new()
                    .delimiter(b',')
                    .from_reader(data.as_slice());
                for (i, result) in rdr.records().enumerate() {
                    if let Ok(record) = result {
                        if let Some(s) = record.get(4) {
                            match pem::decode_vec(s.as_bytes()) {
                                Ok((label, der_bytes)) => {
                                    if label == "CERTIFICATE" {
                                        match Certificate::from_der(&der_bytes) {
                                            Ok(_) => {
                                                let path = Path::new(&ca_folder)
                                                    .join(format!("{}.der", i));
                                                if fs::write(path, der_bytes).is_err() {
                                                    println!(
                                                        "Failed to write certificate from row {}",
                                                        i
                                                    );
                                                }
                                            }
                                            Err(_e) => {}
                                        }
                                    }
                                }
                                Err(_e) => {}
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to read data from Mozilla CSV file with {}", e);
            }
        }
    } else if args.validate_self_signed {
        if let Some(eff) = &args.end_entity_file {
            if let Ok(t) = get_file_as_byte_vec_pem(Path::new(&eff)) {
                let parsed_cert = parse_cert(t.as_slice(), eff.as_str());
                if let Ok(target_cert) = parsed_cert {
                    let mut pe = PkiEnvironment::default();
                    pe.populate_5280_pki_environment();
                    if is_self_signed(&pe, &target_cert) {
                        println!("{} is self-signed", eff);
                    } else {
                        println!("{} is not self-signed", eff);
                    }
                } else {
                    // try base 64
                    if let Ok(encoded) = pem_rfc7468::decode_vec(t.as_slice()) {
                        let parsed_cert = parse_cert(&encoded.1, eff.as_str());
                        if let Ok(target_cert) = parsed_cert {
                            let mut pe = PkiEnvironment::default();
                            pe.populate_5280_pki_environment();
                            if is_self_signed(&pe, &target_cert) {
                                println!("{} is self-signed", eff);
                            } else {
                                println!("{} is not self-signed", eff);
                            }
                        }
                    }
                }
            };
        };
    } else {
        // Generate, validate certificate file, or validate certificates folder per args.
        generate_and_validate(args).await;
    }
}

/// generate_and_validate takes a [`TaSource`](../certval/ta_source/index.html) and program arguments and performs CBOR file generation
/// and/or validation of certificate(s) indicated by the end-entity-file option and/or end-entity-folder option.
///
/// If the `generate` option is present, a fresh CBOR file is generated using materials from
/// locations indicated by `ta-folder` and `ca-folder` options. These locations may be augmented if
/// chase-aia-and-sia is enabled and either `download-folder` or `ca-folder` is specified. Download actions
/// will be governed by the `last-modified-map` option and/or `blocklist` option.
///
/// If `end-entity-file` or `end-entity-folder` options are present, path building and validation actions
/// are performed for any .der, .cer, or .crt files indicated by the end entity options. Folders are
/// recursively processed. If `dynamic-build` is present, remote sources will be consulted as necessary,
/// i.e., if a path can be validated without using remote resources and `validate-all` is not specified then
/// dynamic building is not performed. Where `validate-all` is present, all possible paths (as limited
/// by `dynamic-build`, `last-modified-map` and `blocklist`) will be validated.
///
/// This function demonstrates deserializing a set of buffers and partial paths, attempting validation
/// then downloading fresh artifacts, updating the buffers and partial paths and trying again until no
/// further options are available.
#[cfg(feature = "std")]
async fn generate_and_validate(args: &Pittv3Args) {
    // The CBOR file is required (but can be an empty file if doing dynamic building only)
    let cbor_file = if let Some(cbor) = &args.cbor {
        cbor
    } else {
        ""
    };

    #[cfg(feature = "remote")]
    let ca_folder = if let Some(ca_folder) = &args.ca_folder {
        ca_folder
    } else {
        ""
    };

    #[cfg(feature = "remote")]
    let download_folder = if let Some(download_folder) = &args.download_folder {
        download_folder
    } else {
        ca_folder
    };

    #[cfg(feature = "remote")]
    if args.dynamic_build && download_folder.is_empty() {
        panic!(
            "Either ca_folder or download_folder must be specified when dynamic_build is specified"
        )
    }

    let mut cps = match read_settings(&args.settings) {
        Ok(cps) => cps,
        Err(e) => {
            panic!("Failed to parse settings file: {:?}", e)
        }
    };

    if !cps.0.contains_key(PS_TIME_OF_INTEREST) {
        cps.set_time_of_interest(args.time_of_interest);
    }

    #[cfg(feature = "remote")]
    if !args.dynamic_build {
        cps.set_retrieve_from_aia_sia_http(false);
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut ta_store_added = false;
    #[cfg(feature = "webpki")]
    if args.webpki_tas {
        // the TAs read from webpki-roots do not assert a validity do turn off this check
        cps.set_enforce_trust_anchor_validity(false);

        match TaSource::new_from_webpki() {
            Ok(ta_store) => {
                pe.add_trust_anchor_source(Box::new(ta_store));
                ta_store_added = true;
            }
            Err(e) => {
                error!(
                    "Failed to initialize TA store from webpki-roots: {:?}. Continuing...",
                    e
                );
            }
        };
    }

    // Load up the trust anchors. This occurs once and is not effected by the dynamic_build flag.
    if let Some(ta_folder) = &args.ta_folder {
        let mut ta_store = TaSource::new();
        let r = ta_folder_to_vec(&pe, ta_folder, &mut ta_store, args.time_of_interest);
        if let Err(e) = r {
            println!(
                "Failed to load trust anchors from {} with error {:?}",
                ta_folder, e
            );
            return;
        }
        if let Err(e) = ta_store.initialize() {
            println!(
                "Failed to initialize trust anchor source from {} with error {:?}",
                ta_folder, e
            );
            return;
        }
        pe.add_trust_anchor_source(Box::new(ta_store));
        ta_store_added = true;
    }

    // Generate can be paired with validation to ensure the CBOR file used during validation is current
    if args.generate {
        generate(args, &mut cps, &mut pe).await;
    }

    // if there's nothing to validate, there is nothing further to do
    if args.end_entity_folder.is_none() && args.end_entity_file.is_none() {
        return;
    }

    if !ta_store_added {
        #[cfg(feature = "webpki")]
        error!("Either the ta_folder argument or webpki argument must be provided");

        #[cfg(not(feature = "webpki"))]
        error!("The ta_folder argument argument must be provided");
        return;
    };

    // The pass value governs two actions during the loop. AIA/SIA fetch operations are only
    // performed on second and subsequent loops. The threshold for evaluating partial paths is set
    // to zero on first pass only (for subsequent it is the length of buffers vector before
    // augmenting with AIA/SIA).
    let mut pass: u8 = 0;

    // Read CBOR from a file only once. It will be generated following AIA/SIA fetch while looping
    // in support of dynamic path building.
    let mut cbor = read_cbor(&args.cbor);

    // define a vector to receive URIs scraped from AIA and SIA extensions.
    let mut fresh_uris: Vec<String> = vec![];

    // Define index into fresh_uris that serves as starting point when performing fetch operation.
    // During dynamic building, the loop terminates when the number of fresh URIs observed does not
    // change from one iteration to the next (or when number of passes exceeds max number of
    // intermediate CA certs that may appear in a path).
    let mut uri_threshold = 0;

    let mut stats = PathValidationStatsGroup::new();

    // Start the clock for entire set of validation actions
    let start = Instant::now();

    #[cfg(all(feature = "std", feature = "revocation"))]
    let crl_source = match &args.crl_folder {
        Some(crl_folder) => {
            let mut crl_source = CrlSourceFolders::new(crl_folder);
            match crl_source.index_crls(cps.get_time_of_interest()) {
                Ok(_) => Some(crl_source),
                Err(e) => {
                    error!("Failed to index CRL source with {}", e);
                    None
                }
            }
        }
        _ => None,
    };

    #[cfg(all(feature = "std", feature = "revocation"))]
    let remote_status = args
        .crl_folder
        .as_ref()
        .map(|crl_folder| RemoteStatus::new(crl_folder));

    #[cfg(all(feature = "std", feature = "revocation"))]
    if let Some(crl_source) = &crl_source {
        pe.add_crl_source(Box::new(crl_source.clone()));
    }
    #[cfg(all(feature = "std", feature = "revocation"))]
    if let Some(remote_status) = &remote_status {
        pe.add_check_remote(Box::new(remote_status.clone()));
    }
    #[cfg(all(feature = "std", feature = "revocation"))]
    pe.add_revocation_cache(Box::new(RevocationCache::new()));
    loop {
        // Create a new CertSource and (re-)deserialize on every iteration due references to
        // buffers in the certs member. On the first pass, cbor will contain data read from file,
        // on subsequent passes it will contain a fresh CBOR blob that features buffers downloaded
        // from AIA or SIA locations.
        let mut cert_source = if cbor.is_empty() {
            // Empty CBOR is fine when doing dynamic building or when validating certificates
            // issued by a trust anchor
            if 0 == pass {
                info!("Empty CBOR file at {}. Proceeding without it.", cbor_file);
            }
            CertSource::default()

            // Not harvesting URIs and doing dynamic on first pass on off chance the end entity
            // was issued by a trust anchor. It may be better to harvest here and save a loop.
        } else {
            // we want to use the buffers as augmented by last round but want to start from scratch
            // on the partial paths.
            match CertSource::new_from_cbor(cbor.as_slice()) {
                Ok(cbor_data) => cbor_data,
                Err(e) => {
                    error!(
                        "Failed to parse CBOR file at {} with: {}. Proceeding without it.",
                        cbor_file, e
                    );
                    CertSource::default()
                }
            }
        };

        // We don't want to return previously returned paths on subsequent passes through the loop.
        // Since buffers from AIA/SIA are appended to the cert_source.buffers_and_paths.buffers
        // vector, set a threshold to limit paths returned to the caller when building paths. On
        // first pass, use zero so all paths are available. On subsequent passes, only use paths
        // with at least one index above the length of the buffers vector prior to augmentation.
        let threshold = if 0 == pass { 0 } else { cert_source.len() };

        // Don't do AIA and SIA chasing on first pass (fresh_uris and uri_threshold will be
        // zero). On subsequent passes, if the number of URIs did not change, then we have
        // nothing else to try and can exit the loop.
        if uri_threshold != fresh_uris.len() {
            #[cfg(feature = "remote")]
            if args.dynamic_build {
                let p = Path::new(&download_folder);
                let blp = p.join("last_modified_map.json");
                let lmm_file = if let Some(bl) = blp.to_str() { bl } else { "" };

                let blp = p.join("blocklist.json");
                let blocklist_file = if let Some(bl) = blp.to_str() { bl } else { "" };

                // read the last modified map and blocklist once
                let mut lmm = read_last_modified_map(lmm_file);
                let mut blocklist = read_blocklist(blocklist_file);

                //let bap_ref = &mut cert_source.buffers_and_paths.buffers;
                if 1 == pass {
                    // on first dynamic action, pick up certs from downloads folder
                    if cert_folder_to_vec(
                        &pe,
                        download_folder,
                        &mut cert_source,
                        args.time_of_interest,
                    )
                    .is_err()
                    {
                        debug!("Encountered error reading certificates from downloads folder");
                    }
                }

                // this could likely return after fetching one URI, but once we're in the dynamic
                // building soup, we might as well fetch all.
                let r = fetch_to_buffer(
                    &pe,
                    &fresh_uris,
                    download_folder,
                    &mut cert_source,
                    if uri_threshold == 0 {
                        0
                    } else {
                        uri_threshold - 1
                    },
                    &mut lmm,
                    &mut blocklist,
                    args.time_of_interest,
                )
                .await;

                let json_lmm = serde_json::to_string(&lmm);
                if !lmm_file.is_empty() {
                    if let Ok(json_lmm) = &json_lmm {
                        if fs::write(lmm_file, json_lmm).is_err() {
                            error!("Unable to write last modified map file",);
                        }
                    }
                }

                let json_blocklist = serde_json::to_string(&blocklist);
                if !blocklist_file.is_empty() {
                    if let Ok(json_blocklist) = &json_blocklist {
                        if fs::write(blocklist_file, json_blocklist).is_err() {
                            error!("Unable to write blocklist file");
                        }
                    }
                }
                if let Err(e) = r {
                    error!("Failed to fetch fresh URIs with {:?}", e);
                    break;
                }
            } else if 0 < pass {
                break;
            }

            // Save the URI count before doing any validation, which will harvest new URIs
            uri_threshold = fresh_uris.len();
        }

        //TODO refactor to make TaSource.tas and CertSource.certs RefCells with on demand parsing
        //instead of holding all certs parsed all the time?
        let r = cert_source.initialize(&cps);
        if let Err(e) = r {
            error!("Failed to populate cert map: {}", e);
            break;
        }

        // If this is not the first pass, find all partial paths present in buffers_and_paths. If
        // this is the first pass, we expect this to have been present in the deserialized CBOR.
        if 0 < pass {
            cert_source.find_all_partial_paths(&pe, &cps);

            // After finding all partial paths, serialize as CBOR and save for next pass
            match cert_source.serialize(CertificationPathBuilderFormats::Cbor) {
                Ok(new_cbor) => {
                    cbor = new_cbor;
                }
                Err(e) => error!(
                    "Failed to serialize CBOR after dynamic building with {:?}",
                    e
                ),
            }

            #[cfg(feature = "remote")]
            if args.dynamic_build {
                // Iterate over freshly added certs and collect up URIs from AIA and SIA
                for i in threshold..cert_source.num_certs() {
                    if let Some(c) = &cert_source.get_cert_at_index(i) {
                        collect_uris_from_aia_and_sia(c, &mut fresh_uris);
                    }
                }
            }
        }

        // add the CertSource instance to the PkiEnvironment as both a source of certificates and
        // as a path builder
        pe.add_certificate_source(Box::new(cert_source.clone()));

        // perform validation of end entity certificate file or folder. pass in fresh_uris to collect
        // URIs from any relevant trust anchors.
        if let Some(filename) = &args.end_entity_file {
            stats.init_for_target(filename);
            if let Some(stats_for_file) = stats.get_mut(filename) {
                if args.validate_all
                    || (stats_for_file.valid_paths_per_target == 0
                        && !stats_for_file.target_is_revoked)
                {
                    // validate when validating all or we don't have a definitive answer yet
                    let _ = validate_cert_file(
                        &mut pe,
                        &cps,
                        filename.as_str(),
                        stats_for_file,
                        args,
                        &mut fresh_uris,
                        threshold,
                    )
                    .await;
                }
            }
        }

        if let Some(folder) = &args.end_entity_folder {
            validate_cert_folder(
                &mut pe,
                &cps,
                folder.as_str(),
                &mut stats,
                args,
                &mut fresh_uris,
                threshold,
            )
            .await;
        }

        pe.clear_certificate_sources();

        #[cfg(feature = "remote")]
        if !args.dynamic_build {
            break;
        }

        if !args.validate_all {
            let mut all_definitive = true;
            for k in stats.keys() {
                let s = &stats[k];
                // revocation is not supported at present, but revocation would be a definitive answer
                if s.valid_paths_per_target == 0 && !s.target_is_revoked {
                    // we did not find a path and target is not revoked, so validate_all should be in effect
                    all_definitive = false;
                }
            }
            if all_definitive {
                break;
            }
        }

        // Subtract two for target and TA
        if pass >= (PS_MAX_PATH_LENGTH_CONSTRAINT - 2) {
            break;
        } else {
            pass += 1;
        }
    } // end loop

    let finish = Instant::now();
    let duration = finish - start;

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

    debug!("Args: {:?}", args);

    info!(
        "{:?} to deserialize graph and perform build and validation operation(s) for {} file(s)",
        duration,
        stats.keys().len()
    );
}

//! PKI Interoperability Test Tool v3 (PITTv3) can be used to build and validate certification paths
//! using different sets of trust anchors, intermediate CA certificates and end entity certificates.
//! It also serves a sample app for using the certval and related RustCrypto formats libraries.
//!
//! ## Using PITTv3
//!
//! **1) Serialize a set intermediate CA certificates and partial certification paths**
//!
//! PITTv3 works best when using a set of intermediate CA certificates and partial certification
//! paths that have been serialized to a CBOR file. To generate a CBOR file for a given PKI:
//! - prepare a set of trust anchor certificates in a folder
//! - prepare a set of CA certificates in a folder,
//! - use the `generate` option, as shown below.
//!
//! The `chase-aia-and-sia` can be included to download additional certificates. The downloaded
//! artifacts may be directed to a location specified by the `download-folder` option for later
//! review or to the `ca-folder` for inclusion in CBOR file.
//!```
//! pittv3 --cbor example.cbor --ca-folder path/to/ca_folder --ta-folder path/to/ta_folder --generate
//!```
//! If intermediate certificates are not available but one or more end entity certificates are
//! available, the `validate-all` and `dynamic-build` options ca be used with the `ta-folder` and
//! `download-folder` options to download available intermediate CA certificates relevant to the
//! validation of the end entity certificate(s) using URIs read from AIA and SIA extensions. The
//! `last-modified-map` and `blocklist` can be used to improve performance of AIA and SIA retrieval
//! operations during generation or during dynamic certification path building.
//!```
//! pittv3 -t path/to/ta_folder -e path/to/ee/certificate -d path/to/download/folder -v -y
//!```
//! The `generate` command can then be used to prepare a CBOR file for use in validating end entity
//! certificates or analyzing certification paths within the PKI.
//!
//! **2) Build and validate certification paths**
//!
//! To validate certificates using a CBOR file, use the cbor option in tandem with the `ta-folder` option
//! and either the `end-entity-file` or `end-entity-folder` options. The `validate-all` option can be added
//! to validate all available possible paths. Validation results can be saved by specifying a folder
//! to receive the results using the `results-folder` option.
//!```
//! pittv3 -b example.cbor -t path/to/ta_folder -e path/to/ee/certificate.der
//!```
//! The `dynamic-build` and `download-folder` options can be added to dynamically develop certification paths for validation by
//! downloading certificates from location specified in AIA or SIA extensions. Download operations
//! can be influenced by the `last-modified-map` and `blocklist` options. Generation and validation
//! operations use the `time-of-interest` option to determine if certificates are expired or not yet
//! valid. By default, the current time is used. An alternative time of interest can be specified
//! by passing the number of seconds since the Unix epoch via the `time-of-interest` option.
//!
//! **3) Analyze a given PKI**
//!
//! Several diagnostic tools are provided. Of these, `list-partial-paths-for-target` and
//! `list-partial-paths-for-leaf-ca` options are likely the most useful. These return a list of
//! partial certifications paths and list of associated certificates given a target certificate or
//! leaf CA index. The `cbor` and `ta-folder` options are required for most diagnostic tools. As
//! with validation operations, the `time-of-interest` option can be used to vary the partial paths
//! returned for a target by ignoring involid certificates.
//!
//! ```
//! pittv3 -cbor example.cbor --list-partial-paths-for-target path/to/ee/certificate.der
//! ```
//!
//! **4) Logging**
//!
//! PITTv3 generates a large volume of logging output to aid in troubleshooting or analysis efforts.
//! The `logging-config` option can be used to specify a YAML file that follows the [`log4-rs`](https://docs.rs/log4rs/latest/log4rs/)
//! configuration practices. When no logging configuration is specified output generated at the Info
//! level and higher is directed ot stdout.

mod pitt_file_utils;
mod pitt_uri_utils;
mod pitt_utils;

use pitt_file_utils::*;
use pitt_utils::*;

use certval::cert_source::*;
use certval::pdv_utilities::collect_uris_from_aia_and_sia;
use certval::ta_source::*;
use certval::*;
use ciborium::de::from_reader;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Instant;

use std::env;
use std::fs;

use crate::pitt_uri_utils::fetch_to_buffer;
use clap::IntoApp;
use clap::Parser;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::path::Path;
use x509::PKIX_KP_SERVERAUTH;

/// PKI Interoperability Test Tool v3 (PITTv3)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Pittv3Args {
    /// Full path of folder containing binary DER-encoded trust anchors to use when generating CBOR
    /// file containing partial certification paths and when validating certification paths.
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    ta_folder: Option<String>,

    /// Full path and filename of file to provide and/or receive CBOR-formatted representation of
    /// buffers containing binary DER-encoded CA certificates and map containing set of partial
    /// certification paths.
    #[clap(long, short = 'b', help_heading = "COMMON OPTIONS")]
    cbor: Option<String>,

    /// Time to use for path validation expressed as the number of seconds since Unix epoch
    /// (defaults to current system time).
    #[clap(short = 'i', long, default_value_t = get_now_as_unix_epoch(), help_heading = "COMMON OPTIONS")]
    time_of_interest: u64,

    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See <https://docs.rs/log4rs/latest/log4rs/> for details.
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    logging_config: Option<String>,

    /// Full path of folder to receive binary DER-encoded certificates from paths that fail path
    /// validation. If absent, errant files are not saved for review.
    #[clap(long, short = 'o', help_heading = "COMMON OPTIONS")]
    error_folder: Option<String>,

    /// Full path and filename of folder to receive downloaded binary DER-encoded certificates, if
    /// absent at generate time, the ca_folder is used.
    #[clap(long, short, help_heading = "COMMON OPTIONS")]
    download_folder: Option<String>,

    /// Full path of folder containing binary, DER-encoded intermediate CA certificates. Required
    /// when generate action is performed. This is not used when path validation is performed other
    /// than as a place to store downloaded files when dynamic building is used and download_folder
    /// is not specified.
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    ca_folder: Option<String>,

    /// Full path and filename of file to provide and/or receive JSON-formatted Last-Modified
    /// information for SIA and AIA retrieval during generate operations or when using dynamic building.
    #[clap(long, short = 'm', help_heading = "COMMON OPTIONS")]
    last_modified_map: Option<String>,

    /// Full path and filename of file to provide and/or receive JSON-formatted list of URIs to skip
    /// when processing SIA and AIA URIs during generate operations or when using dynamic building.
    #[clap(long, short = 'x', help_heading = "COMMON OPTIONS")]
    blocklist: Option<String>,

    /// Flag that indicates a fresh CBOR-formatted file containing buffers of CA certificates and
    /// map containing set of partial certification paths should be generated and saved to location
    /// indicated by cbor parameter.
    #[clap(short = 'g', long, help_heading = "GENERATION")]
    generate: bool,

    /// Flag that indicates whether AIA and SIA URIs should be consulted when performing generate
    /// action.
    #[clap(short = 'a', long, help_heading = "GENERATION")]
    chase_aia_and_sia: bool,

    /// Flag that indicates all available certification paths should be validated for each target,
    /// instead of stopping after finding first valid path.
    #[clap(short, long, help_heading = "VALIDATION")]
    validate_all: bool,

    /// Process AIA and SIA during path validation, as appropriate. Either ca_folder or
    /// download_folder must be specified when using this flag to provide a place to store
    /// downloaded artifacts.
    #[clap(short = 'y', long, help_heading = "VALIDATION")]
    dynamic_build: bool,

    /// Causes the server authentication EKU value to be required across the path. This will likely
    /// be dropped when serialized certification path settings support is added.
    #[clap(long, help_heading = "VALIDATION")]
    tls_eku: bool,

    /// Full path and filename of a binary DER-encoded certificate to validate.
    #[clap(short, long, help_heading = "VALIDATION")]
    end_entity_file: Option<String>,

    /// Full path folder to recursively traverse for binary DER-encoded certificates to validate.
    /// Only files with .der, .crt or cert as file extension are processed.
    #[clap(long, short = 'f', help_heading = "VALIDATION")]
    end_entity_folder: Option<String>,

    /// Full path and filename of folder to receive binary DER-encoded certificates from certification
    /// paths. Folders will be created beneath this using a hash of the target certificate. Within
    /// that folder, folders will be created with a number indicating each path, i.e., the number
    /// indicates the order in which the path was returned for consideration. For best results, this
    /// folder should be cleaned in between runs. PITTv3 does not perform hygiene on this folder or
    /// its contents.
    #[clap(long, short, help_heading = "VALIDATION")]
    results_folder: Option<String>,

    /// Paired with ca_folder to remove expired, unparseable certificates, self-signed
    /// certificates and non-CA certificates from consideration. When paired with error_folder,
    /// the errant files are moved instead of deleted. After cleanup completes, the application
    /// exits with no other parameters acted upon.
    #[clap(long, help_heading = "CLEANUP")]
    cleanup: bool,

    /// Paired with ta_folder to remove expired or unparseable certificatesfrom consideration. When
    /// paired with error_folder, the errant files are moved instead of deleted. After cleanup
    /// completes, the application exits with no other parameters acted upon.
    #[clap(long, help_heading = "CLEANUP")]
    ta_cleanup: bool,

    /// Pair with cleanup to generate list of files that would be cleaned up by cleanup operation
    /// without actually deleting or moving files.
    #[clap(long, help_heading = "CLEANUP")]
    report_only: bool,

    /// Outputs all partial paths present in CBOR file. If a ta_folder is provided, the CBOR file
    /// will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of
    /// partial paths relative to that read from CBOR). Use of a logging-config option is recommended
    /// for large CBOR files.
    #[clap(long, help_heading = "DIAGNOSTICS")]
    list_partial_paths: bool,

    /// Outputs all buffers present in CBOR file.
    #[clap(long, help_heading = "DIAGNOSTICS")]
    list_buffers: bool,

    /// Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file. Add
    /// downloads_folder to save certificates that are valid as of time_of_interest from the
    /// downloaded artifacts (use time_of_interest=0 to download all). Pass blocklist or
    /// last_modified_map if desired.
    #[clap(long, help_heading = "DIAGNOSTICS")]
    list_aia_and_sia: bool,

    /// Outputs all name constraints found in certificates present in CBOR file.
    #[clap(long, help_heading = "DIAGNOSTICS")]
    list_name_constraints: bool,

    /// Outputs all buffers present in trust anchors folder.
    #[clap(long, help_heading = "DIAGNOSTICS")]
    list_trust_anchors: bool,

    /// Outputs the certificate at the specified index to a file names <index>.der in the
    /// download_folder if specified, else current working directory.
    #[clap(long, help_heading = "DIAGNOSTICS")]
    dump_cert_at_index: Option<usize>,

    /// Outputs all partial paths present in CBOR file relative to the indicated target. If a
    /// ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
    /// time_of_interest (possibly changing the set of partial paths relative to that read from CBOR).
    #[clap(short = 'z', long, help_heading = "DIAGNOSTICS")]
    list_partial_paths_for_target: Option<String>,

    /// Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If a
    /// ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
    /// time_of_interest (possibly changing the set of partial paths relative to that read from CBOR).
    #[clap(short = 'p', long, help_heading = "DIAGNOSTICS")]
    list_partial_paths_for_leaf_ca: Option<usize>,
}

/// `PathValidationStats` enables collection of some basic statistics related to path validation.
pub struct PathValidationStats<'a> {
    files_processed: i32,
    paths_per_target: usize,
    valid_paths_per_target: usize,
    invalid_paths_per_target: usize,
    target_is_revoked: bool,
    results: Vec<CertificationPathResults<'a>>,
}

impl<'a> Default for PathValidationStats<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> PathValidationStats<'_> {
    /// BuffersAndPaths::new instantiates a new empty BuffersAndPaths.
    pub fn new() -> PathValidationStats<'a> {
        PathValidationStats {
            files_processed: 0,
            paths_per_target: 0,
            valid_paths_per_target: 0,
            invalid_paths_per_target: 0,
            target_is_revoked: false,
            results: vec![],
        }
    }
}

/// `PVStats` is used to initialize stats collection for a given target certificate.
trait PVStats {
    fn init_for_target(&mut self, cert_filename: &str);
}

/// `PathValidationStatsGroup` is a typedef for a BTreeMap that associates a string (containing a filename)
/// with a [`PathValidationStats`] instance.
pub type PathValidationStatsGroup<'a> = BTreeMap<String, PathValidationStats<'a>>;

impl<'a> PVStats for PathValidationStatsGroup<'_> {
    fn init_for_target(&mut self, cert_filename: &str) {
        if !self.contains_key(cert_filename) {
            self.insert(cert_filename.to_string(), PathValidationStats::default());
        }
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
async fn generate_and_validate(ta_source: &TaSource<'_>, args: &Pittv3Args) {
    // TODO add means to load serialized path settings to allow use of various configurations
    let mut cps = CertificationPathSettings::new();
    set_time_of_interest(&mut cps, args.time_of_interest);
    set_extended_key_usage_path(&mut cps, true);

    if args.tls_eku {
        let mut ekus = BTreeSet::new();
        ekus.insert(PKIX_KP_SERVERAUTH);
        set_extended_key_usage(&mut cps, ekus);
    }

    // The CBOR file is required (but can be an empty file if doing dynamic building only)
    let cbor_file = if let Some(cbor) = &args.cbor {
        cbor
    } else {
        ""
    };

    // The last modified map, blocklist and download_folder (or ca_folder if present and
    // download_folder is absent) are only relevant when doing dynamic building.
    let lmm_file = if let Some(lmm) = &args.last_modified_map {
        lmm
    } else {
        ""
    };

    let blocklist_file = if let Some(blocklist) = &args.blocklist {
        blocklist
    } else {
        ""
    };

    let ca_folder = if let Some(ca_folder) = &args.ca_folder {
        ca_folder
    } else {
        ""
    };

    let download_folder = if let Some(download_folder) = &args.download_folder {
        download_folder
    } else {
        ca_folder
    };

    if args.dynamic_build && download_folder.is_empty() {
        panic!(
            "Either ca_folder or download_folder must be specified when dynamic_build is specified"
        )
    }

    // read the last modified map and blocklist once
    let mut lmm = read_lmm(lmm_file);
    let mut blocklist = read_blocklist(blocklist_file);

    // Generate can be paired with validation to ensure the CBOR file used during validation is current
    if args.generate {
        let mut pe = PkiEnvironment::default();
        populate_5280_pki_environment(&mut pe);
        pe.add_logger(log_message);
        pe.add_trust_anchor_source(ta_source);
        generate(args, &cps, &pe).await;
    }

    // if there's nothing to validate, there is nothing further to do
    if args.end_entity_folder.is_none() && args.end_entity_file.is_none() {
        return;
    }

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

    loop {
        // TODO add means to remove specific items from a PkiEnvironment then move this outside the loop
        let mut pe = PkiEnvironment::default();
        populate_5280_pki_environment(&mut pe);
        pe.add_logger(log_message);
        pe.add_trust_anchor_source(ta_source);

        // Create a new CertSource and (re-)deserialize on every iteration due references to
        // buffers in the certs member. On the first pass, cbor will contain data read from file,
        // on subsequent passes it will contain a fresh CBOR blob that features buffers downloaded
        // from AIA or SIA locations.
        let mut cert_source = CertSource::new();
        if cbor.is_empty() {
            // Empty CBOR is fine when doing dynamic building or when validating certificates
            // issued by a trust anchor
            if 0 == pass {
                pe.log_message(
                    &PeLogLevels::PeInfo,
                    format!("Empty CBOR file at {}. Proceeding without it.", cbor_file).as_str(),
                );
            }
            cert_source.buffers_and_paths = BuffersAndPaths::default();

            // Not harvesting URIs and doing dynamic on first pass on off chance the end entity
            // was issued by a trust anchor. It may be better to harvest here and save a loop.
        } else {
            // we want to use the buffers as augmented by last round but want to start from scratch
            // on the partial paths.
            match from_reader(cbor.as_slice()) {
                Ok(cbor_data) => cert_source.buffers_and_paths = cbor_data,
                Err(e) => {
                    cert_source.buffers_and_paths = BuffersAndPaths::default();
                    pe.log_message(
                        &PeLogLevels::PeError,
                        format!(
                            "Failed to parse CBOR file at {} with: {}. Proceeding without it.",
                            cbor_file, e
                        )
                        .as_str(),
                    );
                }
            }
            if 0 < pass {
                cert_source
                    .buffers_and_paths
                    .partial_paths
                    .borrow_mut()
                    .clear();
            }
        }

        // We don't want to return previously returned paths on subsequent passes through the loop.
        // Since buffers from AIA/SIA are appended to the cert_source.buffers_and_paths.buffers
        // vector, set a threshold to limit paths returned to the caller when building paths. On
        // first pass, use zero so all paths are available. On subsequent passes, only use paths
        // with at least one index above the length of the buffers vector prior to augmentation.
        let threshold = if 0 == pass || cert_source.buffers_and_paths.buffers.is_empty() {
            0
        } else {
            cert_source.buffers_and_paths.buffers.len()
        };

        // Don't do AIA and SIA chasing on first pass (fresh_uris and uri_threshold will be
        // zero). On subsequent passes, if the number of URIs did not change, then we have
        // nothing else to try and can exit the loop.
        if args.dynamic_build && uri_threshold != fresh_uris.len() {
            // this could likely return after fetching one URI, but once we're in the dynamic
            // building soup, we might as well fetch all.
            let r = fetch_to_buffer(
                &pe,
                &fresh_uris,
                download_folder,
                &mut cert_source.buffers_and_paths.buffers,
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
            if let Err(e) = r {
                pe.log_message(
                    &PeLogLevels::PeError,
                    format!("Failed to fetch fresh URIs with {:?}", e).as_str(),
                );
                break;
            }
        } else if 0 < pass {
            break;
        }

        // Save the URI count before doing any validation, which will harvest new URIs
        uri_threshold = fresh_uris.len();

        //TODO refactor to make TaSource.tas and CertSource.certs RefCells with on demand parsing
        //instead of holding all certs parsed all the time?
        let r = populate_parsed_cert_vector(
            &pe,
            &cert_source.buffers_and_paths,
            &cps,
            &mut cert_source.certs,
        );
        if let Err(e) = r {
            pe.log_message(
                &PeLogLevels::PeError,
                format!("Failed to populate cert map: {}", e).as_str(),
            );
            break;
        }

        // Set up the SKID and name maps
        cert_source.index_certs(&pe);

        // If this is not the first pass, find all partial paths present in buffers_and_paths. If
        // this is the first pass, we expect this to have been present in the deserialized CBOR.
        if 0 < pass {
            cert_source.find_all_partial_paths(&pe, ta_source, &cps);

            // After finding all partial paths, serialize as CBOR and save for next pass
            match cert_source.serialize_partial_paths(&pe, CertificationPathBuilderFormats::Cbor) {
                Ok(new_cbor) => {
                    cbor = new_cbor;
                }
                Err(e) => pe.log_message(
                    &PeLogLevels::PeError,
                    format!(
                        "Failed to serialize CBOR after dynamic building with {:?}",
                        e
                    )
                    .as_str(),
                ),
            }

            if args.dynamic_build {
                // Iterate over freshly added certs and collect up URIs from AIA and SIA
                for i in threshold..cert_source.certs.len() {
                    if let Some(c) = &cert_source.certs[i] {
                        collect_uris_from_aia_and_sia(c, &mut fresh_uris);
                    }
                }
            }
        }

        // add the CertSource instance to the PkiEnvironment as both a source of certificates and
        // as a path builder
        pe.add_certificate_source(&cert_source);
        pe.add_path_builder(&cert_source);

        // perform validation of end entity certificate file or folder. pass in fresh_uris to collect
        // URIs from any relevant trust anchors.
        if let Some(filename) = &args.end_entity_file {
            stats.init_for_target(filename);
            let stats_for_file = stats.get_mut(filename).unwrap();

            if args.validate_all
                || (stats_for_file.valid_paths_per_target == 0 && !stats_for_file.target_is_revoked)
            {
                // validate when validating all or we don't have a definitive answer yet
                validate_cert_file(
                    &pe,
                    &cps,
                    filename.as_str(),
                    stats_for_file,
                    args,
                    &mut fresh_uris,
                    threshold,
                );
            }
        }

        if let Some(folder) = &args.end_entity_folder {
            validate_cert_folder(
                &pe,
                &cps,
                folder.as_str(),
                &mut stats,
                args,
                &mut fresh_uris,
                threshold,
            );
        }

        if !args.dynamic_build {
            break;
        } else if !args.validate_all {
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

    let mut error_indices: BTreeMap<&String, BTreeMap<Error, Vec<usize>>> = BTreeMap::new();
    let mut error_counts: BTreeMap<&String, BTreeMap<Error, i32>> = BTreeMap::new();
    for key in stats.keys() {
        let stats = &stats[key];
        let mut index_map: BTreeMap<Error, Vec<usize>> = BTreeMap::new();
        let mut count_map: BTreeMap<Error, i32> = BTreeMap::new();
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

    log_message(&PeLogLevels::PeDebug, format!("Args: {:?}", args).as_str());

    log_message(
        &PeLogLevels::PeInfo,
        format!(
        "{:?} to deserialize graph and perform build and validation operation(s) for {} file(s)",
        duration,
        stats.keys().len()
    )
        .as_str(),
    );

    let json_lmm = serde_json::to_string(&lmm);
    if !lmm_file.is_empty() {
        if let Ok(json_lmm) = &json_lmm {
            fs::write(lmm_file, json_lmm).expect("Unable to write last modified map file");
        }
    }

    let json_blocklist = serde_json::to_string(&blocklist);
    if !blocklist_file.is_empty() {
        if let Ok(json_blocklist) = &json_blocklist {
            fs::write(blocklist_file, json_blocklist).expect("Unable to write blocklist file");
        }
    }
}

/// Point of entry for PITTv3 application.
#[tokio::main]
async fn main() {
    let e = env::args_os();
    if 1 == e.len() {
        let mut a = Pittv3Args::into_app();
        if let Err(_e) = a.print_help() {
            println!("Error printing help. Try again with -h parameter.")
        }
        return;
    }
    let args = Pittv3Args::parse();

    if let Some(logging_config) = &args.logging_config {
        if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
            println!(
                "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                logging_config, e
            );
        }
    } else {
        // if there's no config, prepare one using stdout
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();
        let config = Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
            .unwrap();
        let handle = log4rs::init_config(config);
        if let Err(e) = handle {
            println!(
                "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                e
            );
        }
    }
    log_message(&PeLogLevels::PeDebug, "PITTv3 start");

    if args.cleanup {
        // Cleanup runs in isolation because it does not require or process a TA folder
        let mut pe = PkiEnvironment::default();
        populate_5280_pki_environment(&mut pe);
        pe.add_logger(log_message);
        cleanup(&pe, &args);
    } else if args.ta_cleanup {
        // Cleanup runs in isolation because it does not require or process a TA folder
        let mut pe = PkiEnvironment::default();
        populate_5280_pki_environment(&mut pe);
        pe.add_logger(log_message);
        ta_cleanup(&pe, &args);
    } else if args.list_trust_anchors {
        let mut pe = PkiEnvironment::default();
        pe.add_logger(log_message);

        // Load up the trust anchors. This occurs once and is not effected by the dynamic_build flag.
        let ta_folder: &String = if let Some(ta_folder) = &args.ta_folder {
            ta_folder
        } else {
            panic!("The ta_folder argument must be provided")
        };

        let mut ta_store = TaSource::new();
        let r = certs_folder_to_map(&pe, ta_folder, &mut ta_store.buffers, args.time_of_interest);
        if let Err(e) = r {
            println!(
                "Failed to load trust anchors from {} with error {:?}",
                ta_folder, e
            );
            return;
        }
        populate_parsed_ta_vector(&ta_store.buffers, &mut ta_store.tas);
        ta_store.index_tas(&pe);

        let mut pe = PkiEnvironment::default();
        pe.add_logger(log_message);
        ta_store.log_tas(&pe);
    } else if args.list_partial_paths
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
        set_time_of_interest(&mut cps, args.time_of_interest);

        let mut pe = PkiEnvironment::default();
        pe.add_logger(log_message);

        let cbor = read_cbor(&args.cbor);
        if cbor.is_empty() {
            println!(
                "Failed to read CBOR data from file located at {}",
                cbor_file
            );
            return;
        }

        let mut cert_source = CertSource::new();
        match from_reader(cbor.as_slice()) {
            Ok(cbor_data) => {
                cert_source.buffers_and_paths = cbor_data;
            }
            Err(e) => {
                panic!("Failed to parse CBOR file at {} with: {}", cbor_file, e)
            }
        }
        let r = populate_parsed_cert_vector(
            &pe,
            &cert_source.buffers_and_paths,
            &cps,
            &mut cert_source.certs,
        );
        if let Err(e) = r {
            pe.log_message(
                &PeLogLevels::PeError,
                format!("Failed to populate cert vector with: {:?}", e).as_str(),
            );
        }

        cert_source.index_certs(&pe);
        let mut ta_store = TaSource::new();

        if let Some(ta_folder) = &args.ta_folder {
            let r =
                certs_folder_to_map(&pe, ta_folder, &mut ta_store.buffers, args.time_of_interest);
            if let Err(e) = r {
                println!(
                    "Failed to load trust anchors from {} with error {:?}",
                    ta_folder, e
                );
                return;
            }
            populate_parsed_ta_vector(&ta_store.buffers, &mut ta_store.tas);
            ta_store.index_tas(&pe);
            populate_5280_pki_environment(&mut pe);
            pe.add_trust_anchor_source(&ta_store);

            cert_source
                .buffers_and_paths
                .partial_paths
                .borrow_mut()
                .clear();
            cert_source.find_all_partial_paths(&pe, &ta_store, &cps);
        }

        if let Some(index) = args.dump_cert_at_index {
            if index >= cert_source.certs.len() {
                println!(
                    "Requested index does not exist. Try again with an index value less than {}",
                    cert_source.certs.len()
                );
                return;
            }
            let c = &cert_source.certs[index];
            if let Some(cert) = c {
                let p = Path::new(&download_folder);
                let fname = format!("{}.der", index);
                let f = p.join(fname);
                fs::write(f, cert.encoded_cert).expect("Unable to write certificate file");
            } else {
                println!("Requested index does not exist, possibly due to a parsing or validity check error when deserializing the CBOR file");
                return;
            }
        }

        if args.list_aia_and_sia {
            let mut fresh_uris = vec![];
            cert_source.log_all_aia_and_sia(&pe, &mut fresh_uris);

            let lmm_file = if let Some(lmm) = &args.last_modified_map {
                lmm
            } else {
                ""
            };

            let blocklist_file = if let Some(blocklist) = &args.blocklist {
                blocklist
            } else {
                ""
            };

            if let Some(download_folder) = &args.download_folder {
                let mut buffers: Vec<CertFile> = vec![];

                let mut blocklist = read_blocklist(blocklist_file);
                let mut lmm = read_lmm(lmm_file);

                let r = fetch_to_buffer(
                    &pe,
                    &fresh_uris,
                    download_folder,
                    &mut buffers,
                    0,
                    &mut lmm,
                    &mut blocklist,
                    args.time_of_interest,
                )
                .await;
                if let Err(e) = r {
                    pe.log_message(
                        &PeLogLevels::PeError,
                        format!("Encountered error downloading URIs: {}", e).as_str(),
                    );
                }
            }
        }

        if args.list_name_constraints {
            cert_source.log_all_name_constraints(&pe);
        }

        if args.list_buffers {
            cert_source.log_certs(&pe);
            if let Some(download_folder) = &args.download_folder {
                for (i, buffer) in cert_source.buffers_and_paths.buffers.iter().enumerate() {
                    let p = Path::new(download_folder);
                    let fname = format!("{}.der", i);
                    let pbuf = p.join(fname);
                    if let Err(e) = fs::write(pbuf, &buffer.bytes) {
                        pe.log_message(
                            &PeLogLevels::PeError,
                            format!("Failed to write certificate #{} to file: {}", i, e).as_str(),
                        );
                    }
                }
            }
        }
        if args.list_partial_paths {
            cert_source.log_partial_paths(&pe);
        }
        if let Some(cert_filename) = args.list_partial_paths_for_target {
            let target = if let Ok(t) = get_file_as_byte_vec(Path::new(&cert_filename)) {
                t
            } else {
                pe.log_message(
                    &PeLogLevels::PeError,
                    format!("Failed to read file at {}", cert_filename).as_str(),
                );
                return;
            };

            let parsed_cert = parse_cert(target.as_slice(), cert_filename.as_str());
            if let Some(target_cert) = parsed_cert {
                cert_source.log_paths_for_target(&pe, &target_cert, args.time_of_interest);
            }
        }
        if let Some(leaf_ca_index) = args.list_partial_paths_for_leaf_ca {
            if leaf_ca_index >= cert_source.certs.len() {
                println!(
                    "Requested index does not exist. Try again with an index value less than {}",
                    cert_source.certs.len()
                );
                return;
            }
            let c = &cert_source.certs[leaf_ca_index];
            if let Some(leaf_ca_cert) = c {
                cert_source.log_paths_for_leaf_ca(&pe, leaf_ca_cert);
            } else {
                println!("Requested index does not exist, possibly due to a parsing or validity check error when deserializing the CBOR file");
                return;
            }
        }
    } else {
        let mut pe = PkiEnvironment::default();
        pe.add_logger(log_message);

        // Load up the trust anchors. This occurs once and is not effected by the dynamic_build flag.
        let ta_folder: &String = if let Some(ta_folder) = &args.ta_folder {
            ta_folder
        } else {
            panic!("The ta_folder argument must be provided")
        };

        let mut ta_store = TaSource::new();
        let r = certs_folder_to_map(&pe, ta_folder, &mut ta_store.buffers, args.time_of_interest);
        if let Err(e) = r {
            println!(
                "Failed to load trust anchors from {} with error {:?}",
                ta_folder, e
            );
            return;
        }
        populate_parsed_ta_vector(&ta_store.buffers, &mut ta_store.tas);
        ta_store.index_tas(&pe);

        // Generate, validate certificate file, or validate certificates folder per args.
        generate_and_validate(&ta_store, &args).await;
    }
    log_message(&PeLogLevels::PeDebug, "PITTv3 end");
}

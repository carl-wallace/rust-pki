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
//! The options shown below are those of the default build, which includes remote support:
//!
//! ```text
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
//!   -t, --ta-folder <TA_FOLDER>
//!           Full path of a folder containing binary DER-encoded trust anchors, or of a single such file, to use when generating CBOR file containing partial certification paths and when validating certification paths. A file may hold several concatenated PEM objects
//!       --ta-cbor <TA_CBOR>
//!           Full path and filename of a CBOR-formatted trust anchor store, i.e., the form written by --generate --cbor-ta-store and the form the certval trust store providers serialize. This is the trust anchor counterpart of --cbor; it may be combined with --ta-folder, in which case the anchors from both are used
//!       --ta <TA_INPUT>
//!           Additional trust anchor input, repeatable. Each occurrence may name a folder, a certificate, a bundle holding several, or a CBOR-formatted trust anchor store; what it is comes from the path and then from the bytes, so the four need not be sorted into different arguments first. This is the plural form of --ta-folder and --ta-cbor, which still work and are used alongside it
//!       --webpki-tas
//!           Use trust anchors from webpki-roots crate (which are from Mozilla)
//!   -b, --cbor <CBOR>
//!           Full path and filename of file to provide and/or receive CBOR-formatted representation of buffers containing binary DER-encoded CA certificates and map containing set of partial certification paths
//!   -i, --time-of-interest <TIME_OF_INTEREST>
//!           Time to use for path validation expressed as the number of seconds since Unix epoch (defaults to current system time) [default: 1787579866]
//!   -l, --logging-config <LOGGING_CONFIG>
//!           Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See <https://docs.rs/log4rs/latest/log4rs/> for details
//!   -o, --error-folder <ERROR_FOLDER>
//!           Full path of folder to receive binary DER-encoded certificates from paths that fail path validation. If absent, errant files are not saved for review
//!   -d, --download-folder <DOWNLOAD_FOLDER>
//!           Full path and filename of folder to receive downloaded binary DER-encoded certificates, if absent at generate time, the ca_folder is used, which requires it to name a folder rather than a single file. Additionally, this is used to designate where exported buffers are written by dump_cert_at_index or list_buffers
//!   -c, --ca-folder <CA_FOLDER>
//!           Full path of a folder containing binary, DER-encoded intermediate CA certificates, or of a single such file (which may hold several concatenated PEM objects, e.g. a fullchain). Required when generate action is performed. When path validation is performed, these certificates are added to the graph that is built, augmenting any CBOR store in use. A folder also doubles as a place to store downloaded files when dynamic building is used and download_folder is not specified
//!       --ca <CA_INPUT>
//!           Additional intermediate CA input, repeatable. Each occurrence may name a folder, a certificate, a bundle holding several, or a CBOR-formatted store, and all of them feed the one graph a run builds. This is the plural form of --ca-folder and --cbor for validation. It is not consulted when generating: --ca-folder names the folder generation reads, and --cbor the file it writes
//!
//! GENERATION:
//!   -g, --generate           Flag that indicates a fresh CBOR-formatted file containing buffers of CA certificates and map containing set of partial certification paths should be generated and saved to location indicated by cbor parameter
//!   -a, --chase-aia-and-sia  Flag that indicates whether AIA and SIA URIs should be consulted when performing generate action
//!       --cbor-ta-store      Flag that indicates generated CBOR file will contain only trust anchors  (so no need for partial paths and no need to exclude self-signed certificates). The anchors are read from the ca_folder input, which may name a single file, and the result is the form ta_cbor takes
//!
//! VALIDATION:
//!   -v, --validate-all
//!           Flag that indicates all available certification paths should be validated for each target
//!       --validate-self-signed
//!           Check if certificate passed as end_entity_file is self-signed
//!   -y, --dynamic-build
//!           Process AIA and SIA during path validation, as appropriate. Either ca_folder or download_folder must be specified when using this flag to provide a place to store downloaded artifacts
//!   -e, --end-entity-file <END_ENTITY_FILE>
//!           Full path and filename of a binary DER-encoded certificate to validate
//!   -f, --end-entity-folder <END_ENTITY_FOLDER>
//!           Full path folder to recursively traverse for binary DER-encoded certificates to validate. Only files with .der, .crt or cert as file extension are processed
//!       --ee <EE_INPUT>
//!           Additional certificate to validate, repeatable. Each occurrence may name a single certificate or a folder to traverse for them. This is the plural form of --end-entity-file and --end-entity-folder, which still work and are validated alongside it
//!   -r, --results-folder <RESULTS_FOLDER>
//!           Full path and filename of folder to receive binary DER-encoded certificates from certification paths. Folders will be created beneath this using a hash of the target certificate. Within that folder, folders will be created with a number indicating each path, i.e., the number indicates the order in which the path was returned for consideration. For best results, this folder should be cleaned in between runs. PITTv3 does not perform hygiene on this folder or its contents
//!   -s, --settings <SETTINGS>
//!           Full path and filename of JSON-formatted certification path validation settings
//!       --crl-folder <CRL_FOLDER>
//!           Full path of a folder containing DER- or PEM-encoded CRLs, traversed recursively and indexed before path validation begins. Only files with a .crl extension are processed. The indexed CRLs are the local revocation source, consulted before any remote retrieval, and the folder also receives CRLs fetched remotely along with the last-modified map that makes those fetches conditional. Note that the folder is written as well as read: indexing deletes any CRL that is not valid at the time of interest, i.e. one whose thisUpdate is in the future or whose nextUpdate has passed
//!       --rev <REV_INPUT>
//!           Revocation artifact to staple into candidate certification paths, repeatable. Each occurrence may name a single artifact or a folder to traverse, and may hold either a CRL or an OCSP response — the bytes decide, since an OCSP response has no settled file extension. CRLs are matched to path positions by issuer name, OCSP responses by the CertID each answers about. Unlike --crl-folder, which is an index that deletes CRLs not valid at the time of interest, artifacts named here are read and left alone
//!       --keep-crl-entries-in-memory
//!           When set together with --crl-folder, retain the revoked serial numbers of each verified full/direct CRL in memory so subsequent certificates under the same scope are answered without re-parsing or re-verifying the CRL
//!
//! CLEANUP:
//!       --cleanup      Paired with ca_folder to remove expired, unparseable certificates, self-signed certificates and non-CA certificates from consideration. When paired with error_folder, the errant files are moved instead of deleted. After cleanup completes, the application exits with no other parameters acted upon
//!       --ta-cleanup   Paired with ta_folder to remove expired or unparseable certificatesfrom consideration. When paired with error_folder, the errant files are moved instead of deleted. After cleanup completes, the application exits with no other parameters acted upon
//!       --report-only  Pair with cleanup to generate list of files that would be cleaned up by cleanup operation without actually deleting or moving files
//!
//! DIAGNOSTICS:
//!       --list-partial-paths
//!           Outputs all partial paths present in CBOR file. If a ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of partial paths relative to that read from CBOR). Use of a logging-config option is recommended for large CBOR files
//!       --list-buffers
//!           Outputs all buffers present in CBOR file
//!       --list-aia-and-sia
//!           Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file. Add downloads_folder to save certificates that are valid as of time_of_interest from the downloaded artifacts (use time_of_interest=0 to download all). Specify a blocklist or last_modified_map if desired via CertificationPathSettings or rely on default files that will be generated and managed in folder used to download artifacts
//!       --list-name-constraints
//!           Outputs all name constraints found in certificates present in CBOR file
//!       --list-trust-anchors
//!           Outputs all buffers present in trust anchors folder
//!       --dump-cert-at-index <DUMP_CERT_AT_INDEX>
//!           Outputs the certificate at the specified index to a file names `<index>.der` in the download_folder if specified, else current working directory
//!   -z, --list-partial-paths-for-target <LIST_PARTIAL_PATHS_FOR_TARGET>
//!           Outputs all partial paths present in CBOR file relative to the indicated target. If a ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of partial paths relative to that read from CBOR)
//!   -p, --list-partial-paths-for-leaf-ca <LIST_PARTIAL_PATHS_FOR_LEAF_CA>
//!           Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If a ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of partial paths relative to that read from CBOR)
//!
//! TOOLS:
//!       --mozilla-csv <MOZILLA_CSV>  Parses the given CSV file and saves files to folder indicated by the ca_folder parameter. The CSV file is assumed to be as posted as the "Non-revoked, non-expired Intermediate CA Certificates chaining up to roots in Mozilla's program with the Websites trust bit set (CSV with PEM of raw certificate data)" report available on the Mozilla wiki page at <https://wiki.mozilla.org/CA/Intermediate_Certificates>
//!       --check-uris <CHECK_URIS>    Checks the HTTP URIs in the AIA, SIA, CRL DP and freshest-CRL extensions of the certificate at the given path, reporting per-URI reachability and correctness. Runs independently of path processing; no CBOR store or trust anchors are required
//!       --issuer <ISSUER>            Optional issuer certificate (path) for --check-uris, used to verify CRL signatures and check OCSP URIs. Auto-discovered from AIA caIssuers when omitted
//!       --no-auto-discover           Disables auto-discovery of the issuer certificate from AIA caIssuers during --check-uris
//! ```
//!
//! A build without remote support omits the two options shown below:
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
use crate::graph_cache;
use crate::report::{ReportTotals, TargetReport, ValidationReport};
use crate::retained::{RetainedPath, RetainedRun};
use crate::stats::{PVStats, PathValidationStats, PathValidationStatsGroup};
use crate::std_utils::*;

#[cfg(feature = "sha1_sig")]
use crate::sha1_sig::verify_signature_message_rust_crypto_sha1;

/// Added to the no-paths diagnosis, and logged where the folder is read, when a trust anchor folder
/// was supplied and yielded nothing. The filtering happens quietly in `ta_folder_to_vec`, which
/// returns `Ok(0)` for a folder it emptied — indistinguishable from no folder at all by the time the
/// environment is queried. Note the validity filter there is not governed by
/// `PS_ENFORCE_TRUST_ANCHOR_VALIDITY`: that setting applies during path validation, where it also
/// (correctly) passes an anchor that asserts no validity to enforce.
const TA_FOLDER_EMPTY: &str =
    "A trust anchor folder was supplied but no anchor was read from it: objects that do not parse \
     as a trust anchor, or that are expired at the time of interest, are dropped when the folder \
     is read.";

/// Added to the no-paths diagnosis when a CA folder was supplied and nothing was read from it. The
/// folder is folded into the graph at validation time, so an empty read is the one case where the
/// user supplied intermediates and the builder still had none. Named here because it is reported
/// twice: once in the run log beside the zero count, and once in the structured report for a
/// frontend to display.
const CA_FOLDER_EMPTY: &str =
    "A CA folder was supplied but no certificate was read from it: only .der, .cer and .crt files \
     are read, and objects that do not parse as a certificate, or that are expired at the time of \
     interest, are dropped when the folder is read.";

/// Added to the no-paths diagnosis when the anchors came from a Windows certificate store. Unlike
/// the two above this does not mean the store was empty: it says that what a store holds is not the
/// set of roots the platform will ultimately trust, which is the part that surprises. Windows ships
/// a subset of its root program and fetches the rest on demand, so a root can be genuinely absent
/// at the moment of the run and present later — and a root placed there by hand is only the one
/// that was placed there, which is not always the one the target needs.
#[cfg(feature = "capi")]
const CAPI_TA_STORE_PARTIAL: &str =
    "Trust anchors were read from a Windows certificate store. Such a store holds only the roots \
     that have been installed on this machine or that Windows has fetched on demand, so it may not \
     yet hold the one this target needs. Check the store for the target's root -- in PowerShell, \
     Get-ChildItem Cert:\\LocalMachine\\Root -- and note that the current user's view of a store \
     includes the machine's roots as well as any added for the user.";

/// Normalizes a PEM block so its base64 body is wrapped at the 64 columns that RFC 7468 (and the
/// strict `pem-rfc7468` decoder) requires. Some CCADB CSV exports wrap the certificate PEM at a
/// non-standard width (e.g. 65 columns), which the strict decoder rejects; re-wrapping lets those
/// rows be ingested without loosening the decoder used everywhere else. Returns `None` if the input
/// does not look like a single `-----BEGIN <label>----- … -----END <label>-----` block.
#[cfg(feature = "std")]
fn normalize_pem_wrap(pem: &str) -> Option<String> {
    let mut lines = pem.lines().map(|l| l.trim());
    let begin = lines.next()?.trim();
    let label = begin
        .strip_prefix("-----BEGIN ")
        .and_then(|l| l.strip_suffix("-----"))?;
    let end = format!("-----END {label}-----");

    let mut body = String::new();
    let mut saw_end = false;
    for line in lines {
        if line == end {
            saw_end = true;
            break;
        }
        body.push_str(line);
    }
    if !saw_end {
        return None;
    }

    let mut out = format!("-----BEGIN {label}-----\n");
    let bytes = body.as_bytes();
    for chunk in bytes.chunks(64) {
        out.push_str(core::str::from_utf8(chunk).ok()?);
        out.push('\n');
    }
    out.push_str(&end);
    out.push('\n');
    Some(out)
}

/// The `options_std` function provides argument parsing and corresponding actions when `PITTv3` and
/// `certval` are built with standard library support (i.e., with `std`, `revocation,std` or `remote` features).
///
/// A structured [`ValidationReport`] is returned when validation actions are performed; actions
/// that perform no validation (generation, cleanup, diagnostics, tools) return a default (empty)
/// report. The CLI ignores the return value (log/file output is unchanged); GUI and server
/// frontends consume it.
pub async fn options_std(args: &Pittv3Args) -> ValidationReport {
    let (report, _) = options_std_retaining(args, false).await;
    report
}

/// As [`options_std`], additionally returning the paths a run validated and the environment it
/// validated them against when `retain` is set.
///
/// This is what lets a frontend offer the artifacts behind a result *after* the run: `results_folder`
/// answers the same need but has to be named before it starts, and validating a second time to
/// produce an export would describe a different run, since revocation data moves.
///
/// `None` comes back whenever nothing was validated — the actions that generate, clean up, or run a
/// diagnostic have no paths to keep — and whenever `retain` is false, which is the CLI's case and
/// costs it nothing.
pub async fn options_std_retaining(
    args: &Pittv3Args,
    retain: bool,
) -> (ValidationReport, Option<RetainedRun>) {
    let mut kept = None;
    let report = options_std_inner(args, retain.then_some(&mut kept)).await;
    (report, kept)
}

/// The dispatcher itself. Every action other than validation returns a report and writes nothing to
/// `kept`, which is why "nothing was retained" needs no code in those branches: the slot the caller
/// declared simply stays empty.
#[cfg(feature = "std")]
async fn options_std_inner(
    args: &Pittv3Args,
    kept: Option<&mut Option<RetainedRun>>,
) -> ValidationReport {
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

    // The SIA/AIA URI checker runs independently of certification path processing: it needs neither a
    // CBOR store nor trust anchors, so it is handled before any store is loaded and returns directly.
    #[cfg(feature = "remote")]
    if let Some(target_path) = &args.check_uris {
        let target_der = match fs::read(target_path) {
            Ok(b) => b,
            Err(e) => {
                return ValidationReport::failed(format!(
                    "failed to read target certificate {target_path}: {e}"
                ))
            }
        };
        let issuer_der = match &args.issuer {
            Some(p) => match fs::read(p) {
                Ok(b) => Some(b),
                Err(e) => {
                    return ValidationReport::failed(format!(
                        "failed to read issuer certificate {p}: {e}"
                    ))
                }
            },
            None => None,
        };

        let report = crate::uri_check::check_uris_from_bytes(
            &target_der,
            issuer_der.as_deref(),
            !args.no_auto_discover,
            args.time_of_interest,
            &[],
        )
        .await;

        print!("{}", report.to_table_string());
        return ValidationReport::default();
    }

    #[cfg(feature = "std")]
    if args.list_trust_anchors {
        let pe = PkiEnvironment::default();

        // Load up the trust anchors. This occurs once and is not effected by the dynamic_build flag.
        match load_trust_anchors(
            &pe,
            args,
            TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
        ) {
            Ok(Some(ta_store)) => ta_store.log_tas(),
            Ok(None) => {}
            Err(msg) => {
                println!("Failed to load trust anchors: {msg}");
                return ValidationReport::default();
            }
        }

        #[cfg(feature = "webpki")]
        if args.webpki_tas {
            match TaSource::new_from_webpki() {
                Ok(mut ta_store) => {
                    if let Err(e) = ta_store.initialize() {
                        println!(
                            "Failed to initialize trust anchor source from webpki-roots with error {e:?}"
                        );
                        return ValidationReport::default();
                    }

                    ta_store.log_tas();
                }
                Err(e) => {
                    println!(
                        "Failed to create trust anchor source from webpki-roots with error {e:?}"
                    );
                    return ValidationReport::default();
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
            return ValidationReport::failed("--cbor is required when using a diagnostic command");
        };

        let download_folder = if let Some(download_folder) = &args.download_folder {
            download_folder.clone()
        } else {
            "./".to_string()
        };

        let mut cps = CertificationPathSettings::new();
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap());

        let mut pe = PkiEnvironment::default();

        let cbor = read_cbor(&args.cbor);
        if cbor.is_empty() {
            println!("Failed to read CBOR data from the file located at {cbor_file}");
            return ValidationReport::default();
        }

        let mut cert_source = match CertSource::new_from_cbor(cbor.as_slice()) {
            Ok(cbor_data) => cbor_data,
            Err(e) => {
                return ValidationReport::failed(format!(
                    "failed to parse CBOR file at {cbor_file}: {e}"
                ));
            }
        };
        let r = cert_source.initialize(&cps);
        if let Err(e) = r {
            error!("Failed to populate cert vector with: {e:?}");
        }

        pe.populate_5280_pki_environment();

        #[cfg(feature = "sha1_sig")]
        pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto_sha1);

        #[cfg(feature = "webpki")]
        if args.webpki_tas {
            // the TAs read from webpki-roots do not assert a validity do turn off this check
            cps.set_enforce_trust_anchor_validity(false);

            match TaSource::new_from_webpki() {
                Ok(ta_store) => {
                    pe.add_trust_anchor_source(Box::new(ta_store));
                }
                Err(e) => {
                    error!("Failed to initialize TA store from webpki-roots: {e:?}. Continuing...");
                }
            };
        }

        let ta_store = match load_trust_anchors(
            &pe,
            args,
            TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
        ) {
            Ok(ta_store) => ta_store,
            Err(msg) => {
                println!("Failed to load trust anchors: {msg}");
                return ValidationReport::default();
            }
        };

        // Partial paths are recomputed against whatever anchors were supplied, since the set of
        // paths that terminate at an anchor depends on them; a store loaded with none keeps the
        // paths it was serialized with.
        let ta_store_added = ta_store.is_some();
        if let Some(ta_store) = ta_store {
            pe.add_trust_anchor_source(Box::new(ta_store));
        }
        #[cfg(feature = "webpki")]
        let ta_store_added = ta_store_added || args.webpki_tas;
        if ta_store_added {
            cert_source.clear_paths();
            cert_source.find_all_partial_paths(&pe, &cps);
        }

        if let Some(index) = args.dump_cert_at_index {
            if index >= cert_source.num_certs() {
                println!(
                    "Requested index does not exist. Try again with an index value less than {}",
                    cert_source.num_certs()
                );
                return ValidationReport::default();
            }
            let c = &cert_source.get_cert_at_index(index);
            if let Some(cert) = c {
                let p = Path::new(&download_folder);
                let fname = format!("{index}.der");
                let f = p.join(fname);
                if let Err(e) = fs::write(f, cert.as_bytes()) {
                    return ValidationReport::failed(format!(
                        "unable to write certificate file: {e}"
                    ));
                }
            } else {
                println!("Requested index does not exist, possibly due to a parsing or validity check error when deserializing the CBOR file");
                return ValidationReport::default();
            }
        }

        #[cfg(feature = "std")]
        if args.list_aia_and_sia {
            let mut fresh_uris = vec![];
            cert_source.log_all_aia_and_sia(&mut fresh_uris);

            #[cfg(feature = "remote")]
            {
                let lmm_file = last_modified_map_file(&cps, &download_folder);
                let lmm_file = lmm_file.as_str();
                let blocklist_file = uri_blocklist_file(&cps, &download_folder);
                let blocklist_file = blocklist_file.as_str();

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
                        TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
                        cps.get_max_aia_fetch_bytes(),
                    )
                    .await;
                    if let Err(e) = r {
                        error!("Encountered error downloading URIs: {e}");
                    }
                    let json_lmm = serde_json::to_string(&lmm);
                    if !lmm_file.is_empty() {
                        if let Ok(json_lmm) = &json_lmm {
                            if let Err(e) = fs::write(lmm_file, json_lmm) {
                                error!("Unable to write last modified map file: {e}");
                            }
                        }
                    }

                    let json_blocklist = serde_json::to_string(&blocklist);
                    if !blocklist_file.is_empty() {
                        if let Ok(json_blocklist) = &json_blocklist {
                            if let Err(e) = fs::write(blocklist_file, json_blocklist) {
                                error!("Unable to write blocklist file: {e}");
                            }
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
                    let fname = format!("{i}.der");
                    let pbuf = p.join(fname);
                    if let Err(e) = fs::write(pbuf, &buffer.bytes) {
                        error!("Failed to write certificate #{i} to file: {e}");
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
                error!("Failed to read file at {cert_filename}");
                return ValidationReport::default();
            };

            let parsed_cert = parse_cert(target.as_slice(), cert_filename.as_str());
            if let Ok(target_cert) = parsed_cert {
                cert_source.log_paths_for_target(
                    &target_cert,
                    TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
                );
            }
        }
        if let Some(leaf_ca_index) = args.list_partial_paths_for_leaf_ca {
            if leaf_ca_index >= cert_source.num_certs() {
                println!(
                    "Requested index does not exist. Try again with an index value less than {}",
                    cert_source.num_certs()
                );
                return ValidationReport::default();
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
            return ValidationReport::failed(
                "--ca-folder is required when parsing a Mozilla CSV file (to receive the certificate files)",
            );
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

                // Locate the certificate column by header name rather than a fixed index.
                // CCADB has shipped more than one schema for this report: the older export
                // used a "PEM" column (5 columns, PEM at index 4), while the current
                // PublicAllIntermediateCertsWithPEMCSV export uses a "PEM Info" column at a
                // different position (26 columns). A hardcoded index silently stops
                // producing certificates when the format changes.
                let pem_col = rdr.headers().ok().and_then(|h| {
                    h.iter().position(|c| {
                        let c = c.trim();
                        c.eq_ignore_ascii_case("PEM") || c.eq_ignore_ascii_case("PEM Info")
                    })
                });
                let pem_col = match pem_col {
                    Some(c) => c,
                    None => {
                        return ValidationReport::failed(
                            "could not find a \"PEM\" or \"PEM Info\" column in the Mozilla CSV header",
                        );
                    }
                };

                for (i, result) in rdr.records().enumerate() {
                    if let Ok(record) = result {
                        if let Some(s) = record.get(pem_col) {
                            // The current CCADB export wraps the cell in literal apostrophes
                            // (Salesforce's escape so a spreadsheet won't treat the leading
                            // '-' as a formula); strip them from both ends, plus any
                            // surrounding whitespace, before decoding. Older exports have no
                            // such wrapping, so this is a no-op for them.
                            let s = s.trim().trim_matches('\'').trim();
                            // Re-wrap the base64 body to the 64-column width the strict decoder
                            // expects; fall back to the raw cell if it isn't a PEM block.
                            let normalized = normalize_pem_wrap(s);
                            let pem_bytes = normalized.as_deref().unwrap_or(s);
                            match pem::decode_vec(pem_bytes.as_bytes()) {
                                Ok((label, der_bytes)) => {
                                    if label == "CERTIFICATE" {
                                        match Certificate::from_der(&der_bytes) {
                                            Ok(_) => {
                                                let path =
                                                    Path::new(&ca_folder).join(format!("{i}.der"));
                                                if fs::write(path, der_bytes).is_err() {
                                                    println!(
                                                        "Failed to write certificate from row {i}"
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
                println!("Failed to read data from Mozilla CSV file with {e}");
            }
        }
    } else if args.validate_self_signed {
        // The first target named, from either the singular argument or the pool: this asks about
        // one certificate, and a frontend that has replaced its end entity box with a list has no
        // singular argument to put it in.
        if let Some(eff) = args
            .end_entity_file
            .iter()
            .chain(args.ee_inputs.iter())
            .next()
        {
            if let Ok(t) = get_file_as_byte_vec_pem(Path::new(&eff)) {
                let parsed_cert = parse_cert(t.as_slice(), eff.as_str());
                if let Ok(target_cert) = parsed_cert {
                    let mut pe = PkiEnvironment::default();
                    pe.populate_5280_pki_environment();

                    #[cfg(feature = "sha1_sig")]
                    pe.add_verify_signature_message_callback(
                        verify_signature_message_rust_crypto_sha1,
                    );

                    if is_self_signed(&pe, &target_cert) {
                        println!("{eff} is self-signed");
                    } else {
                        println!("{eff} is not self-signed");
                    }
                } else {
                    // try base 64
                    if let Ok(encoded) = pem_rfc7468::decode_vec(t.as_slice()) {
                        let parsed_cert = parse_cert(&encoded.1, eff.as_str());
                        if let Ok(target_cert) = parsed_cert {
                            let mut pe = PkiEnvironment::default();
                            pe.populate_5280_pki_environment();

                            #[cfg(feature = "sha1_sig")]
                            pe.add_verify_signature_message_callback(
                                verify_signature_message_rust_crypto_sha1,
                            );

                            if is_self_signed(&pe, &target_cert) {
                                println!("{eff} is self-signed");
                            } else {
                                println!("{eff} is not self-signed");
                            }
                        }
                    }
                }
            };
        };
    } else {
        // Generate, validate certificate file, or validate certificates folder per args.
        return generate_and_validate(args, kept).await;
    }
    ValidationReport::default()
}

/// generate_and_validate takes a [`TaSource`](certval::TaSource) and program arguments and performs CBOR file generation
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
///
/// When `retain` is set, every validated path is kept and returned with the environment it was
/// validated against, so a frontend can export the artifacts behind a result once the run is over
/// rather than having to name a results folder before it starts.
#[cfg(feature = "std")]
async fn generate_and_validate(
    args: &Pittv3Args,
    kept: Option<&mut Option<RetainedRun>>,
) -> ValidationReport {
    let retain = kept.is_some();
    let mut retained: Vec<RetainedPath> = vec![];
    // The CBOR file is required (but can be an empty file if doing dynamic building only)
    let cbor_file = if let Some(cbor) = &args.cbor {
        cbor
    } else {
        ""
    };

    let mut cps = match read_settings(&args.settings) {
        Ok(cps) => cps,
        Err(e) => {
            return ValidationReport::failed(format!("failed to parse settings file: {e:?}"));
        }
    };

    // Where downloaded intermediates go, resolved after the settings are read because the settings
    // are one of the places it can be named. The argument wins, then the settings file, then the CA
    // folder — a CLI user's flag still takes precedence, and a GUI user who named the folder in the
    // settings form no longer has to name it a second time on the run form.
    #[cfg(feature = "remote")]
    let ca_folder = args
        .ca_folder
        .clone()
        .or_else(|| cps.get_certification_authority_folder())
        .unwrap_or_default();

    #[cfg(feature = "remote")]
    let download_folder = args
        .download_folder
        .clone()
        .or_else(|| cps.get_download_folder())
        .unwrap_or_else(|| ca_folder.clone());

    #[cfg(feature = "remote")]
    if args.dynamic_build && download_folder.is_empty() {
        return ValidationReport::failed(
            "a CA folder or download folder is required when dynamic build is enabled",
        );
    }

    if !cps.0.contains_key(PS_TIME_OF_INTEREST) {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap());
    }

    // Keyed here, on the settings as read, because what follows adjusts them for the run — turning
    // off AIA/SIA retrieval, and anchor validity for webpki anchors — and a caller outside a run
    // has no way to reproduce those adjustments. Both are covered by the key anyway: chasing runs
    // are not cached at all, and webpki_tas is hashed in its own right.
    let graph_fingerprint = graph_cache::fingerprint(args, &cps);

    #[cfg(feature = "remote")]
    if !args.dynamic_build {
        cps.set_retrieve_from_aia_sia_http(false);
    }

    let mut pe = PkiEnvironment::default();
    pe.add_signature_cache(Box::new(DefaultSignatureVerificationCache::default()));
    pe.populate_5280_pki_environment();

    #[cfg(feature = "sha1_sig")]
    pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto_sha1);

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
                error!("Failed to initialize TA store from webpki-roots: {e:?}. Continuing...");
            }
        };
    }

    // Load up the trust anchors. This occurs once and is not effected by the dynamic_build flag.
    match load_trust_anchors(
        &pe,
        args,
        TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
    ) {
        Ok(Some(ta_store)) => {
            // A folder whose objects were all filtered contributes nothing, which is otherwise
            // indistinguishable from having supplied no folder at all — and this is the loudest
            // thing that can be said at the point where the anchors went missing.
            if ta_store.is_empty() {
                let named = args
                    .ta_folder
                    .iter()
                    .chain(args.ta_inputs.iter())
                    .map(String::as_str)
                    .collect::<Vec<&str>>()
                    .join(", ");
                if !named.is_empty() {
                    error!("No trust anchors were loaded from {named}. {TA_FOLDER_EMPTY}");
                }
            }
            // Cached beside the graph and under the same key: the graph's partial paths end at
            // these anchors, and nothing in the graph carries them.
            if let Some(fingerprint) = &graph_fingerprint {
                graph_cache::store_anchors(fingerprint, ta_store.get_tas());
            }
            pe.add_trust_anchor_source(Box::new(ta_store));
            ta_store_added = true;
        }
        Ok(None) => {}
        Err(msg) => {
            println!("Failed to load trust anchors: {msg}");
            return ValidationReport::default();
        }
    }

    // Generate can be paired with validation to ensure the CBOR file used during validation is current
    if args.generate {
        generate(args, &mut cps, &mut pe).await;
    }

    // if there's nothing to validate, there is nothing further to do
    if args.end_entity_folder.is_none()
        && args.end_entity_file.is_none()
        && args.ee_inputs.is_empty()
    {
        return ValidationReport::default();
    }

    if !ta_store_added {
        #[cfg(feature = "webpki")]
        error!("One of the ta_cbor, ta_folder, ta_inputs or webpki arguments must be provided");

        #[cfg(not(feature = "webpki"))]
        error!("One of the ta_cbor, ta_folder or ta_inputs arguments must be provided");
        return ValidationReport::default();
    };

    // Built once and threaded through, rather than derived per target: it carries the revocation
    // artifacts the run was handed, and reading those again for every certificate would read the
    // same files once per target.
    let mut validate_opts = ValidateOpts::from_args(args);
    #[cfg(feature = "revocation")]
    {
        let supplied = load_revocation_inputs(args.rev_inputs.iter().map(String::as_str));
        if !supplied.is_empty() {
            info!(
                "Read {} CRL(s) and {} OCSP response(s) to staple into candidate paths",
                supplied.crls.len(),
                supplied.ocsp_responses.len()
            );
        }
        validate_opts.crls = supplied.crls;
        validate_opts.ocsp_responses = supplied.ocsp_responses;
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

    // Number of certificates the CA folder contributed to the graph, used after the loop to tell a
    // folder that yielded nothing from no folder at all.
    let mut ca_folder_certs = 0;

    // Whether the graph came off the cache rather than being built. Its identity was settled
    // before the settings were adjusted for the run — see `graph_fingerprint` above.
    let mut graph_from_cache = false;

    // Whether the CA input was a CBOR store adopted with the partial paths it carries, which means
    // the graph is already built and searching again would recompute it.
    let mut ca_store_paths_adopted = false;

    // Start the clock for entire set of validation actions
    let start = Instant::now();

    #[cfg(all(feature = "std", feature = "revocation"))]
    let crl_source = match &args.crl_folder {
        Some(crl_folder) => {
            let crl_source =
                CrlSourceFolders::with_options(crl_folder, args.keep_crl_entries_in_memory);
            match crl_source.index_crls(cps.get_time_of_interest()) {
                Ok(_) => Some(std::sync::Arc::new(crl_source)),
                Err(e) => {
                    error!("Failed to index CRL source with {e}");
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
    if let Some(remote_status) = remote_status {
        pe.add_check_remote(Box::new(remote_status));
    }
    // The CrlSourceFolders serves CRLs (as a CrlSource) and, when keep_crl_entries_in_memory is set,
    // answers revocation status from its retained CRL serials (as a RevocationStatusCache). Register
    // it in both roles via a shared Arc, with its revocation cache FIRST so the kept fast path is
    // consulted before the per-certificate memo. A RevocationCache is always registered as that memo
    // for OCSP determinations and anything not covered by a kept CRL.
    #[cfg(all(feature = "std", feature = "revocation"))]
    {
        if let Some(crl_source) = crl_source {
            pe.add_crl_source(Box::new(crl_source.clone()));
            pe.add_revocation_cache(Box::new(crl_source));
        }
        pe.add_revocation_cache(Box::new(RevocationCache::new()));
    }

    // Opened once rather than per pass: opening snapshots what the store already holds, which is a
    // read of every certificate in it, and that answer does not change under us — this process is
    // the only thing adding to it during the run.
    #[cfg(feature = "capi")]
    let mut capi_sink = match &args.capi_ca_store_rw {
        Some(spec) => match parse_capi_stores(std::slice::from_ref(spec)).and_then(|s| {
            CapiCertStore::open_rw(&s[0]).map_err(|e| format!("cannot open {spec}: {e:?}"))
        }) {
            Ok(sink) => Some(sink),
            Err(msg) => {
                // Refused here rather than at the first write: a dynamic build that fetched for a
                // minute and then could not keep any of it is a worse way to learn this, and the
                // usual cause -- a machine store without elevation -- is one the user can act on.
                println!("Failed to open the CAPI store to write to: {msg}");
                return ValidationReport::default();
            }
        },
        None => None,
    };

    loop {
        // Create a new CertSource and (re-)deserialize on every iteration due references to
        // buffers in the certs member. On the first pass, cbor will contain data read from file,
        // on subsequent passes it will contain a fresh CBOR blob that features buffers downloaded
        // from AIA or SIA locations.
        let mut cert_source = if cbor.is_empty() {
            // Empty CBOR is fine when doing dynamic building, when the intermediates come from a
            // CA folder, or when validating certificates issued by a trust anchor. Only worth
            // saying when a store was actually named: a run that supplied none is not missing one.
            if 0 == pass && !cbor_file.is_empty() {
                info!("Empty CBOR file at {cbor_file}. Proceeding without it.");
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
                        "Failed to parse CBOR file at {cbor_file} with: {e}. Proceeding without it."
                    );
                    CertSource::default()
                }
            }
        };

        // The same augmented graph as last time, when nothing it was built from has changed. What
        // is skipped is the folder walk and the partial-path search, which is the expensive half of
        // preparing a run; the certificates are still parsed, since they have to be.
        if 0 == pass && !graph_from_cache {
            if let Some(cached) = graph_fingerprint.as_deref().and_then(graph_cache::load) {
                match CertSource::new_from_cbor(cached.as_slice()) {
                    Ok(from_cache) => {
                        cert_source = from_cache;
                        graph_from_cache = true;
                    }
                    Err(e) => debug!("Ignoring an unusable cached graph: {e:?}"),
                }
            }
        }

        // A CA folder is the intermediates the user already has, and it fed generation only: at
        // validation time the graph came from the CBOR store alone, so -t tas -c cas -e ee.der
        // found no paths at all and the folder had to be compiled into a store first. Fold it into
        // the graph here so it is a validation input in its own right; a store supplied alongside
        // it is augmented rather than displaced, since both are just certificates to build from. A
        // generate run is exempt because the CBOR read above was built from this same folder.
        if 0 == pass && !args.generate && !graph_from_cache {
            // Where downloaded intermediates land, when the run was asked to reuse them. Last in the
            // order so it augments what was named explicitly rather than being mistaken for the
            // whole CA input: a store named in the pool still gets its partial paths adopted.
            #[cfg(feature = "remote")]
            let reuse_downloads = match args.use_downloaded_cas && !download_folder.is_empty() {
                true => Some(download_folder.clone()),
                false => None,
            };
            #[cfg(not(feature = "remote"))]
            let reuse_downloads: Option<String> = None;

            // The singular argument first, then the pool, so a log read top to bottom follows the
            // order the inputs were named in.
            let outcome = load_ca_inputs(
                &pe,
                args.ca_folder
                    .iter()
                    .chain(args.ca_inputs.iter())
                    .chain(reuse_downloads.iter())
                    .map(String::as_str),
                &mut cert_source,
                cps.get_time_of_interest(),
            );
            ca_folder_certs = outcome.certs;
            ca_store_paths_adopted = outcome.paths_adopted;

            // After the path-shaped inputs, because adopting a CBOR store's graph replaces the
            // source wholesale (see `load_ca_inputs`) and would discard anything pushed before it.
            // The writable store is read here too, so a run that will later write to it starts
            // from what earlier runs left there.
            #[cfg(feature = "capi")]
            {
                let specs: Vec<String> = args
                    .capi_ca_stores
                    .iter()
                    .chain(args.capi_ca_store_rw.iter())
                    .cloned()
                    .collect();
                match load_capi_ca_stores(&specs, &mut cert_source) {
                    Ok(added) => ca_folder_certs += added,
                    Err(msg) => {
                        println!("Failed to read CA certificates from CAPI: {msg}");
                        return ValidationReport::default();
                    }
                }
            }
        }

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
                let lmm_file = last_modified_map_file(&cps, &download_folder);
                let lmm_file = lmm_file.as_str();
                let blocklist_file = uri_blocklist_file(&cps, &download_folder);
                let blocklist_file = blocklist_file.as_str();

                // read the last modified map and blocklist once
                let mut lmm = read_last_modified_map(lmm_file);
                let mut blocklist = read_blocklist(blocklist_file);

                //let bap_ref = &mut cert_source.buffers_and_paths.buffers;
                if 1 == pass {
                    // on first dynamic action, pick up certs from downloads folder
                    if cert_folder_to_vec(
                        &pe,
                        &download_folder,
                        &mut cert_source,
                        TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
                    )
                    .is_err()
                    {
                        debug!("Encountered error reading certificates from downloads folder");
                    }
                }

                // Where the pool stood before this pass, so the certificates it fetched can be told
                // from the ones already held and only the new ones offered to the CAPI store.
                #[cfg(feature = "capi")]
                let before_fetch = cert_source.len();

                // this could likely return after fetching one URI, but once we're in the dynamic
                // building soup, we might as well fetch all.
                let r = fetch_to_buffer(
                    &pe,
                    &fresh_uris,
                    &download_folder,
                    &mut cert_source,
                    if uri_threshold == 0 {
                        0
                    } else {
                        uri_threshold - 1
                    },
                    &mut lmm,
                    &mut blocklist,
                    TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
                    cps.get_max_aia_fetch_bytes(),
                )
                .await;

                // Mirrored after the pass rather than through the sink handed to `fetch_to_buffer`,
                // because that sink is also what the builder reads from: the certificates have to
                // land in the pool whether or not the store accepts them, and a failed write should
                // cost the next run a re-fetch, not this one its path.
                #[cfg(feature = "capi")]
                if let Some(sink) = capi_sink.as_mut() {
                    for cf in cert_source.get_buffers().into_iter().skip(before_fetch) {
                        sink.push(cf);
                    }
                }

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
                    error!("Failed to fetch fresh URIs with {e:?}");
                    break;
                }
            } else if 0 < pass {
                break;
            }

            // Save the URI count before doing any validation, which will harvest new URIs
            uri_threshold = fresh_uris.len();
        }

        // Nothing arrived this pass, so there is nothing left for the loop to do. `threshold` is the
        // size of the pool this pass started with, and a path is only returned to the caller when
        // `above_threshold` finds an index at or above it, which no path can satisfy once the pool
        // has stopped growing -- so this pass would find zero paths, rebuild the same graph and
        // re-serialize it to the same bytes, and the next pass would do it again.
        //
        // The loop had no other way out of that. The fetch block above stops running once the URI
        // set stops changing, and the `break` for a non-dynamic run lives inside it, so a dynamic
        // run that has run out of URIs to chase skips the test that would have ended it and keeps
        // going until the pass cap. Whether that shows up depends on whether some other exit fires
        // first: a run that finds a definitive answer for every target leaves through the
        // `all_definitive` break below, while `--validate-all`, or any run that never finds a path,
        // stays in the loop for the full remaining passes.
        if 0 < pass && cert_source.len() == threshold {
            debug!("Nothing was added to the certificate pool on pass {pass}; stopping");
            break;
        }

        //TODO refactor to make TaSource.tas and CertSource.certs RefCells with on demand parsing
        //instead of holding all certs parsed all the time?
        let r = cert_source.initialize(&cps);
        if let Err(e) = r {
            error!("Failed to populate cert map: {e}");
            break;
        }

        // Certificates read from the CA folder arrive with no partial paths, and a path that spans
        // the folder and the store exists only once the two are searched together, so build the
        // graph here rather than take the store's serialized paths as complete. A graph off the
        // cache already carries the result of this search, which is the point of caching it, and so
        // does a store adopted whole above -- neither is cached again here, because neither was
        // built here.
        if 0 == pass && 0 < ca_folder_certs && !graph_from_cache && !ca_store_paths_adopted {
            cert_source.find_all_partial_paths(&pe, &cps);
            if let Some(fingerprint) = &graph_fingerprint {
                graph_cache::store(fingerprint, &cert_source);
            }
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
                Err(e) => error!("Failed to serialize CBOR after dynamic building with {e:?}"),
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
                        &pe,
                        &cps,
                        filename.as_str(),
                        stats_for_file,
                        &validate_opts,
                        &mut fresh_uris,
                        threshold,
                        retain.then_some(&mut retained),
                    )
                    .await;
                }
            }
        }

        if let Some(folder) = &args.end_entity_folder {
            validate_cert_folder_retaining(
                &pe,
                &cps,
                folder.as_str(),
                &mut stats,
                &validate_opts,
                &mut fresh_uris,
                threshold,
                retain.then_some(&mut retained),
            )
            .await;
        }

        // The pool, after the two singular arguments. Each entry says for itself whether it is a
        // certificate or a folder of them, where `end_entity_file` and `end_entity_folder` are told
        // apart by which argument carried them: a set of targets is assembled from both kinds at
        // once, and sorting them into two arguments first is work the run can do instead.
        for input in &args.ee_inputs {
            if Path::new(input).is_dir() {
                validate_cert_folder_retaining(
                    &pe,
                    &cps,
                    input.as_str(),
                    &mut stats,
                    &validate_opts,
                    &mut fresh_uris,
                    threshold,
                    retain.then_some(&mut retained),
                )
                .await;
                continue;
            }
            stats.init_for_target(input);
            let Some(stats_for_file) = stats.get_mut(input) else {
                continue;
            };
            // validate when validating all or we don't have a definitive answer yet
            if args.validate_all
                || (stats_for_file.valid_paths_per_target == 0 && !stats_for_file.target_is_revoked)
            {
                let _ = validate_cert_file(
                    &pe,
                    &cps,
                    input.as_str(),
                    stats_for_file,
                    &validate_opts,
                    &mut fresh_uris,
                    threshold,
                    retain.then_some(&mut retained),
                )
                .await;
            }
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

    // The one cause a zero-path run cannot read off its own environment: the folder was read and
    // filtered down to nothing, which leaves the graph as empty as no folder at all while the user
    // has every reason to believe they provided the intermediates.
    // A graph off the cache did not read the folder this run, and a graph is only cached once the
    // folder has contributed to it, so a zero count here says nothing about the folder.
    let ca_folder_empty = (args.ca_folder.is_some() || !args.ca_inputs.is_empty())
        && !args.generate
        && 0 == ca_folder_certs
        && !graph_from_cache;
    // Distinguishes "no folder was given" from "the folder was given and nothing survived reading
    // it", which the shared diagnosis cannot tell apart because both leave the environment empty
    let ta_folder_empty = args.ta_folder.is_some() && pe.get_trust_anchors().is_empty();
    // Not an "empty" predicate like the two above: the store having been used at all is what makes
    // the hint worth saying, because its contents are a moving target rather than a set the user
    // assembled.
    #[cfg(feature = "capi")]
    let capi_tas_used = !args.capi_ta_stores.is_empty();

    let mut totals = PathValidationStats::default();
    for k in stats.keys() {
        let s = &stats[k];
        info!("Stats for {k}");
        info!("\t * Paths found: {}", s.paths_per_target);
        info!("\t * Valid paths found: {}", s.valid_paths_per_target);
        info!("\t * Invalid paths found: {}", s.invalid_paths_per_target);

        // Say why the count is zero where the count is reported, not only in the structured report
        if let Some((_status, reason)) = &s.no_path_reason {
            info!("\t * No certification path was found because of the target itself: {reason}");
        }
        if 0 == s.paths_per_target {
            for hint in &s.no_paths_hints {
                info!("\t * {hint}");
            }
            if !s.no_paths_hints.is_empty() && ta_folder_empty {
                info!("\t * {TA_FOLDER_EMPTY}");
            }
            if !s.no_paths_hints.is_empty() && ca_folder_empty {
                info!("\t * {CA_FOLDER_EMPTY}");
            }
            #[cfg(feature = "capi")]
            if !s.no_paths_hints.is_empty() && capi_tas_used {
                info!("\t * {CAPI_TA_STORE_PARTIAL}");
            }
        }
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

    debug!("Args: {args:?}");

    info!(
        "{:?} to deserialize graph and perform build and validation operation(s) for {} file(s)",
        duration,
        stats.keys().len()
    );

    // assemble the structured report from the accumulated per-target stats; the target summary is
    // drawn from the last certificate of a processed path (i.e., the target certificate)
    let mut report = ValidationReport {
        targets: vec![],
        totals: ReportTotals::default(),
        time_of_interest: cps.get_time_of_interest().as_unix_secs(),
        duration_ms: duration.as_millis() as u64,
        error: None,
    };
    for (name, s) in stats.iter_mut() {
        let paths_found = s.paths_per_target > 0;
        let path_reports = core::mem::take(&mut s.path_reports);
        // A target that never yielded a path is reported as why rather than rolled up from path
        // results it has none of
        let (status, error) = match s.no_path_reason.take() {
            Some((status, reason)) => (status, Some(reason)),
            None => (
                TargetReport::compute_status(&path_reports, paths_found),
                None,
            ),
        };
        let target_summary = s
            .target_summary
            .clone()
            .or_else(|| path_reports.iter().find_map(|p| p.certs.last().cloned()));

        let mut no_paths_hints = core::mem::take(&mut s.no_paths_hints);
        if !no_paths_hints.is_empty() && ta_folder_empty {
            no_paths_hints.push(TA_FOLDER_EMPTY.to_string());
        }
        if !no_paths_hints.is_empty() && ca_folder_empty {
            no_paths_hints.push(CA_FOLDER_EMPTY.to_string());
        }
        #[cfg(feature = "capi")]
        if !no_paths_hints.is_empty() && capi_tas_used {
            no_paths_hints.push(CAPI_TA_STORE_PARTIAL.to_string());
        }

        report.totals.targets += 1;
        report.totals.paths_found += s.paths_per_target;
        report.totals.valid_paths += s.valid_paths_per_target;
        report.totals.invalid_paths += s.invalid_paths_per_target;

        report.targets.push(TargetReport {
            name: name.clone(),
            target: target_summary,
            status,
            paths: path_reports,
            no_paths_hints,
            error,
        });
    }
    // The environment goes back with the paths when the caller asked to retain: the certificates
    // travel with a path but the CRLs behind a status do not, and those are recovered from the
    // sources registered here. Certificate sources were cleared above once building finished, which
    // an export does not need -- it names artifacts, it does not build further paths.
    if let Some(slot) = kept {
        *slot = Some(RetainedRun {
            environment: pe,
            paths: retained,
        });
    }
    report
}

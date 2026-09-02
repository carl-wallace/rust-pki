//! Command line arguments for the Pittv3 utility

use clap::Parser;

use pittv3_lib::args::{get_now_as_unix_epoch, Pittv3Args};

/// PKI Interoperability Test Tool v3 (PITTv3)
#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
#[clap(author, version, about, long_about = None)]
pub struct Pittv3CliArgs {
    /// Full path of a folder containing binary DER-encoded trust anchors, or of a single such file,
    /// to use when generating CBOR file containing partial certification paths and when validating
    /// certification paths. A file may hold several concatenated PEM objects.
    #[cfg(feature = "std")]
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    pub ta_folder: Option<String>,

    /// Full path and filename of a CBOR-formatted trust anchor store, i.e., the form written by
    /// --generate --cbor-ta-store and the form the certval trust store providers serialize. This is
    /// the trust anchor counterpart of --cbor; it may be combined with --ta-folder, in which case
    /// the anchors from both are used.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "COMMON OPTIONS")]
    pub ta_cbor: Option<String>,

    /// Additional trust anchor input, repeatable. Each occurrence may name a folder, a
    /// certificate, a bundle holding several, or a CBOR-formatted trust anchor store; what it is
    /// comes from the path and then from the bytes, so the four need not be sorted into different
    /// arguments first. This is the plural form of --ta-folder and --ta-cbor, which still work and
    /// are used alongside it.
    #[cfg(feature = "std")]
    #[clap(long = "ta", value_name = "TA_INPUT", help_heading = "COMMON OPTIONS")]
    pub ta_inputs: Vec<String>,

    /// Use trust anchors from webpki-roots crate (which are from Mozilla)
    #[cfg(feature = "webpki")]
    #[clap(long, help_heading = "COMMON OPTIONS")]
    pub webpki_tas: bool,

    /// Microsoft CryptoAPI store to read trust anchors from, named Location\Name, e.g.
    /// LocalMachine\ROOT, or as a bare store name for a current-user store. May be given more than
    /// once; the anchors are combined with those from the other trust anchor options. Machine
    /// stores need an elevated process. Note that CurrentUser\ROOT already includes the machine's
    /// anchors.
    #[cfg(all(windows, feature = "capi"))]
    #[clap(
        long = "capi-ta",
        value_name = "CAPI_STORE",
        help_heading = "COMMON OPTIONS"
    )]
    pub capi_ta_stores: Vec<String>,

    /// Microsoft CryptoAPI store to read intermediate CA certificates from, named as for
    /// --capi-ta. May be given more than once.
    #[cfg(all(windows, feature = "capi"))]
    #[clap(
        long = "capi-ca",
        value_name = "CAPI_STORE",
        help_heading = "COMMON OPTIONS"
    )]
    pub capi_ca_stores: Vec<String>,

    /// Microsoft CryptoAPI store that dynamic building writes fetched certificates into, named as
    /// for --capi-ta, so a later run starts from what this one found. Read at the start of the run
    /// as --capi-ca would be. Requires --dynamic-build to have anything to write.
    #[cfg(all(windows, feature = "capi"))]
    #[clap(
        long = "capi-ca-rw",
        value_name = "CAPI_STORE",
        help_heading = "COMMON OPTIONS"
    )]
    pub capi_ca_store_rw: Option<String>,

    /// Full path and filename of file to provide and/or receive CBOR-formatted representation of
    /// buffers containing binary DER-encoded CA certificates and map containing set of partial
    /// certification paths.
    #[cfg(feature = "std")]
    #[clap(long, short = 'b', help_heading = "COMMON OPTIONS")]
    pub cbor: Option<String>,

    /// Time to use for path validation expressed as the number of seconds since Unix epoch
    /// (defaults to current system time).
    #[clap(short = 'i', long, default_value_t = get_now_as_unix_epoch(), help_heading = "COMMON OPTIONS")]
    pub time_of_interest: u64,

    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See <https://docs.rs/log4rs/latest/log4rs/> for details.
    #[cfg(feature = "std_app")]
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    pub logging_config: Option<String>,

    /// Full path of folder to receive binary DER-encoded certificates from paths that fail path
    /// validation. If absent, errant files are not saved for review.
    #[cfg(feature = "std_app")]
    #[clap(long, short = 'o', help_heading = "COMMON OPTIONS")]
    pub error_folder: Option<String>,

    /// Full path and filename of folder to receive downloaded binary DER-encoded certificates, if
    /// absent at generate time, the ca_folder is used, which requires it to name a folder rather
    /// than a single file. Additionally, this is used to designate where exported buffers are
    /// written by dump_cert_at_index or list_buffers.
    #[cfg(feature = "std")]
    #[clap(long, short, help_heading = "COMMON OPTIONS")]
    pub download_folder: Option<String>,

    /// Full path of a folder containing binary, DER-encoded intermediate CA certificates, or of a
    /// single such file (which may hold several concatenated PEM objects, e.g. a fullchain).
    /// Required when generate action is performed. When path validation is performed, these
    /// certificates are added to the graph that is built, augmenting any CBOR store in use. A folder
    /// also doubles as a place to store downloaded files when dynamic building is used and
    /// download_folder is not specified.
    #[cfg(feature = "std")]
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    pub ca_folder: Option<String>,

    /// Additional intermediate CA input, repeatable. Each occurrence may name a folder, a
    /// certificate, a bundle holding several, or a CBOR-formatted store, and all of them feed the
    /// one graph a run builds. This is the plural form of --ca-folder and --cbor for validation.
    /// It is not consulted when generating: --ca-folder names the folder generation reads, and
    /// --cbor the file it writes.
    #[cfg(feature = "std")]
    #[clap(long = "ca", value_name = "CA_INPUT", help_heading = "COMMON OPTIONS")]
    pub ca_inputs: Vec<String>,

    /// Flag that indicates a fresh CBOR-formatted file containing buffers of CA certificates and
    /// map containing set of partial certification paths should be generated and saved to location
    /// indicated by cbor parameter.
    #[cfg(feature = "std")]
    #[clap(short = 'g', long, help_heading = "GENERATION")]
    pub generate: bool,

    /// Flag that indicates whether AIA and SIA URIs should be consulted when performing generate
    /// action.
    #[cfg(feature = "remote")]
    #[clap(short = 'a', long, help_heading = "GENERATION")]
    pub chase_aia_and_sia: bool,

    /// Flag that indicates generated CBOR file will contain only trust anchors  (so no need for
    /// partial paths and no need to exclude self-signed certificates). The anchors are read from
    /// the ca_folder input, which may name a single file, and the result is the form ta_cbor takes.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "GENERATION")]
    pub cbor_ta_store: bool,

    /// Include the folder downloaded intermediates are written to among the CA certificates a run
    /// builds paths from, so certificates fetched by earlier runs are reused rather than fetched
    /// again. The folder is --download-folder if given, otherwise --ca-folder, either of which may
    /// come from the settings file.
    #[cfg(feature = "remote")]
    #[clap(long, help_heading = "VALIDATION")]
    pub use_downloaded_cas: bool,

    /// Flag that indicates all available certification paths should be validated for each target.
    #[cfg(feature = "std_app")]
    #[clap(short, long, help_heading = "VALIDATION")]
    pub validate_all: bool,

    /// Check if certificate passed as end_entity_file is self-signed.
    #[cfg(feature = "std_app")]
    #[clap(long, help_heading = "VALIDATION")]
    pub validate_self_signed: bool,

    /// Flag that indicates all available certification paths compiled into the app should be
    /// validated for each target, instead of stopping after finding first valid path.
    #[cfg(not(feature = "std_app"))]
    #[clap(long, help_heading = "VALIDATION")]
    pub validate_all: bool,

    /// Process AIA and SIA during path validation, as appropriate. Either ca_folder or
    /// download_folder must be specified when using this flag to provide a place to store
    /// downloaded artifacts.
    #[cfg(feature = "remote")]
    #[clap(short = 'y', long, help_heading = "VALIDATION")]
    pub dynamic_build: bool,

    /// Full path and filename of a binary DER-encoded certificate to validate.
    #[cfg(feature = "std_app")]
    #[clap(short, long, help_heading = "VALIDATION")]
    pub end_entity_file: Option<String>,

    /// Full path folder to recursively traverse for binary DER-encoded certificates to validate.
    /// Only files with .der, .crt or cert as file extension are processed.
    #[cfg(feature = "std")]
    #[clap(long, short = 'f', help_heading = "VALIDATION")]
    pub end_entity_folder: Option<String>,

    /// Additional certificate to validate, repeatable. Each occurrence may name a single
    /// certificate or a folder to traverse for them. This is the plural form of --end-entity-file
    /// and --end-entity-folder, which still work and are validated alongside it.
    #[cfg(feature = "std")]
    #[clap(long = "ee", value_name = "EE_INPUT", help_heading = "VALIDATION")]
    pub ee_inputs: Vec<String>,

    /// Full path and filename of folder to receive binary DER-encoded certificates from certification
    /// paths. Folders will be created beneath this using a hash of the target certificate. Within
    /// that folder, folders will be created with a number indicating each path, i.e., the number
    /// indicates the order in which the path was returned for consideration. For best results, this
    /// folder should be cleaned in between runs. PITTv3 does not perform hygiene on this folder or
    /// its contents.
    #[cfg(feature = "std_app")]
    #[clap(long, short, help_heading = "VALIDATION")]
    pub results_folder: Option<String>,

    /// Full path and filename of JSON-formatted certification path validation settings.
    #[cfg(feature = "std")]
    #[clap(long, short, help_heading = "VALIDATION")]
    pub settings: Option<String>,

    /// Full path of a folder containing DER- or PEM-encoded CRLs, traversed recursively and indexed
    /// before path validation begins. Only files with a .crl extension are processed. The indexed
    /// CRLs are the local revocation source, consulted before any remote retrieval, and the folder
    /// also receives CRLs fetched remotely along with the last-modified map that makes those
    /// fetches conditional. Note that the folder is written as well as read, though only added to:
    /// a CRL that does not cover the time of interest is left out of the index and left on disk, so
    /// a later run asking about a different time can still use it.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "VALIDATION")]
    pub crl_folder: Option<String>,

    /// Revocation artifact to staple into candidate certification paths, repeatable. Each
    /// occurrence may name a single artifact or a folder to traverse, and may hold either a CRL or
    /// an OCSP response — the bytes decide, since an OCSP response has no settled file extension.
    /// CRLs are matched to path positions by issuer name, OCSP responses by the CertID each answers
    /// about. Unlike --crl-folder, which is an index a run adds fetched CRLs to, artifacts named
    /// here are read and left alone.
    #[cfg(all(feature = "std", feature = "revocation"))]
    #[clap(long = "rev", value_name = "REV_INPUT", help_heading = "VALIDATION")]
    pub rev_inputs: Vec<String>,

    /// When set together with --crl-folder, retain the revoked serial numbers of each verified
    /// full/direct CRL in memory so subsequent certificates under the same scope are answered
    /// without re-parsing or re-verifying the CRL.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "VALIDATION")]
    pub keep_crl_entries_in_memory: bool,

    /// Makes every path derive every certificate's revocation status from revocation data of its
    /// own, instead of reusing a determination reached while validating an earlier path. Costs
    /// re-fetching; buys a path that accounts for itself, and artifacts for every position, since a
    /// cached determination examines nothing and leaves nothing behind.
    #[cfg(all(feature = "std", feature = "revocation"))]
    #[clap(long, help_heading = "VALIDATION")]
    pub no_revocation_cache: bool,

    /// Paired with ca_folder to remove expired, unparseable certificates, self-signed
    /// certificates and non-CA certificates from consideration. When paired with error_folder,
    /// the errant files are moved instead of deleted. After cleanup completes, the application
    /// exits with no other parameters acted upon.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "CLEANUP")]
    pub cleanup: bool,

    /// Paired with ta_folder to remove expired or unparseable certificatesfrom consideration. When
    /// paired with error_folder, the errant files are moved instead of deleted. After cleanup
    /// completes, the application exits with no other parameters acted upon.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "CLEANUP")]
    pub ta_cleanup: bool,

    /// Pair with cleanup to generate list of files that would be cleaned up by cleanup operation
    /// without actually deleting or moving files.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "CLEANUP")]
    pub report_only: bool,

    /// Outputs all partial paths present in CBOR file. If a ta_folder is provided, the CBOR file
    /// will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of
    /// partial paths relative to that read from CBOR). Use of a logging-config option is recommended
    /// for large CBOR files.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "DIAGNOSTICS")]
    pub list_partial_paths: bool,

    /// Outputs all buffers present in CBOR file.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "DIAGNOSTICS")]
    pub list_buffers: bool,

    /// Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file. Add
    /// downloads_folder to save certificates that are valid as of time_of_interest from the
    /// downloaded artifacts (use time_of_interest=0 to download all). Specify a blocklist or
    /// last_modified_map if desired via CertificationPathSettings or rely on default files that
    /// will be generated and managed in folder used to download artifacts.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "DIAGNOSTICS")]
    pub list_aia_and_sia: bool,

    /// Outputs all name constraints found in certificates present in CBOR file.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "DIAGNOSTICS")]
    pub list_name_constraints: bool,

    /// Outputs all buffers present in trust anchors folder.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "DIAGNOSTICS")]
    pub list_trust_anchors: bool,

    /// Outputs the certificate at the specified index to a file names `<index>.der` in the
    /// download_folder if specified, else current working directory.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "DIAGNOSTICS")]
    pub dump_cert_at_index: Option<usize>,

    /// Outputs all partial paths present in CBOR file relative to the indicated target. If a
    /// ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
    /// time_of_interest (possibly changing the set of partial paths relative to that read from CBOR).
    #[cfg(feature = "std")]
    #[clap(short = 'z', long, help_heading = "DIAGNOSTICS")]
    pub list_partial_paths_for_target: Option<String>,

    /// Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If a
    /// ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
    /// time_of_interest (possibly changing the set of partial paths relative to that read from CBOR).
    #[cfg(feature = "std")]
    #[clap(short = 'p', long, help_heading = "DIAGNOSTICS")]
    pub list_partial_paths_for_leaf_ca: Option<usize>,

    /// Parses the given CSV file and saves files to folder indicated by the ca_folder parameter. The
    /// CSV file is assumed to be as posted as the "Non-revoked, non-expired Intermediate CA Certificates
    /// chaining up to roots in Mozilla's program with the Websites trust bit set (CSV with PEM of raw
    /// certificate data)" report available on the Mozilla wiki page at <https://wiki.mozilla.org/CA/Intermediate_Certificates>.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "TOOLS")]
    pub mozilla_csv: Option<String>,

    /// Checks the HTTP URIs in the AIA, SIA, CRL DP and freshest-CRL extensions of the certificate at
    /// the given path, reporting per-URI reachability and correctness. Runs independently of path
    /// processing; no CBOR store or trust anchors are required.
    #[cfg(feature = "remote")]
    #[clap(long, help_heading = "TOOLS")]
    pub check_uris: Option<String>,

    /// Optional issuer certificate (path) for --check-uris, used to verify CRL signatures and check
    /// OCSP URIs. Auto-discovered from AIA caIssuers when omitted.
    #[cfg(feature = "remote")]
    #[clap(long, help_heading = "TOOLS")]
    pub issuer: Option<String>,

    /// Disables auto-discovery of the issuer certificate from AIA caIssuers during --check-uris.
    #[cfg(feature = "remote")]
    #[clap(long, help_heading = "TOOLS")]
    pub no_auto_discover: bool,
}

impl From<Pittv3CliArgs> for Pittv3Args {
    fn from(v: Pittv3CliArgs) -> Self {
        #[allow(clippy::needless_update)]
        Pittv3Args {
            #[cfg(feature = "std")]
            ta_folder: v.ta_folder,
            #[cfg(feature = "std")]
            ta_cbor: v.ta_cbor,
            #[cfg(feature = "std")]
            ta_inputs: v.ta_inputs,
            #[cfg(feature = "webpki")]
            webpki_tas: v.webpki_tas,
            #[cfg(all(windows, feature = "capi"))]
            capi_ta_stores: v.capi_ta_stores,
            #[cfg(all(windows, feature = "capi"))]
            capi_ca_stores: v.capi_ca_stores,
            #[cfg(all(windows, feature = "capi"))]
            capi_ca_store_rw: v.capi_ca_store_rw,
            #[cfg(feature = "std")]
            cbor: v.cbor,
            time_of_interest: v.time_of_interest,
            #[cfg(feature = "std_app")]
            logging_config: v.logging_config,
            #[cfg(feature = "std_app")]
            error_folder: v.error_folder,
            #[cfg(feature = "std")]
            download_folder: v.download_folder,
            #[cfg(feature = "std")]
            ca_folder: v.ca_folder,
            #[cfg(feature = "std")]
            ca_inputs: v.ca_inputs,
            #[cfg(feature = "std")]
            generate: v.generate,
            #[cfg(feature = "remote")]
            chase_aia_and_sia: v.chase_aia_and_sia,
            #[cfg(feature = "std")]
            cbor_ta_store: v.cbor_ta_store,
            validate_all: v.validate_all,
            #[cfg(feature = "std_app")]
            validate_self_signed: v.validate_self_signed,
            #[cfg(feature = "remote")]
            dynamic_build: v.dynamic_build,
            #[cfg(feature = "remote")]
            use_downloaded_cas: v.use_downloaded_cas,
            #[cfg(feature = "std_app")]
            end_entity_file: v.end_entity_file,
            #[cfg(feature = "std")]
            end_entity_folder: v.end_entity_folder,
            #[cfg(feature = "std")]
            ee_inputs: v.ee_inputs,
            #[cfg(feature = "std_app")]
            results_folder: v.results_folder,
            #[cfg(feature = "std")]
            settings: v.settings,
            #[cfg(feature = "std")]
            crl_folder: v.crl_folder,
            #[cfg(all(feature = "std", feature = "revocation"))]
            rev_inputs: v.rev_inputs,
            #[cfg(feature = "std")]
            keep_crl_entries_in_memory: v.keep_crl_entries_in_memory,
            #[cfg(all(feature = "std", feature = "revocation"))]
            no_revocation_cache: v.no_revocation_cache,
            #[cfg(feature = "std")]
            cleanup: v.cleanup,
            #[cfg(feature = "std")]
            ta_cleanup: v.ta_cleanup,
            #[cfg(feature = "std")]
            report_only: v.report_only,
            #[cfg(feature = "std")]
            list_partial_paths: v.list_partial_paths,
            #[cfg(feature = "std")]
            list_buffers: v.list_buffers,
            #[cfg(feature = "std")]
            list_aia_and_sia: v.list_aia_and_sia,
            #[cfg(feature = "std")]
            list_name_constraints: v.list_name_constraints,
            #[cfg(feature = "std")]
            list_trust_anchors: v.list_trust_anchors,
            #[cfg(feature = "std")]
            dump_cert_at_index: v.dump_cert_at_index,
            #[cfg(feature = "std")]
            list_partial_paths_for_target: v.list_partial_paths_for_target,
            #[cfg(feature = "std")]
            list_partial_paths_for_leaf_ca: v.list_partial_paths_for_leaf_ca,
            #[cfg(feature = "std")]
            mozilla_csv: v.mozilla_csv,
            #[cfg(feature = "remote")]
            check_uris: v.check_uris,
            #[cfg(feature = "remote")]
            issuer: v.issuer,
            #[cfg(feature = "remote")]
            no_auto_discover: v.no_auto_discover,
            // pittv3-lib's feature set is a superset of ours -- ours forward to it and cargo only
            // ever adds -- so it can carry fields this initializer does not name. Let those default
            // rather than tracking a shape we cannot see.
            ..Default::default()
        }
    }
}

//! Arguments for the Pittv3 utility

use serde::{Deserialize, Serialize};

#[cfg(feature = "std_app")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Arguments that govern a PITTv3 run.
///
/// A plain data structure, so a GUI can populate it directly and save it. With the `clap` feature it
/// is also the `pittv3` command line: each field is an option spelled in kebab case (`ta_folder` is
/// `--ta-folder`), and the descriptions below use those option names. The binary supplies its own
/// name, version and description when it builds the command, since the ones a derive here would read
/// belong to this crate.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "clap", command(arg_required_else_help(true)))]
pub struct Pittv3Args {
    /// Full path of a folder containing binary DER-encoded trust anchors, or of a single such file,
    /// to use when generating CBOR file containing partial certification paths and when validating
    /// certification paths. A file may hold several concatenated PEM objects.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(short, long, help_heading = "COMMON OPTIONS"))]
    pub ta_folder: Option<String>,

    /// Full path and filename of a CBOR-formatted trust anchor store, i.e., the form written by
    /// --generate --cbor-ta-store and the form the certval trust store providers serialize. This is
    /// the trust anchor counterpart of --cbor; it may be combined with --ta-folder, in which case
    /// the anchors from both are used.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "COMMON OPTIONS"))]
    pub ta_cbor: Option<String>,

    /// Additional trust anchor input, repeatable. Each occurrence may name a folder, a
    /// certificate, a bundle holding several, or a CBOR-formatted trust anchor store; what it is
    /// comes from the path and then from the bytes, so the four need not be sorted into different
    /// arguments first. This is the plural form of --ta-folder and --ta-cbor, which still work and
    /// are used alongside it.
    ///
    /// The anchors from every entry are combined into one store. It exists because a trust anchor
    /// set is often assembled from several places at once.
    #[cfg(feature = "std")]
    #[serde(default)]
    #[cfg_attr(
        feature = "clap",
        arg(long = "ta", value_name = "TA_INPUT", help_heading = "COMMON OPTIONS")
    )]
    pub ta_inputs: Vec<String>,

    /// Use trust anchors from webpki-roots crate (which are from Mozilla)
    #[cfg(feature = "webpki")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "COMMON OPTIONS"))]
    pub webpki_tas: bool,

    /// Microsoft CryptoAPI store to read trust anchors from, named Location\Name -- usually
    /// CurrentUser\ROOT or LocalMachine\ROOT -- or as a bare store name for a current-user store.
    /// May be given more than once; the anchors are combined with those from the other trust anchor
    /// options. Machine stores need an elevated process. Note that CurrentUser\ROOT already
    /// includes the machine's anchors.
    ///
    /// Naming both locations is harmless, since the certificates are deduplicated, but rarely
    /// necessary.
    #[cfg(all(windows, feature = "capi"))]
    #[serde(default)]
    #[cfg_attr(
        feature = "clap",
        arg(
            long = "capi-ta",
            value_name = "CAPI_STORE",
            help_heading = "COMMON OPTIONS"
        )
    )]
    pub capi_ta_stores: Vec<String>,

    /// Microsoft CryptoAPI store to read intermediate CA certificates from, named as for
    /// --capi-ta and usually CurrentUser\CA or LocalMachine\CA. May be given more than once to
    /// target different CAPI stores. Read-only, and combined with the certificates from the other
    /// CA options.
    #[cfg(all(windows, feature = "capi"))]
    #[serde(default)]
    #[cfg_attr(
        feature = "clap",
        arg(
            long = "capi-ca",
            value_name = "CAPI_STORE",
            help_heading = "COMMON OPTIONS"
        )
    )]
    pub capi_ca_stores: Vec<String>,

    /// Microsoft CryptoAPI store that dynamic building writes fetched certificates into, named as
    /// for --capi-ta and usually CurrentUser\CA, so a later run starts from what this one found.
    /// Read at the start of the run as --capi-ca would be. Requires --dynamic-build to have
    /// anything to write, and a machine store needs an elevated process to write to.
    #[cfg(all(windows, feature = "capi"))]
    #[cfg_attr(
        feature = "clap",
        arg(
            long = "capi-ca-rw",
            value_name = "CAPI_STORE",
            help_heading = "COMMON OPTIONS"
        )
    )]
    pub capi_ca_store_rw: Option<String>,

    /// Full path and filename of file to provide and/or receive CBOR-formatted representation of
    /// buffers containing binary DER-encoded CA certificates and map containing set of partial
    /// certification paths.
    #[cfg(feature = "std")]
    #[cfg_attr(
        feature = "clap",
        arg(long, short = 'b', help_heading = "COMMON OPTIONS")
    )]
    pub cbor: Option<String>,

    /// Time to use for path validation expressed as the number of seconds since Unix epoch
    /// (defaults to current system time).
    #[cfg_attr(
        feature = "clap",
        arg(short = 'i', long, default_value_t = get_now_as_unix_epoch(), help_heading = "COMMON OPTIONS")
    )]
    pub time_of_interest: u64,

    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See <https://docs.rs/log4rs/latest/log4rs/> for details.
    #[cfg(feature = "std_app")]
    #[cfg_attr(feature = "clap", arg(short, long, help_heading = "COMMON OPTIONS"))]
    pub logging_config: Option<String>,

    /// Full path of folder to receive binary DER-encoded certificates from paths that fail path
    /// validation. If absent, errant files are not saved for review.
    #[cfg(feature = "std_app")]
    #[cfg_attr(
        feature = "clap",
        arg(long, short = 'o', help_heading = "COMMON OPTIONS")
    )]
    pub error_folder: Option<String>,

    /// Full path and filename of folder to receive downloaded binary DER-encoded certificates, if
    /// absent at generate time, --ca-folder is used, which requires it to name a folder rather
    /// than a single file. Additionally, this is used to designate where exported buffers are
    /// written by --dump-cert-at-index or --list-buffers.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, short, help_heading = "COMMON OPTIONS"))]
    pub download_folder: Option<String>,

    /// Full path of a folder containing binary, DER-encoded intermediate CA certificates, or of a
    /// single such file (which may hold several concatenated PEM objects, e.g. a fullchain).
    /// Required when the generate action is performed unless --ca names material instead, and
    /// combined with it when both are given. When path validation is performed, these
    /// certificates are added to the graph that is built, augmenting any CBOR store in use. A folder
    /// also doubles as a place to store downloaded files when dynamic building is used and
    /// --download-folder is not specified.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(short, long, help_heading = "COMMON OPTIONS"))]
    pub ca_folder: Option<String>,

    /// Additional intermediate CA input, repeatable. Each occurrence may name a folder, a
    /// certificate, a bundle holding several, or a CBOR-formatted store (whose partial paths are
    /// adopted along with its certificates), and all of them feed the one graph a run builds. This
    /// is the plural form of --ca-folder and --cbor.
    ///
    /// It is consulted when generating as well, where it is how a store is made out of the stores
    /// that already exist: naming several puts their certificates in one pool, and the partial
    /// paths are then discovered over that pool rather than adopted from any one of them. A path
    /// that leaves one PKI and re-enters another exists only once they are searched together, so
    /// the merged store finds paths none of its inputs carried. --cbor still names the file
    /// written.
    ///
    /// --ca-folder also names where --mozilla-csv saves certificates and where dynamic building
    /// stores what it downloads when --download-folder is absent, which this input cannot take on.
    #[cfg(feature = "std")]
    #[serde(default)]
    #[cfg_attr(
        feature = "clap",
        arg(long = "ca", value_name = "CA_INPUT", help_heading = "COMMON OPTIONS")
    )]
    pub ca_inputs: Vec<String>,

    /// Flag that indicates a fresh CBOR-formatted file containing buffers of CA certificates and
    /// map containing set of partial certification paths should be generated and saved to location
    /// indicated by --cbor. The certificates come from --ca-folder, from every --ca input, or from
    /// both; the anchors the partial paths end at come from the trust anchor inputs as usual.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(short = 'g', long, help_heading = "GENERATION"))]
    pub generate: bool,

    /// Flag that indicates generated CBOR file will contain only trust anchors (so no need for
    /// partial paths and no need to exclude self-signed certificates). The anchors are read from
    /// --ca-folder, which may name a single file, and the result is the form --ta-cbor takes.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "GENERATION"))]
    pub cbor_ta_store: bool,

    /// Include the folder downloaded intermediates are written to among the CA certificates a run
    /// builds paths from, so certificates fetched by earlier runs are reused rather than fetched
    /// again. The folder is --download-folder if given, otherwise --ca-folder, either of which may
    /// come from the settings file.
    ///
    /// Naming that folder with --ca does the same thing; this exists because the folder is
    /// configured elsewhere, so an input naming it goes stale the moment it is reconfigured.
    #[cfg(feature = "remote")]
    #[serde(default)]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub use_downloaded_cas: bool,

    /// Flag that indicates all available certification paths should be validated for each target.
    #[cfg(feature = "std_app")]
    #[cfg_attr(feature = "clap", arg(short, long, help_heading = "VALIDATION"))]
    pub validate_all: bool,

    /// Run the URI checker over every certificate on each validated path, appending the results to
    /// that path's log. Each distinct certificate is checked once per run and reported in every
    /// path it appears on. Trust anchors are scanned for their SIA only, having no issuer to name
    /// and no revocation a run consults. Requires network access.
    #[cfg(all(feature = "std_app", feature = "remote"))]
    #[serde(default)]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub check_uris_when_validating: bool,

    /// Check if certificate passed as --end-entity-file is self-signed.
    #[cfg(feature = "std_app")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub validate_self_signed: bool,

    /// Flag that indicates all available certification paths compiled into the app should be
    /// validated for each target, instead of stopping after finding first valid path.
    #[cfg(not(feature = "std_app"))]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub validate_all: bool,

    /// Process AIA and SIA during path validation, as appropriate. Either --ca-folder or
    /// --download-folder must be specified when using this flag to provide a place to store
    /// downloaded artifacts.
    #[cfg(feature = "remote")]
    #[cfg_attr(feature = "clap", arg(short = 'y', long, help_heading = "VALIDATION"))]
    pub dynamic_build: bool,

    /// Full path and filename of a binary DER-encoded certificate to validate.
    #[cfg(feature = "std_app")]
    #[cfg_attr(feature = "clap", arg(short, long, help_heading = "VALIDATION"))]
    pub end_entity_file: Option<String>,

    /// Full path folder to recursively traverse for binary DER-encoded certificates to validate.
    /// Only files with .der, .crt or cert as file extension are processed.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, short = 'f', help_heading = "VALIDATION"))]
    pub end_entity_folder: Option<String>,

    /// Additional certificate to validate, repeatable. Each occurrence may name a single
    /// certificate or a folder to traverse for them. This is the plural form of --end-entity-file
    /// and --end-entity-folder, which still work and are validated alongside it.
    #[cfg(feature = "std")]
    #[serde(default)]
    #[cfg_attr(
        feature = "clap",
        arg(long = "ee", value_name = "EE_INPUT", help_heading = "VALIDATION")
    )]
    pub ee_inputs: Vec<String>,

    /// Full path and filename of folder to receive binary DER-encoded certificates from certification
    /// paths. Folders will be created beneath this using a hash of the target certificate. Within
    /// that folder, folders will be created with a number indicating each path, i.e., the number
    /// indicates the order in which the path was returned for consideration. For best results, this
    /// folder should be cleaned in between runs. PITTv3 does not perform hygiene on this folder or
    /// its contents.
    #[cfg(feature = "std_app")]
    #[cfg_attr(feature = "clap", arg(long, short, help_heading = "VALIDATION"))]
    pub results_folder: Option<String>,

    /// Full path and filename of JSON-formatted certification path validation settings.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, short, help_heading = "VALIDATION"))]
    pub settings: Option<String>,

    /// Full path of a folder containing DER- or PEM-encoded CRLs, traversed recursively and indexed
    /// before path validation begins. Only files with a .crl extension are processed. The indexed
    /// CRLs are the local revocation source, consulted before any remote retrieval, and the folder
    /// also receives CRLs fetched remotely along with the last-modified map that makes those
    /// fetches conditional. Note that the folder is written as well as read, though only added to:
    /// a CRL that does not cover the time of interest is left out of the index and left on disk, so
    /// a later run asking about a different time can still use it.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub crl_folder: Option<String>,

    /// Revocation artifact to staple into candidate certification paths, repeatable. Each
    /// occurrence may name a single artifact or a folder to traverse, and may hold either a CRL or
    /// an OCSP response — the bytes decide, since an OCSP response has no settled file extension.
    /// CRLs are matched to path positions by issuer name, OCSP responses by the CertID each answers
    /// about. Unlike --crl-folder, which is an index a run adds fetched CRLs to, artifacts named
    /// here are read and left alone.
    ///
    /// Supply what a run needs when there is no network to fetch it from, or when the answer should
    /// come from a captured artifact rather than from whatever a responder says today.
    #[cfg(all(feature = "std", feature = "revocation"))]
    #[serde(default)]
    #[cfg_attr(
        feature = "clap",
        arg(long = "rev", value_name = "REV_INPUT", help_heading = "VALIDATION")
    )]
    pub rev_inputs: Vec<String>,

    /// Keep CRLs fetched during the run in memory instead of in a folder, for a run that should
    /// leave nothing behind. The store lasts as long as the process, so a CRL retrieved for one
    /// path serves later paths and targets in the same run. Needs no --crl-folder and takes
    /// precedence over one. Without a CRL folder, If-Modified-Since is not used.
    #[cfg(all(feature = "std", feature = "revocation"))]
    #[serde(default)]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub crl_in_memory: bool,

    /// When set together with --crl-folder, retain the revoked serial numbers of each verified
    /// full/direct CRL in memory so subsequent certificates under the same scope are answered
    /// without re-parsing or re-verifying the CRL.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub keep_crl_entries_in_memory: bool,

    /// Makes every path derive every certificate's revocation status from revocation data of its
    /// own, instead of reusing a determination reached while validating an earlier path. Costs
    /// re-fetching; buys a path that accounts for itself, and artifacts for every position, since a
    /// cached determination examines nothing and leaves nothing behind.
    ///
    /// Both caches are declined, not just the per-certificate one: a CRL folder is registered as a
    /// revocation status cache as well as a CRL source, and the first determination any registered
    /// cache offers is the one used, so leaving either in place would keep answering.
    #[cfg(all(feature = "std", feature = "revocation"))]
    #[serde(default)]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "VALIDATION"))]
    pub no_revocation_cache: bool,

    /// Paired with --ca-folder to remove expired, unparseable certificates, self-signed
    /// certificates and non-CA certificates from consideration. When paired with --error-folder,
    /// the errant files are moved instead of deleted. After cleanup completes, the application
    /// exits with no other parameters acted upon.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "CLEANUP"))]
    pub cleanup: bool,

    /// Paired with --ta-folder to remove expired or unparseable certificates from consideration.
    /// When paired with --error-folder, the errant files are moved instead of deleted. After
    /// cleanup completes, the application exits with no other parameters acted upon.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "CLEANUP"))]
    pub ta_cleanup: bool,

    /// Pair with --cleanup to generate list of files that would be cleaned up by cleanup operation
    /// without actually deleting or moving files.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "CLEANUP"))]
    pub report_only: bool,

    /// Outputs all partial paths present in CBOR file. If --ta-folder is provided, the CBOR file
    /// will be re-evaluated using --ta-folder and --time-of-interest (possibly changing the set of
    /// partial paths relative to that read from CBOR). Use of --logging-config is recommended for
    /// large CBOR files.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "DIAGNOSTICS"))]
    pub list_partial_paths: bool,

    /// Outputs all buffers present in CBOR file.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "DIAGNOSTICS"))]
    pub list_buffers: bool,

    /// Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file. Add
    /// --download-folder to save certificates that are valid as of --time-of-interest from the
    /// downloaded artifacts (use --time-of-interest 0 to download all).
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "DIAGNOSTICS"))]
    pub list_aia_and_sia: bool,

    /// Outputs all name constraints found in certificates present in CBOR file.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "DIAGNOSTICS"))]
    pub list_name_constraints: bool,

    /// Outputs all buffers present in trust anchors folder.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "DIAGNOSTICS"))]
    pub list_trust_anchors: bool,

    /// Outputs the certificate at the specified index to a file named `<index>.der` in
    /// --download-folder if specified, else current working directory.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "DIAGNOSTICS"))]
    pub dump_cert_at_index: Option<usize>,

    /// Outputs all partial paths present in CBOR file relative to the indicated target. If
    /// --ta-folder is provided, the CBOR file will be re-evaluated using --ta-folder and
    /// --time-of-interest (possibly changing the set of partial paths relative to that read from
    /// CBOR).
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(short = 'z', long, help_heading = "DIAGNOSTICS"))]
    pub list_partial_paths_for_target: Option<String>,

    /// Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If
    /// --ta-folder is provided, the CBOR file will be re-evaluated using --ta-folder and
    /// --time-of-interest (possibly changing the set of partial paths relative to that read from
    /// CBOR).
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(short = 'p', long, help_heading = "DIAGNOSTICS"))]
    pub list_partial_paths_for_leaf_ca: Option<usize>,

    /// Parses the given CSV file and saves files to folder indicated by --ca-folder. The CSV file is
    /// assumed to be as posted as the "Non-revoked, non-expired Intermediate CA Certificates
    /// chaining up to roots in Mozilla's program with the Websites trust bit set (CSV with PEM of raw
    /// certificate data)" report available on the Mozilla wiki page at <https://wiki.mozilla.org/CA/Intermediate_Certificates>.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "TOOLS"))]
    pub mozilla_csv: Option<String>,

    /// Checks the HTTP URIs in the AIA, SIA, CRL DP and freshest-CRL extensions of the certificate at
    /// the given path, reporting per-URI reachability and correctness. Runs independently of path
    /// processing; no CBOR store or trust anchors are required.
    #[cfg(feature = "remote")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "TOOLS"))]
    pub check_uris: Option<String>,

    /// Optional issuer certificate (path) for --check-uris, used to verify CRL signatures and check
    /// OCSP URIs. Auto-discovered from AIA caIssuers when omitted, unless --no-auto-discover is set.
    #[cfg(feature = "remote")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "TOOLS"))]
    pub issuer: Option<String>,

    /// Disables auto-discovery of the issuer certificate from AIA caIssuers during --check-uris.
    #[cfg(feature = "remote")]
    #[cfg_attr(feature = "clap", arg(long, help_heading = "TOOLS"))]
    pub no_auto_discover: bool,
}

/// Returns number of seconds since Unix epoch upon success and zero upon failure. This is used by
/// [`Pittv3Args`] to establish a default value for the time-of-interest option.
#[cfg(feature = "std_app")]
pub fn get_now_as_unix_epoch() -> u64 {
    if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        n.as_secs()
    } else {
        0
    }
}

/// Returns number of seconds since Unix epoch upon success and zero upon failure. This is used by
/// [`Pittv3Args`] to establish a default value for the time-of-interest option.
#[cfg(not(feature = "std_app"))]
pub fn get_now_as_unix_epoch() -> u64 {
    0
}

//! Arguments for the Pittv3 utility

use clap::Parser;

use pittv3_lib::args::get_now_as_unix_epoch;

use pittv3_lib::args::Pittv3Args;
use serde::{Deserialize, Serialize};

/// PKI Interoperability Test Tool v3 (PITTv3)
#[derive(Parser, Debug, Serialize, Deserialize, Default)]
#[command(arg_required_else_help(true))]
#[clap(author, version, about, long_about = None)]
pub struct Pittv3CliArgs {
    /// Full path of folder containing binary DER-encoded trust anchors to use when generating CBOR
    /// file containing partial certification paths and when validating certification paths.
    #[cfg(feature = "std")]
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    pub ta_folder: Option<String>,

    /// Use trust anchors from webpki-roots crate (which are from Mozilla)
    #[cfg(feature = "webpki")]
    #[clap(long, help_heading = "COMMON OPTIONS")]
    pub webpki_tas: bool,

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
    /// absent at generate time, the ca_folder is used. Additionally, this is used to designate where
    /// exported buffers are written by dump_cert_at_index or list_buffers.
    #[cfg(feature = "std")]
    #[clap(long, short, help_heading = "COMMON OPTIONS")]
    pub download_folder: Option<String>,

    /// Full path of folder containing binary, DER-encoded intermediate CA certificates. Required
    /// when generate action is performed. This is not used when path validation is performed other
    /// than as a place to store downloaded files when dynamic building is used and download_folder
    /// is not specified.
    #[cfg(feature = "std")]
    #[clap(short, long, help_heading = "COMMON OPTIONS")]
    pub ca_folder: Option<String>,

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
    /// partial paths and no need to exclude self-signed certificates).
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "GENERATION")]
    pub cbor_ta_store: bool,

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

    /// Full path of folder containing binary, DER-encoded intermediate CA certificates. Required
    /// when generate action is performed. This is not used when path validation is performed other
    /// than as a place to store downloaded files when dynamic building is used and download_folder
    /// is not specified.
    #[cfg(feature = "std")]
    #[clap(long, help_heading = "VALIDATION")]
    pub crl_folder: Option<String>,

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
}

impl TryFrom<Pittv3CliArgs> for Pittv3Args {
    type Error = ();

    fn try_from(v: Pittv3CliArgs) -> Result<Self, Self::Error> {
        Ok(Pittv3Args {
            #[cfg(feature = "std")]
            ta_folder: v.ta_folder,
            #[cfg(feature = "webpki")]
            webpki_tas: v.webpki_tas,
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
            #[cfg(feature = "std_app")]
            end_entity_file: v.end_entity_file,
            #[cfg(feature = "std")]
            end_entity_folder: v.end_entity_folder,
            #[cfg(feature = "std_app")]
            results_folder: v.results_folder,
            #[cfg(feature = "std")]
            settings: v.settings,
            #[cfg(feature = "std")]
            crl_folder: v.crl_folder,
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
        })
    }
}

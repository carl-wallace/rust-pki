//! Arguments for the Pittv3 utility

use serde::{Deserialize, Serialize};

#[cfg(feature = "std_app")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Arguments that govern a PITTv3 run. This is a plain data structure so that non-CLI frontends,
/// like a GUI, can populate it directly; the CLI converts clap-parsed arguments into this type.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Pittv3Args {
    /// Full path of a folder containing binary DER-encoded trust anchors, or of a single such file,
    /// to use when generating CBOR file containing partial certification paths and when validating
    /// certification paths. A file may hold several concatenated PEM objects.
    #[cfg(feature = "std")]
    pub ta_folder: Option<String>,

    /// Full path and filename of a CBOR-formatted trust anchor store, i.e., the form written when
    /// generating with cbor_ta_store set and the form the trust store providers serialize. This is
    /// the counterpart of `cbor` for trust anchors; either or both of this and `ta_folder` may be
    /// given, and the anchors they carry are combined.
    #[cfg(feature = "std")]
    pub ta_cbor: Option<String>,

    /// Additional trust anchor inputs, each naming a folder, a certificate, a bundle holding
    /// several, or a CBOR-formatted trust anchor store. Every entry is resolved the same way
    /// `ta_folder` and `ta_cbor` resolve theirs, from the path and then from the bytes, and the
    /// anchors from all of them are combined into one store.
    ///
    /// This is the plural form of those two arguments and exists because a trust anchor set is
    /// often assembled from several places at once. It is input-only: `ta_folder` and `ta_cbor`
    /// remain for the single-input case and are used together with this when both are given.
    #[cfg(feature = "std")]
    #[serde(default)]
    pub ta_inputs: Vec<String>,

    /// Use trust anchors from webpki-roots crate (which are from Mozilla)
    #[cfg(feature = "webpki")]
    pub webpki_tas: bool,

    /// Full path and filename of file to provide and/or receive CBOR-formatted representation of
    /// buffers containing binary DER-encoded CA certificates and map containing set of partial
    /// certification paths.
    #[cfg(feature = "std")]
    pub cbor: Option<String>,

    /// Time to use for path validation expressed as the number of seconds since Unix epoch
    /// (defaults to current system time).
    pub time_of_interest: u64,

    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See <https://docs.rs/log4rs/latest/log4rs/> for details.
    #[cfg(feature = "std_app")]
    pub logging_config: Option<String>,

    /// Full path of folder to receive binary DER-encoded certificates from paths that fail path
    /// validation. If absent, errant files are not saved for review.
    #[cfg(feature = "std_app")]
    pub error_folder: Option<String>,

    /// Full path and filename of folder to receive downloaded binary DER-encoded certificates, if
    /// absent at generate time, the ca_folder is used, which requires it to name a folder rather
    /// than a single file. Additionally, this is used to designate where exported buffers are
    /// written by dump_cert_at_index or list_buffers.
    #[cfg(feature = "std")]
    pub download_folder: Option<String>,

    /// Full path of a folder containing binary, DER-encoded intermediate CA certificates, or of a
    /// single such file (which may hold several concatenated PEM objects, e.g. a fullchain).
    /// Required when generate action is performed. When path validation is performed, these
    /// certificates are added to the graph that is built, augmenting any CBOR store in use. A folder
    /// also doubles as a place to store downloaded files when dynamic building is used and
    /// download_folder is not specified.
    #[cfg(feature = "std")]
    pub ca_folder: Option<String>,

    /// Additional intermediate CA inputs, each naming a folder, a certificate, a bundle holding
    /// several, or a CBOR-formatted store (whose partial paths are adopted along with its
    /// certificates). Every entry is resolved the same way `ca_folder` and `cbor` resolve theirs,
    /// and all of them feed the one graph a run builds.
    ///
    /// This is the plural, input-only form of those two arguments. `ca_folder` and `cbor` keep the
    /// roles this cannot take: `cbor` is also the file a generate run writes, and `ca_folder` also
    /// names where the Mozilla CSV tool saves certificates and where dynamic building stores what
    /// it downloads when `download_folder` is absent.
    #[cfg(feature = "std")]
    #[serde(default)]
    pub ca_inputs: Vec<String>,

    /// Flag that indicates a fresh CBOR-formatted file containing buffers of CA certificates and
    /// map containing set of partial certification paths should be generated and saved to location
    /// indicated by cbor parameter.
    #[cfg(feature = "std")]
    pub generate: bool,

    /// Flag that indicates whether AIA and SIA URIs should be consulted when performing generate
    /// action.
    #[cfg(feature = "remote")]
    pub chase_aia_and_sia: bool,

    /// Flag that indicates generated CBOR file will contain only trust anchors  (so no need for
    /// partial paths and no need to exclude self-signed certificates). The anchors are read from
    /// the ca_folder input, which may name a single file, and the result is the form ta_cbor takes.
    #[cfg(feature = "std")]
    pub cbor_ta_store: bool,

    /// Include the folder downloaded intermediates are written to among the CA certificates a run
    /// builds paths from, so certificates fetched by earlier runs are reused rather than fetched
    /// again.
    ///
    /// The folder is the one dynamic building writes to: `download_folder` if given, otherwise
    /// `ca_folder`, either of which may come from the settings file. Naming that folder in
    /// `ca_inputs` does the same thing; this exists because the folder is configured elsewhere, so
    /// a pool entry naming it goes stale the moment it is reconfigured.
    #[cfg(feature = "remote")]
    #[serde(default)]
    pub use_downloaded_cas: bool,

    /// Flag that indicates all available certification paths should be validated for each target.
    #[cfg(feature = "std_app")]
    pub validate_all: bool,

    /// Check if certificate passed as end_entity_file is self-signed.
    #[cfg(feature = "std_app")]
    pub validate_self_signed: bool,

    /// Flag that indicates all available certification paths compiled into the app should be
    /// validated for each target, instead of stopping after finding first valid path.
    #[cfg(not(feature = "std_app"))]
    pub validate_all: bool,

    /// Process AIA and SIA during path validation, as appropriate. Either ca_folder or
    /// download_folder must be specified when using this flag to provide a place to store
    /// downloaded artifacts.
    #[cfg(feature = "remote")]
    pub dynamic_build: bool,

    /// Full path and filename of a binary DER-encoded certificate to validate.
    #[cfg(feature = "std_app")]
    pub end_entity_file: Option<String>,

    /// Full path folder to recursively traverse for binary DER-encoded certificates to validate.
    /// Only files with .der, .crt or cert as file extension are processed.
    #[cfg(feature = "std")]
    pub end_entity_folder: Option<String>,

    /// Additional certificates to validate, each entry naming either a single certificate or a
    /// folder to traverse for them. This is the plural form of `end_entity_file` and
    /// `end_entity_folder`, which remain for the single-input case and are validated alongside
    /// these when given.
    #[cfg(feature = "std")]
    #[serde(default)]
    pub ee_inputs: Vec<String>,

    /// Full path and filename of folder to receive binary DER-encoded certificates from certification
    /// paths. Folders will be created beneath this using a hash of the target certificate. Within
    /// that folder, folders will be created with a number indicating each path, i.e., the number
    /// indicates the order in which the path was returned for consideration. For best results, this
    /// folder should be cleaned in between runs. PITTv3 does not perform hygiene on this folder or
    /// its contents.
    #[cfg(feature = "std_app")]
    pub results_folder: Option<String>,

    /// Full path and filename of JSON-formatted certification path validation settings.
    #[cfg(feature = "std")]
    pub settings: Option<String>,

    /// Full path of a folder containing DER- or PEM-encoded CRLs, traversed recursively and indexed
    /// before path validation begins. Only files with a .crl extension are processed. The indexed
    /// CRLs are the local revocation source, consulted before any remote retrieval, and the folder
    /// also receives CRLs fetched remotely along with the last-modified map that makes those
    /// fetches conditional. Note that the folder is written as well as read: indexing deletes any
    /// CRL that is not valid at the time of interest, i.e. one whose thisUpdate is in the future or
    /// whose nextUpdate has passed.
    #[cfg(feature = "std")]
    pub crl_folder: Option<String>,

    /// Revocation artifacts to staple into candidate certification paths, repeatable. Each entry
    /// may name a single artifact or a folder to traverse, and may hold either a CRL or an OCSP
    /// response — the bytes decide, since an OCSP response has no settled file extension. CRLs are
    /// matched to path positions by issuer name, OCSP responses by the CertID each answers about.
    ///
    /// This is read-only, which is what distinguishes it from `crl_folder`: that argument names an
    /// *index*, written as well as read, and indexing deletes any CRL not valid at the time of
    /// interest. An artifact named here is used and left alone. Supply what a run needs when there
    /// is no network to fetch it from, or when the answer should come from a captured artifact
    /// rather than from whatever a responder says today.
    #[cfg(all(feature = "std", feature = "revocation"))]
    #[serde(default)]
    pub rev_inputs: Vec<String>,

    /// When set together with crl_folder, retain the revoked serial numbers of each verified
    /// full/direct CRL in memory so subsequent certificates under the same scope are answered
    /// without re-parsing or re-verifying the CRL.
    #[cfg(feature = "std")]
    pub keep_crl_entries_in_memory: bool,

    /// Paired with ca_folder to remove expired, unparseable certificates, self-signed
    /// certificates and non-CA certificates from consideration. When paired with error_folder,
    /// the errant files are moved instead of deleted. After cleanup completes, the application
    /// exits with no other parameters acted upon.
    #[cfg(feature = "std")]
    pub cleanup: bool,

    /// Paired with ta_folder to remove expired or unparseable certificatesfrom consideration. When
    /// paired with error_folder, the errant files are moved instead of deleted. After cleanup
    /// completes, the application exits with no other parameters acted upon.
    #[cfg(feature = "std")]
    pub ta_cleanup: bool,

    /// Pair with cleanup to generate list of files that would be cleaned up by cleanup operation
    /// without actually deleting or moving files.
    #[cfg(feature = "std")]
    pub report_only: bool,

    /// Outputs all partial paths present in CBOR file. If a ta_folder is provided, the CBOR file
    /// will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of
    /// partial paths relative to that read from CBOR). Use of a logging-config option is recommended
    /// for large CBOR files.
    #[cfg(feature = "std")]
    pub list_partial_paths: bool,

    /// Outputs all buffers present in CBOR file.
    #[cfg(feature = "std")]
    pub list_buffers: bool,

    /// Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file. Add
    /// downloads_folder to save certificates that are valid as of time_of_interest from the
    /// downloaded artifacts (use time_of_interest=0 to download all). Specify a blocklist or
    /// last_modified_map if desired via CertificationPathSettings or rely on default files that
    /// will be generated and managed in folder used to download artifacts.
    #[cfg(feature = "std")]
    pub list_aia_and_sia: bool,

    /// Outputs all name constraints found in certificates present in CBOR file.
    #[cfg(feature = "std")]
    pub list_name_constraints: bool,

    /// Checks the HTTP URIs carried in the AIA, SIA, CRL DP and freshest-CRL extensions of the
    /// certificate at the given path, reporting per-URI reachability and correctness (the SIA/AIA URI
    /// checker). Runs independently of certification path processing; no CBOR store or trust anchors
    /// are required.
    #[cfg(feature = "remote")]
    pub check_uris: Option<String>,

    /// Optional issuer certificate (path) used by `check_uris` to verify CRL signatures and check
    /// OCSP URIs. When absent, the issuer is auto-discovered from AIA caIssuers unless
    /// `no_auto_discover` is set.
    #[cfg(feature = "remote")]
    pub issuer: Option<String>,

    /// Disables auto-discovery of the issuer certificate from AIA caIssuers during `check_uris`.
    #[cfg(feature = "remote")]
    pub no_auto_discover: bool,

    /// Outputs all buffers present in trust anchors folder.
    #[cfg(feature = "std")]
    pub list_trust_anchors: bool,

    /// Outputs the certificate at the specified index to a file names `<index>.der` in the
    /// download_folder if specified, else current working directory.
    #[cfg(feature = "std")]
    pub dump_cert_at_index: Option<usize>,

    /// Outputs all partial paths present in CBOR file relative to the indicated target. If a
    /// ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
    /// time_of_interest (possibly changing the set of partial paths relative to that read from CBOR).
    #[cfg(feature = "std")]
    pub list_partial_paths_for_target: Option<String>,

    /// Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If a
    /// ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and
    /// time_of_interest (possibly changing the set of partial paths relative to that read from CBOR).
    #[cfg(feature = "std")]
    pub list_partial_paths_for_leaf_ca: Option<usize>,

    /// Parses the given CSV file and saves files to folder indicated by the ca_folder parameter. The
    /// CSV file is assumed to be as posted as the "Non-revoked, non-expired Intermediate CA Certificates
    /// chaining up to roots in Mozilla's program with the Websites trust bit set (CSV with PEM of raw
    /// certificate data)" report available on the Mozilla wiki page at <https://wiki.mozilla.org/CA/Intermediate_Certificates>.
    #[cfg(feature = "std")]
    pub mozilla_csv: Option<String>,
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

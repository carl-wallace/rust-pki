//! Help text for the [`Pittv3Args`](crate::args::Pittv3Args) fields, keyed by the argument name.
//!
//! The CLI describes a flag in its `--help` output; a GUI describes the same thing in a tooltip on
//! the control that sets it. Both should say the same thing, so the wording lives here rather than
//! being written once per frontend. The text is taken from the `Pittv3Args` field documentation,
//! which is the canonical description of what each argument does.
//!
//! Names are the kebab-case form the frontends already use for their form controls, which is also
//! the CLI's long-flag spelling. Where a field exists as cfg-gated variants with different wording
//! (`validate_all` is the one today), this uses the `std_app` spelling, since that is what the CLI
//! and the GUI frontends build.

/// Returns the help text for `name`, or an empty string when the name is not a PITTv3 argument —
/// a form control that does not correspond to one, for instance.
pub fn arg_help(name: &str) -> &'static str {
    match name {
        "ta-folder" => concat!(
            "Full path of a folder containing binary DER-encoded trust anchors, or of a single such ",
            "file, to use when generating CBOR file containing partial certification paths and when ",
            "validating certification paths. A file may hold several concatenated PEM objects.",
        ),
        "ta-cbor" => concat!(
            "Full path and filename of a CBOR-formatted trust anchor store, i.e., the form written by ",
            "--generate --cbor-ta-store and the form the certval trust store providers serialize. This ",
            "is the trust anchor counterpart of --cbor; it may be combined with --ta-folder, in which ",
            "case the anchors from both are used.",
        ),
        "ta" => concat!(
            "Additional trust anchor input, repeatable. Each occurrence may name a folder, a ",
            "certificate, a bundle holding several, or a CBOR-formatted trust anchor store; what it ",
            "is comes from the path and then from the bytes, so the four need not be sorted into ",
            "different arguments first. This is the plural form of --ta-folder and --ta-cbor, which ",
            "still work and are used alongside it.",
        ),
        "webpki-tas" => "Use trust anchors from webpki-roots crate (which are from Mozilla)",
        "cbor" => concat!(
            "Full path and filename of file to provide and/or receive CBOR-formatted representation of ",
            "buffers containing binary DER-encoded CA certificates and map containing set of partial ",
            "certification paths.",
        ),
        "time-of-interest" => concat!(
            "Time to use for path validation expressed as the number of seconds since Unix epoch ",
            "(defaults to current system time).",
        ),
        "logging-config" => concat!(
            "Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. ",
            "See <https://docs.rs/log4rs/latest/log4rs/> for details.",
        ),
        "error-folder" => concat!(
            "Full path of folder to receive binary DER-encoded certificates from paths that fail path ",
            "validation. If absent, errant files are not saved for review.",
        ),
        "download-folder" => concat!(
            "Full path and filename of folder to receive downloaded binary DER-encoded certificates, if ",
            "absent at generate time, the ca_folder is used, which requires it to name a folder rather ",
            "than a single file. Additionally, this is used to designate where exported buffers are ",
            "written by dump_cert_at_index or list_buffers.",
        ),
        "ca-folder" => concat!(
            "Full path of a folder containing binary, DER-encoded intermediate CA certificates, or of a ",
            "single such file (which may hold several concatenated PEM objects, e.g. a fullchain). ",
            "Required when generate action is performed. When path validation is performed, these ",
            "certificates are added to the graph that is built, augmenting any CBOR store in use. A ",
            "folder also doubles as a place to store downloaded files when dynamic building is used and ",
            "download_folder is not specified.",
        ),
        "ca" => concat!(
            "Additional intermediate CA input, repeatable. Each occurrence may name a folder, a ",
            "certificate, a bundle holding several, or a CBOR-formatted store, and all of them feed ",
            "the one graph a run builds. This is the plural form of --ca-folder and --cbor for ",
            "validation. It is not consulted when generating: --ca-folder names the folder generation ",
            "reads, and --cbor the file it writes.",
        ),
        "generate" => concat!(
            "Flag that indicates a fresh CBOR-formatted file containing buffers of CA certificates and ",
            "map containing set of partial certification paths should be generated and saved to location ",
            "indicated by cbor parameter.",
        ),
        "chase-aia-and-sia" => concat!(
            "Flag that indicates whether AIA and SIA URIs should be consulted when performing generate ",
            "action.",
        ),
        "cbor-ta-store" => concat!(
            "Flag that indicates generated CBOR file will contain only trust anchors (so no need for ",
            "partial paths and no need to exclude self-signed certificates). The anchors are read ",
            "from the CA input, which may name a single file, and the result is the form --ta-cbor ",
            "takes.",
        ),
        "use-downloaded-cas" => concat!(
            "Include the folder downloaded intermediates are written to among the CA certificates ",
            "a run builds paths from, so certificates fetched by earlier runs are reused rather ",
            "than fetched again. The folder is the download folder if given, otherwise the CA ",
            "folder, either of which may come from the settings file.",
        ),
        "validate-all" => "Flag that indicates all available certification paths should be validated for each target.",
        "validate-self-signed" => "Check if certificate passed as end_entity_file is self-signed.",
        "dynamic-build" => concat!(
            "Process AIA and SIA during path validation, as appropriate. Either ca_folder or ",
            "download_folder must be specified when using this flag to provide a place to store ",
            "downloaded artifacts.",
        ),
        "end-entity-file" => "Full path and filename of a binary DER-encoded certificate to validate.",
        "end-entity-folder" => concat!(
            "Full path folder to recursively traverse for binary DER-encoded certificates to validate. ",
            "Only files with .der, .crt or cert as file extension are processed.",
        ),
        "ee" => concat!(
            "Additional certificate to validate, repeatable. Each occurrence may name a single ",
            "certificate or a folder to traverse for them. This is the plural form of ",
            "--end-entity-file and --end-entity-folder, which still work and are validated alongside ",
            "it.",
        ),
        "results-folder" => concat!(
            "Full path and filename of folder to receive binary DER-encoded certificates from ",
            "certification paths. Folders will be created beneath this using a hash of the target ",
            "certificate. Within that folder, folders will be created with a number indicating each path, ",
            "i.e., the number indicates the order in which the path was returned for consideration. For ",
            "best results, this folder should be cleaned in between runs. PITTv3 does not perform hygiene ",
            "on this folder or its contents.",
        ),
        "settings" => "Full path and filename of JSON-formatted certification path validation settings.",
        "rev" => concat!(
            "Revocation artifact to staple into candidate certification paths, repeatable. Each ",
            "occurrence may name a single artifact or a folder to traverse, and may hold either a ",
            "CRL or an OCSP response \u{2014} the bytes decide, since an OCSP response has no settled ",
            "file extension. CRLs are matched to path positions by issuer name, OCSP responses by ",
            "the CertID each answers about. Unlike --crl-folder, which is an index that deletes ",
            "CRLs not valid at the time of interest, artifacts named here are read and left alone.",
        ),
        "crl-folder" => concat!(
            "Full path of a folder containing DER- or PEM-encoded CRLs, traversed recursively and indexed ",
            "before path validation begins. Only files with a .crl extension are processed. The indexed ",
            "CRLs are the local revocation source, consulted before any remote retrieval, and the folder ",
            "also receives CRLs fetched remotely along with the last-modified map that makes those fetches ",
            "conditional. Note that the folder is written as well as read: indexing deletes any CRL that is ",
            "not valid at the time of interest, i.e. one whose thisUpdate is in the future or whose ",
            "nextUpdate has passed.",
        ),
        "keep-crl-entries-in-memory" => concat!(
            "When set together with crl_folder, retain the revoked serial numbers of each verified ",
            "full/direct CRL in memory so subsequent certificates under the same scope are answered ",
            "without re-parsing or re-verifying the CRL.",
        ),
        "cleanup" => concat!(
            "Paired with ca_folder to remove expired, unparseable certificates, self-signed certificates ",
            "and non-CA certificates from consideration. When paired with error_folder, the errant files ",
            "are moved instead of deleted. After cleanup completes, the application exits with no other ",
            "parameters acted upon.",
        ),
        "ta-cleanup" => concat!(
            "Paired with ta_folder to remove expired or unparseable certificatesfrom consideration. When ",
            "paired with error_folder, the errant files are moved instead of deleted. After cleanup ",
            "completes, the application exits with no other parameters acted upon.",
        ),
        "report-only" => concat!(
            "Pair with cleanup to generate list of files that would be cleaned up by cleanup operation ",
            "without actually deleting or moving files.",
        ),
        "list-partial-paths" => concat!(
            "Outputs all partial paths present in CBOR file. If a ta_folder is provided, the CBOR file ",
            "will be re-evaluated using ta_folder and time_of_interest (possibly changing the set of ",
            "partial paths relative to that read from CBOR). Use of a logging-config option is ",
            "recommended for large CBOR files.",
        ),
        "list-buffers" => "Outputs all buffers present in CBOR file.",
        "list-aia-and-sia" => concat!(
            "Outputs all URIs from AIA and SIA extensions found in certificates present in CBOR file. Add ",
            "downloads_folder to save certificates that are valid as of time_of_interest from the ",
            "downloaded artifacts (use time_of_interest=0 to download all). Specify a blocklist or ",
            "last_modified_map if desired via CertificationPathSettings or rely on default files that ",
            "will be generated and managed in folder used to download artifacts.",
        ),
        "list-name-constraints" => "Outputs all name constraints found in certificates present in CBOR file.",
        "check-uris" => concat!(
            "Checks the HTTP URIs carried in the AIA, SIA, CRL DP and freshest-CRL extensions of the ",
            "certificate at the given path, reporting per-URI reachability and correctness (the SIA/AIA ",
            "URI checker). Runs independently of certification path processing; no CBOR store or trust ",
            "anchors are required.",
        ),
        "issuer" => concat!(
            "Optional issuer certificate (path) used by `check_uris` to verify CRL signatures and check ",
            "OCSP URIs. When absent, the issuer is auto-discovered from AIA caIssuers unless ",
            "`no_auto_discover` is set.",
        ),
        "no-auto-discover" => "Disables auto-discovery of the issuer certificate from AIA caIssuers during `check_uris`.",
        "list-trust-anchors" => "Outputs all buffers present in trust anchors folder.",
        "dump-cert-at-index" => concat!(
            "Outputs the certificate at the specified index to a file names `<index>.der` in the ",
            "download_folder if specified, else current working directory.",
        ),
        "list-partial-paths-for-target" => concat!(
            "Outputs all partial paths present in CBOR file relative to the indicated target. If a ",
            "ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and ",
            "time_of_interest (possibly changing the set of partial paths relative to that read from ",
            "CBOR).",
        ),
        "list-partial-paths-for-leaf-ca" => concat!(
            "Outputs all partial paths present in CBOR file relative to the indicated leaf CA. If a ",
            "ta_folder is provided, the CBOR file will be re-evaluated using ta_folder and ",
            "time_of_interest (possibly changing the set of partial paths relative to that read from ",
            "CBOR).",
        ),
        "mozilla-csv" => concat!(
            "Parses the given CSV file and saves files to folder indicated by the ca_folder parameter. ",
            "The CSV file is assumed to be as posted as the \"Non-revoked, non-expired Intermediate CA ",
            "Certificates chaining up to roots in Mozilla's program with the Websites trust bit set (CSV ",
            "with PEM of raw certificate data)\" report available on the Mozilla wiki page at ",
            "<https://wiki.mozilla.org/CA/Intermediate_Certificates>.",
        ),
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_args_have_help_and_unknown_ones_do_not() {
        assert!(arg_help("ta-folder").contains("trust anchors"));
        assert!(arg_help("ca-folder").contains("intermediate CA certificates"));
        assert_eq!(arg_help("not-an-argument"), "");
    }

    /// The CRL folder holds CRLs, not certificates. Asserting the absence as well as the presence
    /// is what distinguishes this entry from the CA folder's, which describes a different artifact
    /// in otherwise similar words.
    #[test]
    fn crl_folder_describes_crls_not_ca_certificates() {
        let help = arg_help("crl-folder");
        assert!(help.contains("CRLs"));
        assert!(!help.contains("intermediate CA certificates"));
    }

    /// `validate_all` is declared twice in `Pittv3Args` behind opposing `std_app` gates. The help
    /// must carry the `std_app` wording, which is what the CLI and GUI frontends build, and must
    /// not be emitted twice.
    #[test]
    fn cfg_gated_duplicate_uses_the_std_app_wording() {
        let help = arg_help("validate-all");
        assert!(help.contains("all available certification paths should be validated"));
        assert!(!help.contains("compiled into the app"));
    }
}

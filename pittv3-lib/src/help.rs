//! Tooltip text for the GUI frontends, keyed by the [`Pittv3Args`](crate::args::Pittv3Args) field
//! name the control sets.
//!
//! **This feeds tooltips and nothing else.** The sole consumer is `tooltip` in
//! `pittv3-gui-lib/src/gui_rows.rs`, which falls back to [`arg_help`] when a row supplies no title
//! of its own. `--help` does not come from here: clap builds that from the doc comments on
//! `Pittv3Args` in `pittv3/src/cliargs.rs`. The two are separate on purpose, because they address
//! different readers.
//!
//! **So command-line vocabulary here is always wrong.** A tooltip naming `ca_folder`, or a
//! "parameter", or a flag by its `--long` spelling, describes something the reader cannot see:
//! they are looking at a labelled row in a window. Say what the control does, using the label on
//! screen. Twenty of these forty-five entries were rewritten on 2026-09-09 for exactly this --
//! among them `generate`, which said a store would be "saved to location indicated by cbor
//! parameter" beside a row labelled CA CBOR (output). The long form belongs in the PITTv3 User's
//! Guide, which the Help view links to; a tooltip that needs three sentences has already failed.
//!
//! Copying a field's documentation verbatim is how this goes wrong -- maintainer rationale and
//! command-line conventions arriving in a tooltip that has neither.
//!
//! **Where the two frontends do not offer the same thing, the wording here follows the GUI.** The
//! CAPI arguments are the case today: the CLI takes any store name and so has to explain the
//! `Location\Name` syntax, while the GUI offers two Windows stores as selector entries and accepts
//! no name at all. Text covering both would carry a syntax one of them cannot use, so those entries
//! read as the control does and the CLI keeps its own fuller wording in `cliargs.rs`.
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
            "A CBOR trust anchor store: the form Generate writes with CBOR TA store checked, and ",
            "the form the certval trust store providers serialize. Anchors from this and from the ",
            "TA Folder are used together.",
        ),
        "ta" => concat!(
            "Trust anchors for the run. Each entry may be a folder, a certificate, a bundle ",
            "holding several, or a CBOR trust anchor store; what an entry is comes from the path ",
            "and then from the bytes, so entries need not be sorted by kind. Everything listed is ",
            "used together.",
        ),
        "webpki-tas" => "Use trust anchors from webpki-roots crate (which are from Mozilla)",
        // Keyed by the CLI long flag -- `--capi-ta`, not the `capi_ta_stores` field it fills. The
        // two diverge for these three alone, so a key derived from the field name would return ""
        // and the control would lose its explanation with nothing failing.
        // The GUI offers two Windows stores as selector entries and takes no store name, so these
        // deliberately differ from the CLI wording: the Location\Name syntax is a command-line
        // concern and has no place on a control that cannot accept one.
        "capi-ta" => "Windows certificate store containing trust anchors to use.",
        "capi-ca" => "Windows certificate store containing intermediate CA certificates to use.",
        "capi-ca-rw" => concat!(
            "Windows certificate store that dynamic building writes fetched certificates into, so a ",
            "later run starts from what this one found. Also read at the start of the run.",
        ),
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
            "Where certificates fetched while chasing AIA and SIA URIs are written. With none ",
            "named, the CA Folder is used, which then has to name a folder rather than a single ",
            "file. Exported buffers are written here too.",
        ),
        "ca-folder" => concat!(
            "A folder of DER-encoded intermediate CA certificates, or a single file holding one or ",
            "more. Required to generate a store. When validating, these are added to the graph ",
            "that is built, augmenting any CBOR store in use. A folder here also receives fetched ",
            "certificates when chasing is on and no Download Folder is named.",
        ),
        "ca" => concat!(
            "Intermediate CA certificates for the run. Each entry may be a folder, a certificate, ",
            "a bundle holding several, or a CBOR store, and all of them feed the one graph a run ",
            "builds. Not read when generating a store: generation reads the CA Folder.",
        ),
        "generate" => concat!(
            "Build a store from the trust anchor and CA inputs and write it to the CBOR output ",
            "named above. Off, nothing is generated and the other controls here do nothing.",
        ),
        "chase-aia-and-sia" => concat!(
            "Flag that indicates whether AIA and SIA URIs should be consulted when performing generate ",
            "action.",
        ),
        "cbor-ta-store" => concat!(
            "Write a trust anchor store rather than a CA store: only the anchors, with no partial ",
            "paths. The anchors are read from the CA input, and the output row is relabelled to ",
            "say so \u{2014} the file it names does not change when this is turned on.",
        ),
        "use-downloaded-cas" => concat!(
            "Include the folder downloaded intermediates are written to among the CA certificates ",
            "a run builds paths from, so certificates fetched by earlier runs are reused rather ",
            "than fetched again. The folder is the download folder if given, otherwise the CA ",
            "folder, either of which may come from the settings file.",
        ),
        "validate-all" => "Flag that indicates all available certification paths should be validated for each target.",
        "validate-self-signed" => concat!(
            "Answer the narrower question of whether the end entity certificate is self-signed, ",
            "instead of building paths for it.",
        ),
        "dynamic-build" => concat!(
            "Follow the AIA and SIA URIs of certificates encountered while building paths, to find ",
            "issuers the inputs do not hold. Needs a CA Folder or a Download Folder to put what it ",
            "fetches.",
        ),
        "end-entity-file" => "Full path and filename of a binary DER-encoded certificate to validate.",
        "end-entity-folder" => concat!(
            "Full path folder to recursively traverse for binary DER-encoded certificates to validate. ",
            "Only files with .der, .crt or cert as file extension are processed.",
        ),
        "ee" => concat!(
            "The certificates to validate. Each entry may be a single certificate or a folder to ",
            "traverse for them, and everything listed is validated.",
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
            "CRLs and OCSP responses supplied for this run, stapled into candidate paths. Either ",
            "list accepts either kind \u{2014} the bytes decide, since an OCSP response has no ",
            "settled file extension. CRLs are matched to path positions by issuer name, OCSP ",
            "responses by the CertID each answers about. Unlike the CRL index, these are read and ",
            "left alone.",
        ),
        "crl-folder" => concat!(
            "Full path of a folder containing DER- or PEM-encoded CRLs, traversed recursively and indexed ",
            "before path validation begins. Only files with a .crl extension are processed. The indexed ",
            "CRLs are the local revocation source, consulted before any remote retrieval, and the folder ",
            "also receives CRLs fetched remotely along with the last-modified map that makes those fetches ",
            "conditional. Note that the folder is written as well as read, though only added to: a CRL ",
            "that does not cover the time of interest is left out of the index and left on disk, so a later ",
            "run asking about a different time can still use it.",
        ),
        "keep-crl-entries-in-memory" => concat!(
            "Keep the revoked serial numbers of each verified CRL in memory, so later certificates ",
            "under the same scope are answered without re-reading or re-verifying it. Needs a CRL ",
            "index to draw on.",
        ),
        "no-revocation-cache" => concat!(
            "Makes every path derive every certificate's revocation status from revocation data of ",
            "its own, instead of reusing a determination reached while validating an earlier path. ",
            "Costs re-fetching. Buys a path that accounts for itself, and artifacts for every ",
            "position: a cached determination examines nothing, so a position answered from cache ",
            "reports a status and carries no evidence for it in a results folder or an export.",
        ),
        "cleanup" => concat!(
            "Remove certificates from the CA Folder that a run could not use: unparseable, not ",
            "valid at the time of interest, self-signed, or not a CA. With an Error Folder named ",
            "they are moved there rather than deleted. The run does nothing else.",
        ),
        "ta-cleanup" => concat!(
            "Remove trust anchors from the TA Folder that are unparseable or not valid at the time ",
            "of interest. With an Error Folder named they are moved there rather than deleted. The ",
            "run does nothing else.",
        ),
        "report-only" => concat!(
            "Pair with cleanup to generate list of files that would be cleaned up by cleanup operation ",
            "without actually deleting or moving files.",
        ),
        "list-partial-paths" => concat!(
            "List every partial path the store holds. With a TA Folder given, the store is ",
            "re-evaluated against those anchors and the time of interest first, which can change ",
            "the set. Large stores produce a great deal of output.",
        ),
        "list-buffers" => "Outputs all buffers present in CBOR file.",
        "list-aia-and-sia" => concat!(
            "List the AIA and SIA URIs carried by the certificates in the store. With a Download ",
            "Folder given, the certificates those URIs name are fetched and kept if they are valid ",
            "at the time of interest; a time of interest of 0 keeps all of them.",
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
            "Write one certificate from the store to a file named for its index. The index is the ",
            "position reported by List Buffers. Written to the Download Folder if one is named, ",
            "otherwise to the working directory.",
        ),
        "list-partial-paths-for-target" => concat!(
            "List the partial paths the store holds that could serve this certificate \u{2014} the ",
            "question to ask when a certificate would not validate. With a TA Folder given, the ",
            "store is re-evaluated against those anchors and the time of interest first.",
        ),
        "list-partial-paths-for-leaf-ca" => concat!(
            "List the partial paths the store holds below one CA, named by its index. With a TA ",
            "Folder given, the store is re-evaluated against those anchors and the time of ",
            "interest first.",
        ),
        "mozilla-csv" => concat!(
            "Parse Mozilla's intermediate CA report and write the certificates it holds into the ",
            "CA Folder. The file is the CSV published at ",
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

    /// The GUI row for this one passes no title of its own, so `arg_help` is the tooltip: a key that
    /// does not match returns "" and the control loses its explanation with nothing failing. The
    /// name is also the one the CLI flag derives, so this pins the two together.
    #[test]
    fn the_revocation_cache_knob_has_help_under_the_name_the_row_uses() {
        let help = arg_help("no-revocation-cache");
        assert!(!help.is_empty());
        assert!(help.contains("revocation data of"));
        assert!(help.contains("carries no evidence"));
    }

    /// The three CAPI arguments are keyed by their CLI long flags, which are shorter than the
    /// fields they fill (`--capi-ta` sets `capi_ta_stores`). Deriving a key from the field name is
    /// the mistake this guards: `arg_help` answers "" for an unknown name rather than failing, so a
    /// row asking under the wrong spelling shows an empty tooltip and nothing reports it.
    #[test]
    fn the_capi_arguments_are_keyed_by_flag_not_by_field() {
        assert!(arg_help("capi-ta").contains("trust anchors"));
        assert!(arg_help("capi-ca").contains("intermediate CA certificates"));
        assert!(arg_help("capi-ca-rw").contains("dynamic building"));
        assert_eq!(arg_help("capi-ta-stores"), "");
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

//! Supports generation of manifest files that describe certification path validation results

extern crate alloc;
use alloc::collections::BTreeMap;
#[cfg(feature = "std_app")]
use log::error;
use std::io::Write;
use std::path::Path;
// The filesystem half of this module exists only where there is a filesystem to write to.
#[cfg(feature = "std_app")]
use std::{fs, fs::File};

use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_EXT_KEY_USAGE, ID_CE_INHIBIT_ANY_POLICY, ID_CE_NAME_CONSTRAINTS,
    ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS, ID_CE_SUBJECT_KEY_IDENTIFIER,
};
#[cfg(feature = "revocation")]
use der::asn1::GeneralizedTime;
use der::{Decode, Encode};
#[cfg(feature = "std_app")]
use sha2::Digest;
#[cfg(feature = "std_app")]
use sha2::Sha256;
use x509_cert::ext::pkix::name::GeneralName;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, ResponderId, SingleResponse};

use certval::source::ta_source::{buffer_to_hex, get_filename_from_ta_metadata};
use certval::util::pdv_utilities::*;
use certval::validator::pdv_trust_anchor::*;
use certval::*;

/// `get_filename_from_metadata` takes a [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) object and returns the value read from the
/// `MD_LOCATOR` entry in the metadata field, if present, or an empty string, if not present.
pub fn get_filename_from_metadata(cert: &PDVCertificate) -> String {
    cert.locator().map(str::to_string).unwrap_or_default()
}

/// `get_file_stem_or_empty` returns stem of indicated file if it can be read or an empty string.
pub fn get_file_stem_or_empty(filename: &str) -> String {
    let path = Path::new(filename);
    if let Some(stem) = path.file_stem() {
        if let Some(str_stem) = stem.to_str() {
            return str_stem.to_string();
        }
    }
    "".to_string()
}

/// `log_cps` contributes to the manifest file related to
/// [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html) contents.
pub fn log_cps(f: &mut dyn Write, cps: &CertificationPathSettings) {
    f.write_all(
        format!(
            "Initial explicit policy: {}\n",
            cps.get_initial_explicit_policy_indicator()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "Initial policy mapping inhibit: {}\n",
            cps.get_initial_policy_mapping_inhibit_indicator()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "Initial inhibit any policy: {}\n",
            cps.get_initial_inhibit_any_policy_indicator()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all("Initial policy set: \n".as_bytes())
        .expect("Unable to write manifest file");
    let policy_set = cps.get_initial_policy_set();
    for policy in policy_set {
        f.write_all(format!("\t* {policy}\n").as_bytes())
            .expect("Unable to write manifest file");
    }
    f.write_all("Initial permitted names: \n".as_bytes())
        .expect("Unable to write manifest file");
    let mut ebufs = BTreeMap::new();
    let mut pbufs = BTreeMap::new();

    let perm = cps
        .get_initial_permitted_subtrees_as_set(&mut pbufs)
        .unwrap_or_default();
    if let Some(perm) = perm {
        for gs in perm.directory_name {
            if let GeneralName::DirectoryName(dn) = &gs.base {
                f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in perm.rfc822_name {
            if let GeneralName::Rfc822Name(rfc822) = &gs.base {
                f.write_all(format!("\t\t\t* RFC822 name: {rfc822}\n").as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in perm.uniform_resource_identifier {
            if let GeneralName::UniformResourceIdentifier(uri) = &gs.base {
                f.write_all(format!("\t\t\t* URI: {uri}\n").as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in perm.dns_name {
            if let GeneralName::DnsName(dns) = &gs.base {
                f.write_all(format!("\t\t\t* DNS name: {dns}\n").as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
    } else {
        f.write_all("\t* unconstrained\n".as_bytes())
            .expect("Unable to write manifest file");
    } // end if let Some(perm) = perm
    f.write_all("Initial excluded names: \n".as_bytes())
        .expect("Unable to write manifest file");
    let excl = cps
        .get_initial_excluded_subtrees_as_set(&mut ebufs)
        .unwrap_or_default();
    if let Some(excl) = excl {
        for gs in excl.directory_name {
            if let GeneralName::DirectoryName(dn) = &gs.base {
                f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in excl.rfc822_name {
            if let GeneralName::Rfc822Name(rfc822) = &gs.base {
                f.write_all(format!("\t\t\t* RFC822 name: {rfc822}\n").as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in excl.uniform_resource_identifier {
            if let GeneralName::UniformResourceIdentifier(uri) = &gs.base {
                f.write_all(format!("\t\t\t* URI: {uri}\n").as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in excl.dns_name {
            if let GeneralName::DnsName(dns) = &gs.base {
                f.write_all(format!("\t\t\t* DNS name: {dns}\n").as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
    } else {
        f.write_all("\t* unconstrained\n".as_bytes())
            .expect("Unable to write manifest file");
    }
    f.write_all(
        format!(
            "Enforce trust anchor constraints: {}\n",
            cps.get_enforce_trust_anchor_constraints()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "Enforce algorithm and key size constraints: {}\n",
            cps.get_enforce_alg_and_key_size_constraints()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(format!("Check revocation: {}\n", cps.get_check_revocation_status()).as_bytes())
        .expect("Unable to write manifest file");
}

/// `log_ta_details` contributes to the manifest file related to
/// [`PDVTrustAnchor`](../certval/pdv_certificate/struct.PDVTrustAnchor.html) contents.
pub fn log_ta_details(_pe: &PkiEnvironment, f: &mut dyn Write, ta: &PDVTrustAnchorChoice) {
    // TODO - implement me
    f.write_all(format!("\t\t* Source: {}\n", get_filename_from_ta_metadata(ta)).as_bytes())
        .expect("Unable to write manifest file");
}

/// `log_cert_details` contributes to the manifest file related to
/// [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) contents.
pub fn log_cert_details(pe: &PkiEnvironment, f: &mut dyn Write, cert: &PDVCertificate) {
    f.write_all(
        format!(
            "\t\t* Issuer Name: {}\n",
            name_to_string(cert.decoded().tbs_certificate().issuer())
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Subject Name: {}\n",
            name_to_string(cert.decoded().tbs_certificate().subject())
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Serial Number: 0x{}\n",
            buffer_to_hex(cert.decoded().tbs_certificate().serial_number().as_bytes())
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Not Before: {}\n",
            cert.decoded().tbs_certificate().validity().not_before
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Not After: {}\n",
            cert.decoded().tbs_certificate().validity().not_after
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Public key algorithm: {}\n",
            pe.oid_lookup(
                &cert
                    .as_ref()
                    .tbs_certificate()
                    .subject_public_key_info()
                    .algorithm
                    .oid
            )
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Public key size: {} bytes\n",
            &cert
                .as_ref()
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes()
                .len()
                / 8
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Signature algorithm: {}\n",
            pe.oid_lookup(&cert.decoded().tbs_certificate().signature().oid)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");

    let pdv_ext = cert.get_extension(&ID_CE_BASIC_CONSTRAINTS);
    if let Ok(Some(PDVExtension::BasicConstraints(bc))) = pdv_ext {
        if let Some(plc) = bc.path_len_constraint {
            if 0 == plc {
                f.write_all(
                    "\t\t* Path length constraint: only end entity certificates may follow\n"
                        .as_bytes(),
                )
                .expect("Unable to write manifest file");
            } else {
                f.write_all(
                    format!(
                        "\t\t* Path length constraint: only {plc} CA certificate(s) may follow\n"
                    )
                    .as_bytes(),
                )
                .expect("Unable to write manifest file");
            }
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_CERTIFICATE_POLICIES);
    if let Ok(Some(PDVExtension::CertificatePolicies(cp))) = pdv_ext {
        f.write_all("\t\t* Certificate policies\n".as_bytes())
            .expect("Unable to write manifest file");
        for p in &cp.0 {
            f.write_all(format!("\t\t\t* {}\n", p.policy_identifier).as_bytes())
                .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_POLICY_CONSTRAINTS);
    if let Ok(Some(PDVExtension::PolicyConstraints(pc))) = pdv_ext {
        if let Some(re) = pc.require_explicit_policy {
            f.write_all(format!("\t\t* Require explicit policy: {re}\n").as_bytes())
                .expect("Unable to write manifest file");
        }
        if let Some(re) = pc.inhibit_policy_mapping {
            f.write_all(format!("\t\t* Inhibit policy mapping: {re}\n").as_bytes())
                .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_INHIBIT_ANY_POLICY);
    if let Ok(Some(PDVExtension::InhibitAnyPolicy(iap))) = pdv_ext {
        f.write_all(format!("\t\t* Inhibit any policy: {}\n", iap.0).as_bytes())
            .expect("Unable to write manifest file");
    }

    let pdv_ext = cert.get_extension(&ID_CE_POLICY_MAPPINGS);
    if let Ok(Some(PDVExtension::PolicyMappings(pm))) = pdv_ext {
        f.write_all("\t\t* Policy mappings\n".as_bytes())
            .expect("Unable to write manifest file");
        for p in &pm.0 {
            f.write_all(
                format!(
                    "\t\t\t* {} -> {}\n",
                    p.issuer_domain_policy, p.subject_domain_policy
                )
                .as_bytes(),
            )
            .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
    if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = pdv_ext {
        if let Some(kid) = &akid.key_identifier {
            let akid_hex = buffer_to_hex(kid.as_bytes());
            f.write_all(format!("\t\t* Authority key identifier: {akid_hex}\n").as_bytes())
                .expect("Unable to write manifest file");
        }
        if let Some(iss) = &akid.authority_cert_issuer {
            f.write_all("\t\t* Authority certificate issuer\n".as_bytes())
                .expect("Unable to write manifest file");
            for gn in iss {
                match gn {
                    GeneralName::OtherName(on) => {
                        f.write_all(
                            format!("\t\t\t* Unsupported OtherName of type {:?}\n", on.type_id)
                                .as_bytes(),
                        )
                        .expect("Unable to write manifest file");
                    }
                    GeneralName::Rfc822Name(rfc822) => {
                        f.write_all(format!("\t\t\t* RFC822 name: {rfc822}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DnsName(dns) => {
                        f.write_all(format!("\t\t\t* DNS name: {dns}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DirectoryName(dn) => {
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::UniformResourceIdentifier(uri) => {
                        f.write_all(format!("\t\t\t* URI: {uri}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    // not supporting name constraints for x400Address, ediPartyName, iPAddress or registeredID
                    _ => {
                        f.write_all("\t\t\t* Unsupported NameConstraint (i.e., one of x400Address, ediPartyName, iPAddress or registeredID)\n".as_bytes()).expect("Unable to write manifest file");
                    }
                }
            }
        }
        if let Some(iss) = &akid.authority_cert_serial_number {
            f.write_all(format!("\t\t* Authority certificate serial number: {iss:?}\n").as_bytes())
                .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_SUBJECT_KEY_IDENTIFIER);
    if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = pdv_ext {
        let skid_hex = buffer_to_hex(skid.0.as_bytes());
        f.write_all(format!("\t\t* Subject key identifier: {skid_hex}\n").as_bytes())
            .expect("Unable to write manifest file");
    }
    //TODO FIX
    /*
        let pdv_ext = cert.get_extension(&ID_CE_KEY_USAGE);
        if let Ok(Some(PDVExtension::KeyUsage(ku))) = pdv_ext {
            let kuv = x509::extensions_utils::get_key_usage_values(ku);
            f.write_all("\t\t* Key usage: ".as_bytes())
                .expect("Unable to write manifest file");
            for (i, v) in kuv.iter().enumerate() {
                if i < kuv.len() - 1 {
                    f.write_all(format!("{},", v).as_bytes())
                        .expect("Unable to write manifest file");
                } else {
                    f.write_all(format!("{}\n", v).as_bytes())
                        .expect("Unable to write manifest file");
                }
            }
        }
    */
    let pdv_ext = cert.get_extension(&ID_CE_EXT_KEY_USAGE);
    if let Ok(Some(PDVExtension::ExtendedKeyUsage(eku))) = pdv_ext {
        f.write_all("\t\t* Extended key usage\n".as_bytes())
            .expect("Unable to write manifest file");
        for p in &eku.0 {
            f.write_all(format!("\t\t\t* {p}\n").as_bytes())
                .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_NAME_CONSTRAINTS);
    if let Ok(Some(PDVExtension::NameConstraints(nc))) = pdv_ext {
        if let Some(perm) = &nc.permitted_subtrees {
            f.write_all("\t\t* Permitted name constraints\n".as_bytes())
                .expect("Unable to write manifest file");
            for gs in perm {
                match &gs.base {
                    GeneralName::OtherName(on) => {
                        f.write_all(
                            format!("\t\t\t* Unsupported OtherName of type {:?}\n", on.type_id)
                                .as_bytes(),
                        )
                        .expect("Unable to write manifest file");
                    }
                    GeneralName::Rfc822Name(rfc822) => {
                        f.write_all(format!("\t\t\t* RFC822 name: {rfc822}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DnsName(dns) => {
                        f.write_all(format!("\t\t\t* DNS name: {dns}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DirectoryName(dn) => {
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::UniformResourceIdentifier(uri) => {
                        f.write_all(format!("\t\t\t* URI: {uri}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    // not supporting name constraints for x400Address, ediPartyName, iPAddress or registeredID
                    _ => {
                        f.write_all("\t\t\t* Unsupported NameConstraint (i.e., one of x400Address, ediPartyName, iPAddress or registeredID)\n".as_bytes()).expect("Unable to write manifest file");
                    }
                }
            }
        }

        if let Some(excl) = &nc.excluded_subtrees {
            f.write_all("\t\t* Excluded name constraints\n".as_bytes())
                .expect("Unable to write manifest file");
            for gs in excl {
                match &gs.base {
                    GeneralName::OtherName(on) => {
                        f.write_all(
                            format!("\t\t\t* Unsupported OtherName of type {:?}\n", on.type_id)
                                .as_bytes(),
                        )
                        .expect("Unable to write manifest file");
                    }
                    GeneralName::Rfc822Name(rfc822) => {
                        f.write_all(format!("\t\t\t* RFC822 name: {rfc822}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DnsName(dns) => {
                        f.write_all(format!("\t\t\t* DNS name: {dns}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DirectoryName(dn) => {
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::UniformResourceIdentifier(uri) => {
                        f.write_all(format!("\t\t\t* URI: {uri}\n").as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    // not supporting name constraints for x400Address, ediPartyName, iPAddress or registeredID
                    _ => {
                        f.write_all("\t\t\t* Unsupported NameConstraint (i.e., one of x400Address, ediPartyName, iPAddress or registeredID)\n".as_bytes()).expect("Unable to write manifest file");
                    }
                }
            }
        }
    }

    f.write_all(format!("\t\t* Source: {}\n", get_filename_from_metadata(cert)).as_bytes())
        .expect("Unable to write manifest file");
}

/// `log_cpr` contributes to the manifest file related to
/// [`CertificationPathResults`](../certval/path_settings/type.CertificationPathResults.html) contents.
#[cfg(feature = "std_app")]
pub fn log_cpr(_pe: &PkiEnvironment, f: &mut dyn Write, np: &Path, cpr: &CertificationPathResults) {
    render_cpr(f, cpr);
    write_cpr_artifacts(np, cpr);
}

/// Renders the certification path validation outputs -- the status and the valid policy graph.
///
/// Separate from [`write_cpr_artifacts`] because the two halves go to different places and only one
/// of them needs a filesystem: a frontend assembling an archive in memory renders this and collects
/// the artifacts as bytes, while a run writing to a results folder does both to disk. Keeping the
/// rendering here means every frontend's manifest is the same manifest rather than a second one that
/// drifts.
pub fn render_cpr(f: &mut dyn Write, cpr: &CertificationPathResults) {
    let status = cpr.get_validation_status();
    if let Some(status) = status {
        f.write_all(format!("Status: {status:?}\n\n").as_bytes())
            .expect("Unable to write manifest file");
    }

    let vpt = cpr.get_final_valid_policy_graph();
    if let Some(vpt) = vpt {
        f.write_all("Valid certificate policies\n".as_bytes())
            .expect("Unable to write manifest file");
        for (i, row) in vpt.iter().enumerate() {
            f.write_all(format!("Row: {}\n", i + 1).as_bytes())
                .expect("Unable to write manifest file");
            for p in row {
                f.write_all(format!("\t* {}\n", p.valid_policy).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
    }
}

/// Writes the revocation artifacts a run consulted into `np`: OCSP requests and responses, the
/// responder certificates carried inside those responses, and CRLs where their bytes are still held.
#[cfg(feature = "std_app")]
fn write_cpr_artifacts(np: &Path, cpr: &CertificationPathResults) {
    for (name, bytes) in cpr_artifact_entries(cpr) {
        let p = np.join(&name);
        if let Err(e) = fs::write(&p, &bytes) {
            error!("Unable to write {}: {e}", p.display());
        }
    }
    // CRLs are not among those entries because the results retain only `CrlInfo`, not the CRL. Here
    // the bytes can sometimes be recovered from the file the source cached, so the note-or-CRL
    // decision lives with the filesystem half.
    if let Some(crls) = cpr.get_crl() {
        for (i, or) in crls.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, info) in or.iter().enumerate() {
                let stem = if suffix {
                    format!("{}-crl-{}", i + 1, j)
                } else {
                    format!("{}-crl", i + 1)
                };
                write_crl_artifact(np, &stem, info);
            }
        }
    }
    if let Some(crls) = cpr.get_failed_crls() {
        for (i, or) in crls.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, info) in or.iter().enumerate() {
                let stem = if suffix {
                    format!("{}-crl-{}.failed", i + 1, j)
                } else {
                    format!("{}-crl.failed", i + 1)
                };
                write_crl_artifact(np, &stem, info);
            }
        }
    }
}

/// The revocation artifacts a run consulted, as (file name, bytes) pairs: OCSP requests and
/// responses, the failed variants, and the responder certificates carried inside each response.
///
/// Named here rather than at each destination so a file in a results folder and an entry in an
/// archive are the same artifact under the same name. Nothing here touches a filesystem, which is
/// what lets a browser assemble the identical set in memory.
///
/// CRLs are absent: the results retain only the compact `CrlInfo`, so their bytes have to come from
/// whichever source still holds them, which is a decision for the caller rather than for this.
pub fn cpr_artifact_entries(cpr: &CertificationPathResults) -> Vec<(String, Vec<u8>)> {
    // i + 1 throughout because trust anchors are not considered here, while artifact indexes put the
    // trust anchor in slot 0.
    let mut out = vec![];
    let mut push_all = |items: Option<Vec<Vec<Vec<u8>>>>, ext: &str| {
        let Some(items) = items else {
            return;
        };
        for (i, per_hop) in items.iter().enumerate() {
            let suffix = per_hop.len() > 1;
            for (j, bytes) in per_hop.iter().enumerate() {
                let name = if suffix {
                    format!("{}-ocsp-{}.{ext}", i + 1, j)
                } else {
                    format!("{}-ocsp.{ext}", i + 1)
                };
                out.push((name, bytes.clone()));
            }
        }
    };
    push_all(cpr.get_ocsp_requests(), "ocspReq");
    push_all(cpr.get_ocsp_responses(), "ocspResp");
    push_all(cpr.get_failed_ocsp_requests(), "failed.ocspReq");
    push_all(cpr.get_failed_ocsp_responses(), "failed.ocspResp");

    if let Some(responses) = cpr.get_ocsp_responses() {
        for (i, per_hop) in responses.iter().enumerate() {
            for (j, response) in per_hop.iter().enumerate() {
                out.extend(ocsp_responder_cert_entries(i + 1, j, response));
            }
        }
    }
    out
}

/// The responder's certificates carried inside one OCSP response, as (file name, bytes).
///
/// Without these a saved response cannot be checked: it is a signed statement, and verifying it
/// needs the responder's certificate. PITTv1 and v2 both wrote them out for that reason. Nothing is
/// retained to produce them -- a `BasicOCSPResponse` carries them in its `certs` field, so this
/// decodes bytes the results already hold. A response identifying its signer by name and key hash
/// alone may carry none, in which case there is nothing to write and the responder certificate is
/// expected to be the CA's own, already on the path.
pub fn ocsp_responder_cert_entries(
    hop: usize,
    resp: usize,
    response: &[u8],
) -> Vec<(String, Vec<u8>)> {
    let Some(basic) = OcspResponse::from_der(response)
        .ok()
        .and_then(|r| r.response_bytes)
        .and_then(|b| BasicOcspResponse::from_der(b.response.as_bytes()).ok())
    else {
        return vec![];
    };
    let Some(certs) = basic.certs.as_ref() else {
        return vec![];
    };
    certs
        .iter()
        .enumerate()
        .filter_map(|(k, cert)| {
            let der = cert.to_der().ok()?;
            Some((format!("{hop}-ocsp-{resp}-cert-{k}.der"), der))
        })
        .collect()
}

/// Renders the "Revocation status determination details" section: what settled the revocation
/// status of each certificate on the path, and what the evidence said.
///
/// A section of its own, after the algorithm outputs, following PITTv2 -- revocation is not an RFC
/// 5280 path-validation output and reads oddly among them, and a reader asking "why does it say
/// revoked?" is looking for one place rather than a line inside each certificate's block.
///
/// Positions are hops: certificate #1 is the one the trust anchor issued. A trust anchor has no
/// revocation status, so it has no entry, and a hop nothing was determined for is named as such
/// rather than omitted -- silence there is indistinguishable from a hop that was checked and found
/// good, which is the distinction the section exists to make.
pub fn render_revocation_details(
    f: &mut dyn Write,
    path: &CertificationPath,
    cpr: &CertificationPathResults,
) {
    // What settled each hop comes from `revocation_outcomes_from_cpr`, the same function the results
    // views render their badges from, so the manifest and the screen cannot disagree.
    //
    // Reading the artifacts instead would be wrong, and was: a determination served from the
    // revocation status cache examines no CRL and no response and leaves nothing behind, so a hop
    // answered from cache has a status and no evidence. Driving the section off the evidence reported
    // "no revocation status was determined" for certificates the run had in fact found to be not
    // revoked. The artifacts are the detail beneath the answer, never the answer.
    let num_certs = path.intermediates.len() + 1;
    let outcomes = crate::report::revocation_outcomes_from_cpr(cpr, num_certs);
    if outcomes.is_empty() {
        return;
    }

    let chain: Vec<&PDVCertificate> = path
        .intermediates
        .iter()
        .chain(core::iter::once(&path.target))
        .collect();

    let ocsp = cpr.get_ocsp_responses();
    #[cfg(feature = "revocation")]
    let crls = cpr.get_crl();

    let mut out = String::new();
    for outcome in &outcomes {
        let pos = outcome.cert_index - 1;
        out.push_str(&format!("\t+ Certificate #{}\n", outcome.cert_index));
        out.push_str(&format!(
            "\t\t+ Status: {}\n",
            revocation_status_text(outcome.status)
        ));
        out.push_str(&format!(
            "\t\t+ Determined by: {}\n",
            revocation_method_text(outcome.method)
        ));

        if let Some(responses) = ocsp.as_ref().and_then(|v| v.get(pos)) {
            for (i, response) in responses.iter().enumerate() {
                out.push_str(&format!("\t\t+ OCSP response #{}\n", i + 1));
                let serial = chain
                    .get(pos)
                    .map(|c| c.decoded().tbs_certificate().serial_number().as_bytes());
                out.push_str(&render_ocsp_details(response, serial));
            }
        }
        #[cfg(feature = "revocation")]
        if let Some(hop_crls) = crls.as_ref().and_then(|v| v.get(pos)) {
            for (i, info) in hop_crls.iter().enumerate() {
                out.push_str(&format!("\t\t+ CRL #{}\n", i + 1));
                out.push_str(&render_crl_details(info));
            }
        }
    }

    f.write_all(
        "\n********************************************************************************\n"
            .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all("Revocation status determination details\n".as_bytes())
        .expect("Unable to write manifest file");
    f.write_all(
        "********************************************************************************\n"
            .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(out.as_bytes())
        .expect("Unable to write manifest file");
}

/// The revocation status of one certificate, worded for a manifest.
fn revocation_status_text(status: crate::report::RevocationStatus) -> &'static str {
    use crate::report::RevocationStatus::*;
    match status {
        NotRevoked => "not revoked",
        Revoked => "revoked",
        Undetermined => "could not be determined",
        NotChecked => "not checked",
    }
}

/// What settled a certificate's revocation status, worded for a manifest.
///
/// Says where the answer came from and not merely what kind of answer it was: a response the run was
/// handed and one it fetched are both OCSP but say different things about what the run did, and a
/// cached determination examined nothing at all this time -- which is exactly the case that has no
/// artifact in the bundle beside it.
fn revocation_method_text(method: crate::report::RevocationMethod) -> &'static str {
    use crate::report::RevocationMethod::*;
    match method {
        OcspNoCheck => "the OCSP no-check extension",
        Crl => "a CRL",
        Ocsp => "an OCSP response",
        Blocklist => "a configured blocklist",
        Allowlist => "a configured allowlist",
        Cache => "a cached determination, not revocation data examined for this path",
        StapledOcsp => "an OCSP response supplied to the run",
        StapledCrl => "a CRL supplied to the run",
        LocalCrl => "a CRL already held",
        OcspFromAia => "an OCSP response from an authority information access URI",
        RemoteCrlDp => "a CRL from a distribution point",
        None => "nothing",
    }
}

/// Renders one OCSP response's details, read out of the response itself rather than from anything
/// recorded alongside it, so the manifest describes the artifact the bundle carries.
fn render_ocsp_details(response: &[u8], serial: Option<&[u8]>) -> String {
    let mut out = String::new();
    let basic = match OcspResponse::from_der(response)
        .ok()
        .and_then(|r| r.response_bytes)
        .and_then(|b| BasicOcspResponse::from_der(b.response.as_bytes()).ok())
    {
        Some(basic) => basic,
        None => {
            out.push_str("\t\t\t+ Response could not be decoded\n");
            return out;
        }
    };

    let data = &basic.tbs_response_data;
    match &data.responder_id {
        ResponderId::ByName(name) => out.push_str(&format!(
            "\t\t\t+ OCSP responder name: {}\n",
            name_to_string(name)
        )),
        ResponderId::ByKey(key) => out.push_str(&format!(
            "\t\t\t+ OCSP responder key ID: {}\n",
            buffer_to_hex(key.as_bytes())
        )),
    }
    out.push_str(&format!(
        "\t\t\t+ Signature algorithm: {}\n",
        basic.signature_algorithm.oid
    ));
    out.push_str(&format!(
        "\t\t\t+ Produced at: {}\n",
        data.produced_at.0.to_date_time()
    ));

    // A responder may answer about many certificates in one response -- DoD's routinely returns a
    // batch of several dozen -- and all but one of those say nothing about this hop. Rendering the
    // batch would bury the single answer that matters among serial numbers from unrelated
    // certificates, so only the entry naming this certificate is shown.
    let singles: Vec<&SingleResponse> = match serial {
        Some(serial) => data
            .responses
            .iter()
            .filter(|s| s.cert_id.serial_number.as_bytes() == serial)
            .collect(),
        None => data.responses.iter().collect(),
    };
    if singles.is_empty() {
        out.push_str("\t\t\t+ The response carries no entry for this certificate\n");
        return out;
    }
    for single in singles {
        out.push_str(&format!(
            "\t\t\t+ This update: {}\n",
            single.this_update.0.to_date_time()
        ));
        if let Some(next) = &single.next_update {
            out.push_str(&format!("\t\t\t+ Next update: {}\n", next.0.to_date_time()));
        }
        out.push_str(&format!(
            "\t\t\t+ Certificate serial number: 0x{}\n",
            buffer_to_hex(single.cert_id.serial_number.as_bytes())
        ));
        match &single.cert_status {
            CertStatus::Good(_) => out.push_str("\t\t\t+ Certificate status: not revoked\n"),
            CertStatus::Revoked(info) => {
                out.push_str("\t\t\t+ Certificate status: revoked\n");
                out.push_str(&format!(
                    "\t\t\t+ Revocation time: {}\n",
                    info.revocation_time.0.to_date_time()
                ));
                if let Some(reason) = info.revocation_reason {
                    out.push_str(&format!("\t\t\t+ Revocation reason: {reason:?}\n"));
                }
            }
            CertStatus::Unknown(_) => out.push_str("\t\t\t+ Certificate status: unknown\n"),
        }
    }
    out
}

/// Renders a Unix epoch second count the way every other time in the manifest reads.
///
/// `CrlInfo` keeps its times as epoch seconds while a certificate's and an OCSP response's arrive as
/// ASN.1 times, so without this the same manifest reports one CRL as `1787147411` and the response
/// beside it as `2026-08-18T14:20:24Z`. Falls back to the raw number if the value is not a time this
/// can represent, which beats printing nothing.
#[cfg(feature = "revocation")]
fn unix_secs_as_time(secs: u64) -> String {
    match GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(secs)) {
        Ok(t) => t.to_date_time().to_string(),
        Err(_) => secs.to_string(),
    }
}

/// Renders one CRL's details from the compact [`CrlInfo`] the results retain.
///
/// The CRL body is not held there, so this reports where it came from as well as what it is: a
/// bundle may carry the note rather than the CRL, and a reader has to be able to tell which.
#[cfg(feature = "revocation")]
fn render_crl_details(info: &CrlInfo) -> String {
    let mut out = format!("\t\t\t+ CRL issuer: {}\n", info.issuer_name);
    if let Some(idp) = &info.idp_name {
        out.push_str(&format!("\t\t\t+ Issuing distribution point: {idp}\n"));
    }
    out.push_str(&format!(
        "\t\t\t+ This update: {}\n",
        unix_secs_as_time(info.this_update)
    ));
    if let Some(next) = info.next_update {
        out.push_str(&format!(
            "\t\t\t+ Next update: {}\n",
            unix_secs_as_time(next)
        ));
    }
    if let Some(uri) = &info.uri {
        out.push_str(&format!("\t\t\t+ Retrieved from: {uri}\n"));
    }
    out
}

/// Writes a CRL artifact into the manifest folder from the compact [`CrlInfo`] now retained in the
/// results (the results no longer carry the full CRL body). When the CRL was loaded from a folder
/// its cached bytes are copied out as a `.crl`; when it is only known by URI (e.g., fetched remotely
/// and not retained) a `.crl.txt` note is written recording where the full CRL can be re-obtained
/// along with its validity window.
#[cfg(feature = "std_app")]
fn write_crl_artifact(np: &Path, stem: &str, info: &CrlInfo) {
    if let Some(filename) = &info.filename {
        let p = np.join(format!("{stem}.crl"));
        if let Err(e) = fs::copy(filename, &p) {
            error!("Unable to copy cached CRL {filename} into manifest: {e}");
        }
        return;
    }

    let p = np.join(format!("{stem}.crl.txt"));
    let mut note = format!("issuer: {}\n", info.issuer_name);
    if let Some(uri) = &info.uri {
        note.push_str(&format!("uri: {uri}\n"));
    }
    if let Some(idp) = &info.idp_name {
        note.push_str(&format!("idp: {idp}\n"));
    }
    note.push_str(&format!("this_update: {}\n", info.this_update));
    if let Some(nu) = info.next_update {
        note.push_str(&format!("next_update: {nu}\n"));
    }
    if let Err(e) = fs::write(&p, note.as_bytes()) {
        error!("Unable to write CRL note {}: {e}", p.display());
    }
}

/// `log_path` contributes to the manifest file related to
/// [`CertificationPath`](../certval/path_settings/struct.CertificationPath.html) contents as well
/// as output generated by [`log_cps`] and [`log_cpr`].
#[cfg(feature = "std_app")]
pub fn log_path(
    pe: &PkiEnvironment,
    f: &Option<String>,
    path: &CertificationPath,
    index: usize,
    cpr: Option<&CertificationPathResults>,
    cps: Option<&CertificationPathSettings>,
) {
    let target_folder = if let Some(rf) = f { rf } else { "" };
    if target_folder.is_empty() {
        return;
    }

    let ta = &path.trust_anchor;
    let target = &path.target;

    let mut target_filename = target
        .locator()
        .map(get_file_stem_or_empty)
        .unwrap_or_default();

    if target_filename.is_empty() {
        let digest = Sha256::digest(path.target.as_bytes()).to_vec();
        target_filename = buffer_to_hex(digest.as_slice());
    }

    let ef = Path::new(&target_folder);
    let np1 = ef.join(Path::new(&target_filename));
    let r = fs::create_dir_all(&np1);
    if let Err(e) = r {
        error!("Failed to create directories for {target_folder} with: {e}");
    }

    let np = np1.join(Path::new(format!("{index}").as_str()));
    let r = fs::create_dir_all(&np);

    if let Err(e) = r {
        println!(
            "Failed to create directory {} with {:?}",
            np.to_str().unwrap_or(""),
            e
        );
    }
    let p = np.join(format!("{}-target.der", path.intermediates.len() + 1).as_str());
    fs::write(p, target.as_bytes()).expect("Unable to write target file");
    let p = np.join("0-ta.der");
    fs::write(p, ta.encoded_ta.as_slice()).expect("Unable to write TA file");

    for (i, ca) in path.intermediates.iter().enumerate() {
        let p = np.join(format!("{}.der", i + 1));
        fs::write(p, ca.as_bytes()).expect("Unable to write intermediate CA file");
    }

    if let Some(cpr) = cpr {
        let p = np.join("manifest.txt");
        let mut f = if let Ok(f) = File::create(p) {
            f
        } else {
            error!("Failed to create manifest file");
            return;
        };
        render_path_manifest(pe, &mut f, path, cpr, cps);
        write_cpr_artifacts(&np, cpr);
    }
}

/// Renders the manifest describing one certification path: the algorithm inputs, the path's
/// certificates, the validation outputs and the revocation determination details.
///
/// This is the whole of the manifest and the only place it is composed, so the file a results-folder
/// run writes and the entry an archive carries are the same document rather than two that agree
/// until one is edited. Nothing here touches a filesystem -- a caller supplies a `File`, a `Vec<u8>`,
/// or anything else that writes.
pub fn render_path_manifest(
    pe: &PkiEnvironment,
    f: &mut dyn Write,
    path: &CertificationPath,
    cpr: &CertificationPathResults,
    cps: Option<&CertificationPathSettings>,
) {
    {
        let s = get_filename_from_metadata(&path.target);
        f.write_all(format!("Certification path validation results for: {s}\n\n").as_bytes())
            .expect("Unable to write manifest file");
        f.write_all(
            "********************************************************************************\n"
                .as_bytes(),
        )
        .expect("Unable to write manifest file");
        f.write_all("Certification path validation algorithm inputs\n".as_bytes())
            .expect("Unable to write manifest file");
        f.write_all(
            "********************************************************************************\n"
                .as_bytes(),
        )
        .expect("Unable to write manifest file");
        if let Some(cps) = cps {
            log_cps(f, cps);
        } else {
            f.write_all("None".as_bytes())
                .expect("Unable to write manifest file");
        }
        f.write_all(
            "\n********************************************************************************\n"
                .as_bytes(),
        )
        .expect("Unable to write manifest file");
        f.write_all("Certification path details\n".as_bytes())
            .expect("Unable to write manifest file");
        f.write_all(
            "********************************************************************************\n"
                .as_bytes(),
        )
        .expect("Unable to write manifest file");
        f.write_all("\t+ Trust Anchor\n".as_bytes())
            .expect("Unable to write manifest file");
        log_ta_details(pe, f, &path.trust_anchor);

        for (i, c) in path.intermediates.iter().enumerate() {
            f.write_all(format!("\t+ Certificate #{}\n", i + 1).as_bytes())
                .expect("Unable to write manifest file");
            log_cert_details(pe, f, c);
        }

        f.write_all("\t+ Target Certificate\n".as_bytes())
            .expect("Unable to write manifest file");
        log_cert_details(pe, f, &path.target);

        f.write_all(
            "\n********************************************************************************\n"
                .as_bytes(),
        )
        .expect("Unable to write manifest file");
        f.write_all("Certification path results\n".as_bytes())
            .expect("Unable to write manifest file");
        f.write_all(
            "********************************************************************************\n"
                .as_bytes(),
        )
        .expect("Unable to write manifest file");
        render_cpr(f, cpr);
        render_revocation_details(f, path, cpr);
    }
}

#[test]
fn test_cps_log() {
    extern crate alloc;
    use alloc::string::ToString;

    use const_oid::db::rfc5280::{ANY_POLICY, ID_KP_SERVER_AUTH};
    use x509_cert::ext::pkix::KeyUsages;

    use certval::validator::path_settings::*;

    #[cfg(feature = "std_app")]
    let mut cps = CertificationPathSettings::new();
    cps.set_initial_explicit_policy_indicator(true);
    cps.set_initial_policy_mapping_inhibit_indicator(true);
    cps.set_initial_inhibit_any_policy_indicator(true);
    let policies = vec![ANY_POLICY.to_string()];
    cps.set_initial_policy_set(policies);
    let perm = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    cps.set_initial_permitted_subtrees(perm);
    let excl = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    cps.set_initial_excluded_subtrees(excl);
    cps.set_time_of_interest(TimeOfInterest::default());
    let ekus = vec![ID_KP_SERVER_AUTH.to_string()];
    cps.set_extended_key_usage(ekus);
    cps.set_extended_key_usage_path(false);
    cps.set_enforce_alg_and_key_size_constraints(false);
    cps.set_check_revocation_status(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_retrieve_from_aia_sia_http(false);
    cps.set_retrieve_from_aia_sia_ldap(false);
    cps.set_check_crls(false);
    cps.set_check_crldp_http(false);
    cps.set_check_crldp_ldap(false);
    cps.set_crl_grace_periods_as_last_resort(false);
    cps.set_ignore_expired(false);
    cps.set_ocsp_aia_nonce_setting(OcspNonceSetting::DoNotSendNonce);
    cps.set_require_country_code_indicator(false);
    let permcountries = vec!["AA".to_string()];
    cps.set_perm_countries(permcountries);
    let exclcountries = vec!["BB".to_string()];
    cps.set_perm_countries(exclcountries);
    let fs = KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    cps.set_target_key_usage(fs);

    use tempfile::tempdir;
    let temp_dir = tempdir().unwrap();
    let results_path = temp_dir.path().join("cps.txt");
    let mut f = File::create(results_path).unwrap();
    log_cps(&mut f, &cps);
}

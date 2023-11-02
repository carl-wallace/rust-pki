//! Supports generation of manifest files that describe certification path validation results
#![cfg(feature = "std_app")]

extern crate alloc;
use alloc::collections::BTreeMap;
use log::error;
use std::io::Write;
use std::{fs, fs::File, path::Path};

use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_EXT_KEY_USAGE, ID_CE_INHIBIT_ANY_POLICY, ID_CE_NAME_CONSTRAINTS,
    ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS, ID_CE_SUBJECT_KEY_IDENTIFIER,
};
use sha2::Digest;
use sha2::Sha256;
use x509_cert::ext::pkix::name::GeneralName;

use certval::source::ta_source::{buffer_to_hex, get_filename_from_ta_metadata};
use certval::util::pdv_utilities::*;
use certval::validator::pdv_trust_anchor::*;
use certval::*;

/// `get_filename_from_metadata` takes a [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) object and returns the value read from the
/// `MD_LOCATOR` entry in the metadata field, if present, or an empty string, if not present.
pub fn get_filename_from_metadata(cert: &PDVCertificate) -> String {
    if let Some(md) = &cert.metadata {
        if let Asn1MetadataTypes::String(filename) = &md[MD_LOCATOR] {
            return filename.to_owned();
        }
    }
    "".to_string()
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
pub fn log_cps(f: &mut File, cps: &CertificationPathSettings) {
    f.write_all(
        format!(
            "Initial explicit policy: {}\n",
            get_initial_explicit_policy_indicator(cps)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "Initial policy mapping inhibit: {}\n",
            get_initial_policy_mapping_inhibit_indicator(cps)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "Initial inhibit any policy: {}\n",
            get_initial_inhibit_any_policy_indicator(cps)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all("Initial policy set: \n".as_bytes())
        .expect("Unable to write manifest file");
    let policy_set = get_initial_policy_set(cps);
    for policy in policy_set {
        f.write_all(format!("\t* {}\n", policy).as_bytes())
            .expect("Unable to write manifest file");
    }
    f.write_all("Initial permitted names: \n".as_bytes())
        .expect("Unable to write manifest file");
    let mut ebufs = BTreeMap::new();
    let mut pbufs = BTreeMap::new();

    let perm = match get_initial_permitted_subtrees_as_set(cps, &mut pbufs) {
        Ok(ip) => ip,
        Err(_e) => None,
    };
    if let Some(perm) = perm {
        for gs in perm.user_principal_name {
            if let GeneralName::OtherName(on) = &gs.base {
                if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                    f.write_all(format!("\t\t\t* UPN: {:?}\n", on.value).as_bytes())
                        .expect("Unable to write manifest file");
                }
            }
        }
        for gs in perm.directory_name {
            if let GeneralName::DirectoryName(dn) = &gs.base {
                f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in perm.rfc822_name {
            if let GeneralName::Rfc822Name(rfc822) = &gs.base {
                f.write_all(format!("\t\t\t* RFC822 name: {}\n", rfc822).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in perm.uniform_resource_identifier {
            if let GeneralName::UniformResourceIdentifier(uri) = &gs.base {
                f.write_all(format!("\t\t\t* URI: {}\n", uri).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in perm.dns_name {
            if let GeneralName::DnsName(dns) = &gs.base {
                f.write_all(format!("\t\t\t* DNS name: {}\n", dns).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
    } else {
        f.write_all("\t* unconstrained\n".as_bytes())
            .expect("Unable to write manifest file");
    } // end if let Some(perm) = perm
    f.write_all("Initial excluded names: \n".as_bytes())
        .expect("Unable to write manifest file");
    let excl = match get_initial_excluded_subtrees_as_set(cps, &mut ebufs) {
        Ok(ie) => ie,
        Err(_e) => None,
    };
    if let Some(excl) = excl {
        for gs in excl.user_principal_name {
            if let GeneralName::OtherName(on) = &gs.base {
                if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                    f.write_all(format!("\t\t\t* UPN: {:?}\n", on.value).as_bytes())
                        .expect("Unable to write manifest file");
                }
            }
        }
        for gs in excl.directory_name {
            if let GeneralName::DirectoryName(dn) = &gs.base {
                f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in excl.rfc822_name {
            if let GeneralName::Rfc822Name(rfc822) = &gs.base {
                f.write_all(format!("\t\t\t* RFC822 name: {}\n", rfc822).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in excl.uniform_resource_identifier {
            if let GeneralName::UniformResourceIdentifier(uri) = &gs.base {
                f.write_all(format!("\t\t\t* URI: {}\n", uri).as_bytes())
                    .expect("Unable to write manifest file");
            }
        }
        for gs in excl.dns_name {
            if let GeneralName::DnsName(dns) = &gs.base {
                f.write_all(format!("\t\t\t* DNS name: {}\n", dns).as_bytes())
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
            get_enforce_trust_anchor_constraints(cps)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "Enforce algorithm and key size constraints: {}\n",
            get_enforce_alg_and_key_size_constraints(cps)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(format!("Check revocation: {}\n", get_check_revocation_status(cps)).as_bytes())
        .expect("Unable to write manifest file");
}

/// `log_ta_details` contributes to the manifest file related to
/// [`PDVTrustAnchor`](../certval/pdv_certificate/struct.PDVTrustAnchor.html) contents.
pub fn log_ta_details(_pe: &PkiEnvironment, f: &mut File, ta: &PDVTrustAnchorChoice) {
    // TODO - implement me
    f.write_all(format!("\t\t* Source: {}\n", get_filename_from_ta_metadata(ta)).as_bytes())
        .expect("Unable to write manifest file");
}

/// `log_cert_details` contributes to the manifest file related to
/// [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) contents.
pub fn log_cert_details(pe: &PkiEnvironment, f: &mut File, cert: &PDVCertificate) {
    f.write_all(
        format!(
            "\t\t* Issuer Name: {}\n",
            name_to_string(&cert.decoded_cert.tbs_certificate.issuer)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Subject Name: {}\n",
            name_to_string(&cert.decoded_cert.tbs_certificate.subject)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Serial Number: 0x{}\n",
            buffer_to_hex(cert.decoded_cert.tbs_certificate.serial_number.as_bytes())
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Not Before: {}\n",
            &cert
                .decoded_cert
                .tbs_certificate
                .validity
                .not_before
                .to_string()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Not After: {}\n",
            &cert
                .decoded_cert
                .tbs_certificate
                .validity
                .not_after
                .to_string()
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Public key algorithm: {}\n",
            pe.oid_lookup(
                &cert
                    .decoded_cert
                    .tbs_certificate
                    .subject_public_key_info
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
                .decoded_cert
                .tbs_certificate
                .subject_public_key_info
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
            pe.oid_lookup(&cert.decoded_cert.tbs_certificate.signature.oid)
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
                        "\t\t* Path length constraint: only {} CA certificate(s) may follow\n",
                        plc
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
            f.write_all(format!("\t\t* Require explicit policy: {}\n", re).as_bytes())
                .expect("Unable to write manifest file");
        }
        if let Some(re) = pc.inhibit_policy_mapping {
            f.write_all(format!("\t\t* Inhibit policy mapping: {}\n", re).as_bytes())
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
            f.write_all(format!("\t\t* Authority key identifier: {}\n", akid_hex).as_bytes())
                .expect("Unable to write manifest file");
        }
        if let Some(iss) = &akid.authority_cert_issuer {
            f.write_all("\t\t* Authority certificate issuer\n".as_bytes())
                .expect("Unable to write manifest file");
            for gn in iss {
                match gn {
                    GeneralName::OtherName(on) => {
                        if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                            f.write_all(format!("\t\t\t* UPN: {:?}\n", on.value).as_bytes())
                                .expect("Unable to write manifest file");
                        } else {
                            f.write_all(
                                format!("\t\t\t* Unsupported OtherName of type {:?}\n", on.type_id)
                                    .as_bytes(),
                            )
                            .expect("Unable to write manifest file");
                        }
                    }
                    GeneralName::Rfc822Name(rfc822) => {
                        f.write_all(format!("\t\t\t* RFC822 name: {}\n", rfc822).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DnsName(dns) => {
                        f.write_all(format!("\t\t\t* DNS name: {}\n", dns).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DirectoryName(dn) => {
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::UniformResourceIdentifier(uri) => {
                        f.write_all(format!("\t\t\t* URI: {}\n", uri).as_bytes())
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
            f.write_all(
                format!("\t\t* Authority certificate serial number: {:?}\n", &iss).as_bytes(),
            )
            .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&ID_CE_SUBJECT_KEY_IDENTIFIER);
    if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = pdv_ext {
        let skid_hex = buffer_to_hex(skid.0.as_bytes());
        f.write_all(format!("\t\t* Subject key identifier: {}\n", skid_hex).as_bytes())
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
            f.write_all(format!("\t\t\t* {}\n", p).as_bytes())
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
                        if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                            f.write_all(format!("\t\t\t* UPN: {:?}\n", on.value).as_bytes())
                                .expect("Unable to write manifest file");
                        } else {
                            f.write_all(
                                format!("\t\t\t* Unsupported OtherName of type {:?}\n", on.type_id)
                                    .as_bytes(),
                            )
                            .expect("Unable to write manifest file");
                        }
                    }
                    GeneralName::Rfc822Name(rfc822) => {
                        f.write_all(format!("\t\t\t* RFC822 name: {}\n", rfc822).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DnsName(dns) => {
                        f.write_all(format!("\t\t\t* DNS name: {}\n", dns).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DirectoryName(dn) => {
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::UniformResourceIdentifier(uri) => {
                        f.write_all(format!("\t\t\t* URI: {}\n", uri).as_bytes())
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
                        if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                            f.write_all(format!("\t\t\t* UPN: {:?}\n", on.value).as_bytes())
                                .expect("Unable to write manifest file");
                        } else {
                            f.write_all(
                                format!("\t\t\t* Unsupported OtherName of type {:?}\n", on.type_id)
                                    .as_bytes(),
                            )
                            .expect("Unable to write manifest file");
                        }
                    }
                    GeneralName::Rfc822Name(rfc822) => {
                        f.write_all(format!("\t\t\t* RFC822 name: {}\n", rfc822).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DnsName(dns) => {
                        f.write_all(format!("\t\t\t* DNS name: {}\n", dns).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::DirectoryName(dn) => {
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(dn)).as_bytes())
                            .expect("Unable to write manifest file");
                    }
                    GeneralName::UniformResourceIdentifier(uri) => {
                        f.write_all(format!("\t\t\t* URI: {}\n", uri).as_bytes())
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
pub fn log_cpr(_pe: &PkiEnvironment, f: &mut File, np: &Path, cpr: &CertificationPathResults) {
    let status = get_validation_status(cpr);
    if let Some(status) = status {
        f.write_all(format!("Status: {:?}\n\n", status).as_bytes())
            .expect("Unable to write manifest file");
    }

    let vpt = get_final_valid_policy_tree(cpr);
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

    // TODO add CRL and OCSP details to manifest (probably best to wait until CrlInfo is in CPR)

    // i + i in the below loops because TAs are not considered here (and the indexes for artifcacts uses
    // TAs in slot 0).
    if let Some(ocsp_reqs) = get_ocsp_requests(cpr) {
        for (i, or) in ocsp_reqs.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, ir) in or.iter().enumerate() {
                let p = if suffix {
                    np.join(format!("{}-ocsp-{}.ocspReq", i + 1, j).as_str())
                } else {
                    np.join(format!("{}-ocsp.ocspReq", i + 1).as_str())
                };
                fs::write(p, ir).expect("Unable to write OCSP request");
            }
        }
    }
    if let Some(ocsp_resp) = get_ocsp_responses(cpr) {
        for (i, or) in ocsp_resp.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, ir) in or.iter().enumerate() {
                let p = if suffix {
                    np.join(format!("{}-ocsp-{}.ocspResp", i + 1, j).as_str())
                } else {
                    np.join(format!("{}-ocsp.ocspResp", i + 1).as_str())
                };
                fs::write(p, ir).expect("Unable to write OCSP response");
            }
        }
    }
    if let Some(ocsp_reqs) = get_failed_ocsp_requests(cpr) {
        for (i, or) in ocsp_reqs.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, ir) in or.iter().enumerate() {
                let p = if suffix {
                    np.join(format!("{}-ocsp-{}.failed.ocspReq", i + 1, j).as_str())
                } else {
                    np.join(format!("{}-ocsp.failed.ocspReq", i + 1).as_str())
                };
                fs::write(p, ir).expect("Unable to write OCSP request");
            }
        }
    }
    if let Some(ocsp_resp) = get_failed_ocsp_responses(cpr) {
        for (i, or) in ocsp_resp.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, ir) in or.iter().enumerate() {
                let p = if suffix {
                    np.join(format!("{}-ocsp-{}.failed.ocspResp", i + 1, j).as_str())
                } else {
                    np.join(format!("{}-ocsp.failed.ocspResp", i + 1).as_str())
                };
                fs::write(p, ir).expect("Unable to write OCSP response");
            }
        }
    }
    if let Some(crls) = get_crl(cpr) {
        for (i, or) in crls.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, ir) in or.iter().enumerate() {
                let p = if suffix {
                    np.join(format!("{}-crl-{}.crl", i + 1, j).as_str())
                } else {
                    np.join(format!("{}-crl.crl", i + 1).as_str())
                };
                fs::write(p, ir).expect("Unable to write CRL");
            }
        }
    }
    if let Some(crls) = get_failed_crls(cpr) {
        for (i, or) in crls.iter().enumerate() {
            let suffix = or.len() > 1;
            for (j, ir) in or.iter().enumerate() {
                let p = if suffix {
                    np.join(format!("{}-crl-{}.failed.crl", i + 1, j).as_str())
                } else {
                    np.join(format!("{}-crl.failed.crl", i + 1).as_str())
                };
                fs::write(p, ir).expect("Unable to write CRL");
            }
        }
    }
}

/// `log_path` contributes to the manifest file related to
/// [`CertificationPath`](../certval/path_settings/struct.CertificationPath.html) contents as well
/// as output generated by [`log_cps`] and [`log_cpr`].
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

    let mut target_filename = if let Some(md) = &target.metadata {
        if let Asn1MetadataTypes::String(filename) = &md[MD_LOCATOR] {
            get_file_stem_or_empty(filename)
        } else {
            "".to_string()
        }
    } else {
        "".to_string()
    };

    if target_filename.is_empty() {
        let digest = Sha256::digest(path.target.encoded_cert.as_slice()).to_vec();
        target_filename = buffer_to_hex(digest.as_slice());
    }

    let ef = Path::new(&target_folder);
    let np1 = ef.join(Path::new(&target_filename));
    let r = fs::create_dir_all(&np1);
    if let Err(e) = r {
        error!(
            "Failed to create directories for {} with: {}",
            target_folder, e
        );
    }

    let np = np1.join(Path::new(format!("{}", index).as_str()));
    let r = fs::create_dir_all(&np);

    if let Err(e) = r {
        println!(
            "Failed to create directory {} with {:?}",
            np.to_str().unwrap_or(""),
            e
        );
    }
    let p = np.join(format!("{}-target.der", path.intermediates.len() + 1).as_str());
    fs::write(p, target.encoded_cert.as_slice()).expect("Unable to write target file");
    let p = np.join("0-ta.der");
    fs::write(p, ta.encoded_ta.as_slice()).expect("Unable to write TA file");

    for (i, ca) in path.intermediates.iter().enumerate() {
        let p = np.join(format!("{}.der", i + 1));
        fs::write(p, ca.encoded_cert.as_slice()).expect("Unable to write intermediate CA file");
    }

    if let Some(cpr) = cpr {
        let p = np.join("manifest.txt");
        let mut f = if let Ok(f) = File::create(p) {
            f
        } else {
            error!("Failed to create manifest file");
            return;
        };
        let s = get_filename_from_metadata(&path.target);
        f.write_all(format!("Certification path validation results for: {}\n\n", s).as_bytes())
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
            log_cps(&mut f, cps);
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
        log_ta_details(pe, &mut f, &path.trust_anchor);

        for (i, c) in path.intermediates.iter().enumerate() {
            f.write_all(format!("\t+ Certificate #{}\n", i + 1).as_bytes())
                .expect("Unable to write manifest file");
            log_cert_details(pe, &mut f, c);
        }

        f.write_all("\t+ Target Certificate\n".as_bytes())
            .expect("Unable to write manifest file");
        log_cert_details(pe, &mut f, &path.target);

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
        log_cpr(pe, &mut f, &np, cpr);
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
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut cps = CertificationPathSettings::new();
    set_initial_explicit_policy_indicator(&mut cps, true);
    set_initial_policy_mapping_inhibit_indicator(&mut cps, true);
    set_initial_inhibit_any_policy_indicator(&mut cps, true);
    let policies = vec![ANY_POLICY.to_string()];
    set_initial_policy_set(&mut cps, policies);
    let perm = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        user_principal_name: Some(vec!["1234567890@mil".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
    };
    set_initial_permitted_subtrees(&mut cps, perm);
    let excl = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        user_principal_name: Some(vec!["0987654321@mil".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
    };
    set_initial_excluded_subtrees(&mut cps, excl);
    let toi = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        n.as_secs()
    } else {
        0
    };
    set_time_of_interest(&mut cps, toi);
    let ekus = vec![ID_KP_SERVER_AUTH.to_string()];
    set_extended_key_usage(&mut cps, ekus);
    set_extended_key_usage_path(&mut cps, false);
    set_enforce_alg_and_key_size_constraints(&mut cps, false);
    set_check_revocation_status(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    set_retrieve_from_aia_sia_http(&mut cps, false);
    set_retrieve_from_aia_sia_ldap(&mut cps, false);
    set_check_crls(&mut cps, false);
    set_check_crldp_http(&mut cps, false);
    set_check_crldp_ldap(&mut cps, false);
    set_crl_grace_periods_as_last_resort(&mut cps, false);
    set_ignore_expired(&mut cps, false);
    set_ocsp_aia_nonce_setting(&mut cps, OcspNonceSetting::DoNotSendNonce);
    set_require_country_code_indicator(&mut cps, false);
    let permcountries = vec!["AA".to_string()];
    set_perm_countries(&mut cps, permcountries);
    let exclcountries = vec!["BB".to_string()];
    set_perm_countries(&mut cps, exclcountries);
    let fs = KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    set_target_key_usage(&mut cps, fs.bits());

    use tempfile::tempdir;
    let temp_dir = tempdir().unwrap();
    let results_path = temp_dir.path().join("cps.txt");
    let mut f = File::create(results_path).unwrap();
    log_cps(&mut f, &cps);
}

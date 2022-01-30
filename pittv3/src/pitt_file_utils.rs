//! Contains utility functions related to interactions with the filesystem

use crate::pitt_utils::*;
use crate::{PVStats, PathValidationStats, PathValidationStatsGroup, Pittv3Args};
use certval::cert_source::CertFile;
use certval::pdv_utilities::*;
use certval::ta_source::{buffer_to_hex, get_filename_from_ta_metadata};
use certval::*;
use core::ops::Deref;
use der::Decodable;
use sha2::Digest;
use sha2::Sha256;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;
use x509::{
    Certificate, GeneralName, PKIX_CE_AUTHORITY_KEY_IDENTIFIER, PKIX_CE_BASIC_CONSTRAINTS,
    PKIX_CE_CERTIFICATE_POLICIES, PKIX_CE_EXTKEYUSAGE, PKIX_CE_INHIBIT_ANY_POLICY,
    PKIX_CE_KEY_USAGE, PKIX_CE_NAME_CONSTRAINTS, PKIX_CE_POLICY_CONSTRAINTS,
    PKIX_CE_POLICY_MAPPINGS, PKIX_CE_SUBJECT_KEY_IDENTIFIER,
};

use std::error;
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// `get_file_as_byte_vec` takes a Path containing a file name and returns a vector of bytes containing
/// the contents of that file or a std::io::Error.
pub fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(&filename)?;
    let metadata = std::fs::metadata(&filename)?;
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// `load_tas` takes a string containing the full path of a folder containing binary DER encoded
/// certificate files. It returns a map containing buffers read from files and the filename
pub fn certs_folder_to_map(
    pe: &PkiEnvironment,
    certsdir: &str,
    certsvec: &mut Vec<CertFile>,
    t: u64,
) -> Result<usize> {
    if !Path::is_dir(Path::new(certsdir)) {
        println!("{} does not exist or is not a directory", certsdir);
        return Ok(0);
    }

    let initial_count = certsvec.len();
    for entry in WalkDir::new(certsdir) {
        match entry {
            Ok(entry) => {
                let e = entry;
                if e.file_type().is_dir() {
                    if e.path().to_str().unwrap() != certsdir {
                        println!("Recursing {}", e.path().display());
                        let s = e.path().to_str();
                        match s {
                            Some(s) => {
                                let r = certs_folder_to_map(pe, s, certsvec, t);
                                if r.is_err() {
                                    continue;
                                }
                            }
                            _ => {
                                continue;
                            }
                        };
                    }
                } else {
                    let buffer = get_file_as_byte_vec(e.path())?;
                    //TODO - handle TrustAnchorChoice

                    // make sure it parses before saving buffer
                    let r = Certificate::from_der(buffer.as_slice());
                    if let Ok(cert) = r {
                        let r = valid_at_time(pe, &cert.tbs_certificate, t, true);
                        if let Err(_e) = r {
                            pe.log_message(
                                &PeLogLevels::PeError,
                                format!(
                                    "Ignored {} as not valid at indicated time of interest",
                                    e.path().to_str().unwrap()
                                )
                                .as_str(),
                            );
                        } else {
                            let cf = CertFile {
                                filename: e.path().to_str().unwrap().to_string(),
                                bytes: buffer,
                            };
                            if !certsvec.contains(&cf) {
                                certsvec.push(cf);
                            }
                        }
                    }
                }
            }
            _ => {
                println!("Failed to unwrap entry");
                continue;
            }
        }
    }
    Ok(certsvec.len() - initial_count)
}

/// `certs_folder_to_certfile_vec` takes a folder, `certsdir` that is recursively processed to discover certificate
/// files that are read and placed into the `certsvec` parameter. Certificates that are not valid at the
/// indicated time `t` are ignored.
///
/// Only files with .der, .cer and .crt extensions are processed.
pub fn certs_folder_to_certfile_vec(
    pe: &PkiEnvironment,
    certsdir: &str,
    certsvec: &mut Vec<CertFile>,
    t: u64,
) -> Result<usize> {
    if !Path::is_dir(Path::new(certsdir)) {
        println!("{} does not exist or is not a directory", certsdir);
        return Ok(0);
    }

    let initial_count = certsvec.len();
    for entry in WalkDir::new(certsdir) {
        match entry {
            Ok(entry) => {
                let e = entry;
                if e.file_type().is_dir() {
                    if e.path().to_str().unwrap() != certsdir {
                        println!("Recursing {}", e.path().display());
                        let s = e.path().to_str();
                        match s {
                            Some(s) => {
                                let r = certs_folder_to_certfile_vec(pe, s, certsvec, t);
                                if r.is_err() {
                                    continue;
                                }
                            }
                            _ => {
                                continue;
                            }
                        };
                    }
                    continue;
                } else {
                    if let Some(ext) = e.path().extension().and_then(OsStr::to_str) {
                        if !["der", "crt", "cer"].contains(&ext) {
                            continue;
                        }
                    }

                    let buffer = get_file_as_byte_vec(e.path())?;
                    //TODO - handle TrustAnchorChoice

                    // make sure it parses before saving buffer
                    let r = Certificate::from_der(buffer.as_slice());
                    if let Ok(cert) = r {
                        let r = valid_at_time(pe, &cert.tbs_certificate, t, true);
                        if let Err(_e) = r {
                            pe.log_message(
                                &PeLogLevels::PeError,
                                format!(
                                    "Ignored {} as not valid at indicated time of interest",
                                    e.path().to_str().unwrap()
                                )
                                .as_str(),
                            );
                            continue;
                        }

                        if is_self_signed_with_buffer(pe, &cert, buffer.as_slice()) {
                            if let Some(s) = e.path().to_str() {
                                pe.log_message(
                                    &PeLogLevels::PeInfo,
                                    format!("Ignoring {} as self-signed", s).as_str(),
                                );
                            }
                            continue;
                        }

                        let cf = CertFile {
                            filename: e.path().to_str().unwrap().to_string(),
                            bytes: buffer,
                        };
                        if !certsvec.contains(&cf) {
                            certsvec.push(cf);
                        }
                    }
                }
            }
            _ => {
                pe.log_message(
                    &PeLogLevels::PeError,
                    "Failed to unwrap entry in certs_folder_to_certfile_vec",
                );
                continue;
            }
        }
    }
    Ok(certsvec.len() - initial_count)
}

/// `get_filename_from_metadata` takes a [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) object and returns the value read from the
/// `MD_LOCATOR` entry in the metadata field, if present, or an empty string, if not present.
fn get_filename_from_metadata(cert: &PDVCertificate) -> String {
    if let Some(md) = &cert.metadata {
        if let Asn1MetadataTypes::String(filename) = &md[MD_LOCATOR] {
            return filename.to_owned();
        }
    }
    "".to_string()
}

/// `log_cps` contributes to the manifest file related to
/// [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html) contents.
fn log_cps(pe: &PkiEnvironment, f: &mut File, cps: &CertificationPathSettings) {
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
    let perm = get_initial_permitted_subtrees(cps);
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
                f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(pe, dn)).as_bytes())
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
    let excl = get_initial_excluded_subtrees(cps);
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
                f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(pe, dn)).as_bytes())
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
fn log_ta_details(_pe: &PkiEnvironment, f: &mut File, ta: &PDVTrustAnchorChoice) {
    // TODO - implement me
    f.write_all(format!("\t\t* Source: {}\n", get_filename_from_ta_metadata(ta)).as_bytes())
        .expect("Unable to write manifest file");
}

/// `log_cert_details` contributes to the manifest file related to
/// [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) contents.
fn log_cert_details(pe: &PkiEnvironment, f: &mut File, cert: &PDVCertificate) {
    f.write_all(
        format!(
            "\t\t* Issuer Name: {}\n",
            name_to_string(pe, &cert.decoded_cert.tbs_certificate.issuer)
        )
        .as_bytes(),
    )
    .expect("Unable to write manifest file");
    f.write_all(
        format!(
            "\t\t* Subject Name: {}\n",
            name_to_string(pe, &cert.decoded_cert.tbs_certificate.subject)
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

    let pdv_ext = cert.get_extension(&PKIX_CE_BASIC_CONSTRAINTS);
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

    let pdv_ext = cert.get_extension(&PKIX_CE_CERTIFICATE_POLICIES);
    if let Ok(Some(PDVExtension::CertificatePolicies(cp))) = pdv_ext {
        f.write_all("\t\t* Certificate policies\n".as_bytes())
            .expect("Unable to write manifest file");
        for p in cp {
            f.write_all(format!("\t\t\t* {}\n", p.policy_identifier).as_bytes())
                .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&PKIX_CE_POLICY_CONSTRAINTS);
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

    let pdv_ext = cert.get_extension(&PKIX_CE_INHIBIT_ANY_POLICY);
    if let Ok(Some(PDVExtension::InhibitAnyPolicy(iap))) = pdv_ext {
        f.write_all(format!("\t\t* Inhibit any policy: {}\n", iap).as_bytes())
            .expect("Unable to write manifest file");
    }

    let pdv_ext = cert.get_extension(&PKIX_CE_POLICY_MAPPINGS);
    if let Ok(Some(PDVExtension::PolicyMappings(pm))) = pdv_ext {
        f.write_all("\t\t* Policy mappings\n".as_bytes())
            .expect("Unable to write manifest file");
        for p in pm {
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

    let pdv_ext = cert.get_extension(&PKIX_CE_AUTHORITY_KEY_IDENTIFIER);
    if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = pdv_ext {
        if let Some(kid) = akid.key_identifier {
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
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(pe, dn)).as_bytes())
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
        if let Some(iss) = akid.authority_cert_serial_number {
            f.write_all(
                format!("\t\t* Authority certificate serial number: {:?}\n", &iss).as_bytes(),
            )
            .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&PKIX_CE_SUBJECT_KEY_IDENTIFIER);
    if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = pdv_ext {
        let skid_hex = buffer_to_hex(skid.as_bytes());
        f.write_all(format!("\t\t* Subject key identifier: {}\n", skid_hex).as_bytes())
            .expect("Unable to write manifest file");
    }

    let pdv_ext = cert.get_extension(&PKIX_CE_KEY_USAGE);
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

    let pdv_ext = cert.get_extension(&PKIX_CE_EXTKEYUSAGE);
    if let Ok(Some(PDVExtension::ExtendedKeyUsage(eku))) = pdv_ext {
        f.write_all("\t\t* Extended key usage\n".as_bytes())
            .expect("Unable to write manifest file");
        for p in eku {
            f.write_all(format!("\t\t\t* {}\n", p).as_bytes())
                .expect("Unable to write manifest file");
        }
    }

    let pdv_ext = cert.get_extension(&PKIX_CE_NAME_CONSTRAINTS);
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
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(pe, dn)).as_bytes())
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
                        f.write_all(format!("\t\t\t* DN: {}\n", name_to_string(pe, dn)).as_bytes())
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
fn log_cpr(_pe: &PkiEnvironment, f: &mut File, cpr: &CertificationPathResults) {
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
}

/// `get_file_stem_or_empty` returns stem of indicated file if it can be read or an empty string.
fn get_file_stem_or_empty(filename: &str) -> String {
    let path = Path::new(filename);
    if let Some(stem) = path.file_stem() {
        if let Some(str_stem) = stem.to_str() {
            return str_stem.to_string();
        }
    }
    "".to_string()
}

/// `log_path` contributes to the manifest file related to
/// [`CertificationPath`](../certval/path_settings/struct.CertificationPath.html) contents as well
/// as output generated by [`log_cps`] and [`log_cpr`].
fn log_path(
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

    let ta = path.trust_anchor;
    let target = path.target;

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
        let digest = Sha256::digest(path.target.encoded_cert).to_vec();
        target_filename = buffer_to_hex(digest.as_slice());
    }

    let ef = Path::new(&target_folder);
    let np1 = ef.join(Path::new(&target_filename));
    let r = fs::create_dir_all(&np1);
    if let Err(e) = r {
        log_message(
            &PeLogLevels::PeError,
            format!(
                "Failed to create directories for {} with: {}",
                target_folder, e
            )
            .as_str(),
        );
    }

    let np = np1.join(Path::new(format!("{}", index).as_str()));
    let r = fs::create_dir_all(&np);

    if let Err(e) = r {
        println!(
            "Failed to create directory {} with {:?}",
            np.to_str().unwrap(),
            e
        );
    }
    let p = np.join(format!("{}-target.der", path.intermediates.len() + 1).as_str());
    fs::write(p, target.encoded_cert).expect("Unable to write target file");
    let p = np.join("0-ta.der");
    fs::write(p, ta.encoded_ta).expect("Unable to write TA file");

    for (i, ca) in path.intermediates.iter().enumerate() {
        let p = np.join(format!("{}.der", i + 1));
        fs::write(p, ca.encoded_cert).expect("Unable to write intermediate CA file");
    }

    if let Some(cpr) = cpr {
        let p = np.join("manifest.txt");
        let mut f = File::create(p).unwrap();
        let s = get_filename_from_metadata(path.target);
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
            log_cps(pe, &mut f, cps);
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
        log_ta_details(pe, &mut f, path.trust_anchor);

        for (i, c) in path.intermediates.iter().enumerate() {
            f.write_all(format!("\t+ Certificate #{}\n", i + 1).as_bytes())
                .expect("Unable to write manifest file");
            log_cert_details(pe, &mut f, c.deref());
        }

        f.write_all("\t+ Target Certificate\n".as_bytes())
            .expect("Unable to write manifest file");
        log_cert_details(pe, &mut f, path.target);

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
        log_cpr(pe, &mut f, cpr);
    }
}

/// `validate_cert_file` attempts to validate the certificate read from the file indicated by
/// `cert_filename` using the resources available via the
/// [`PkiEnvironment`](../certval/pki_environment/struct.PkiEnvironment.html) parameter and the settings
/// available via [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html)
/// parameter.
///
/// Path building is governed by the `threshold` parameter, i.e., only paths with at least one
/// certificate at an index above the threshold will be validated. The `args` parameter contributes
/// `results_folder`, `validate_all`, `error_folder` and `dynamic_build`. Each path that is processed
/// will be saved to the `results_folder`, if present in `args`. If `validate_all` is specified,
/// validation will be attempted for all paths that were found by the builder. If `error_folder` is
/// specified, paths that fail validation will be logged there (in addition to the results_folder).
/// If `dynamic_build` is set, then URIs from the AIA and SIA extension of any trust anchor or
/// intermediate CA cert will be added to `fresh_uris` if not already present. The `stats` parameter
/// is used to get bearings for indices when writing out paths.
pub(crate) fn validate_cert_file(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cert_filename: &str,
    stats: &mut PathValidationStats,
    args: &Pittv3Args,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) {
    let time_of_interest = get_time_of_interest(cps);

    let target = if let Ok(t) = get_file_as_byte_vec(Path::new(&cert_filename)) {
        t
    } else {
        pe.log_message(
            &PeLogLevels::PeError,
            format!("Failed to read file at {}", cert_filename).as_str(),
        );
        return;
    };

    let parsed_cert = parse_cert(target.as_slice(), cert_filename);
    if let Some(target_cert) = parsed_cert {
        pe.log_message(
            &PeLogLevels::PeDebug,
            format!("Start build and validate path(s) for {}", cert_filename).as_str(),
        );

        let start2 = Instant::now();

        stats.files_processed += 1;

        let mut paths: Vec<CertificationPath> = vec![];
        let r = pe.get_paths_for_target(pe, &target_cert, &mut paths, threshold, time_of_interest);
        if let Err(e) = r {
            println!(
                "Failed to find certification paths for target with error {:?}",
                e
            );
            pe.log_message(
                &PeLogLevels::PeError,
                format!(
                    "Failed to find certification paths for target with error {:?}",
                    e
                )
                .as_str(),
            );
            return;
        }

        if paths.is_empty() {
            collect_uris_from_aia_and_sia(&target_cert, fresh_uris);
            pe.log_message(
                &PeLogLevels::PeInfo,
                "Failed to find any certification paths for target",
            );
            return;
        }

        for (i, path) in paths.iter_mut().enumerate() {
            let mut cpr = CertificationPathResults::new();
            let r = pe.validate_path(pe, cps, path, &mut cpr);
            log_path(
                pe,
                &args.results_folder,
                path,
                stats.paths_per_target + i,
                Some(&cpr),
                Some(cps),
            );
            stats.results.push(cpr.clone());
            match r {
                Ok(_) => {
                    stats.valid_paths_per_target += 1;

                    pe.log_message(
                        &PeLogLevels::PeInfo,
                        format!("Successfully validated {}", cert_filename).as_str(),
                    );
                    if !args.validate_all {
                        break;
                    }
                }
                Err(e) => {
                    stats.invalid_paths_per_target += 1;

                    pe.log_message(
                        &PeLogLevels::PeError,
                        format!("Failed to validate {} with {:?}", cert_filename, e).as_str(),
                    );
                    log_path(pe, &args.error_folder, path, i, None, None);
                }
            }
            if args.dynamic_build {
                // if we get here we are validating all possible paths with dynamic building. gather
                // up URIs from the trust anchor
                collect_uris_from_aia_and_sia_from_ta(path.trust_anchor, fresh_uris);

                // This is possibly overkill as CA certs are processed during preparing of partial
                // paths following dynamic building. Without this, then URIs from certs in the
                // intially deserialized CBOR may not be followed.
                for c in path.intermediates.iter() {
                    collect_uris_from_aia_and_sia(c, fresh_uris);
                }
            }
        }
        stats.paths_per_target += paths.len();

        let finish = Instant::now();
        let duration2 = finish - start2;
        pe.log_message(
            &PeLogLevels::PeInfo,
            format!(
                "{:?} to build and validate {} path(s) for {}",
                duration2,
                paths.len(),
                cert_filename
            )
            .as_str(),
        );
    } else {
        // parse_cert writes out an error
        // pe.log_message(
        //     &PeError,
        //     format!("Failed to parse certificate from file {}", cert_filename).as_str(),
        // );
    }
}

/// `validate_cert_folder` recursively iterates over the contents of the folder identified by the
/// certs folder parameter and invokes [`validate_cert_file`] for files with .der, .cer or .crt file
/// extension.
pub fn validate_cert_folder(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    certs_folder: &str,
    stats: &mut PathValidationStatsGroup,
    args: &Pittv3Args,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) {
    for entry in WalkDir::new(certs_folder) {
        match entry {
            Ok(entry) => {
                let e = entry;
                if e.file_type().is_dir() {
                    if e.path().to_str().unwrap() != certs_folder {
                        println!("Recursing {}", e.path().display());
                        if let Some(s) = e.path().to_str() {
                            validate_cert_folder(pe, cps, s, stats, args, fresh_uris, threshold);
                        } else {
                            pe.log_message(
                                &PeLogLevels::PeError,
                                "Skipping file due to invalid Unicode in name",
                            );
                        }
                    }
                } else {
                    let mut do_validate = false;
                    if let Some(filename) = e.path().to_str() {
                        if let Some(ext) = e.path().extension().and_then(OsStr::to_str) {
                            if ["der", "crt", "cer"].contains(&ext) {
                                do_validate = true;
                            }
                        }

                        if do_validate {
                            stats.init_for_target(filename);
                            let stats_for_file = stats.get_mut(filename).unwrap();
                            if args.validate_all
                                || (stats_for_file.valid_paths_per_target == 0
                                    && !stats_for_file.target_is_revoked)
                            {
                                // validate when validating all or we don't have a definitive answer yet
                                validate_cert_file(
                                    pe,
                                    cps,
                                    filename,
                                    stats_for_file,
                                    args,
                                    fresh_uris,
                                    threshold,
                                );
                            }
                        } else {
                            pe.log_message(
                                &PeLogLevels::PeInfo,
                                format!("Skipping {}", filename).as_str(),
                            );
                        }
                    }
                }
            }
            _ => {
                pe.log_message(
                    &PeLogLevels::PeError,
                    format!("Failed to unwrap entry in {}", certs_folder).as_str(),
                );
            }
        }
    }
}

/// generate takes a Pittv3Args structure containing at least `cbor`, `ta-folder` and `ca-folder`
/// options the calls [`build-graph`], which may use the `download-folder`, `last-modified-map` and
/// `blocklist` options.
pub async fn generate(
    args: &Pittv3Args,
    cps: &CertificationPathSettings<'_>,
    pe: &PkiEnvironment<'_>,
) {
    let start = Instant::now();

    if args.cbor.is_none() || args.ta_folder.is_none() || args.ca_folder.is_none() {
        println!("ERROR: The cbor, ta-folder and ca-folder options are required when generate is specified");
        return;
    }

    let graph = build_graph(pe, cps, args).await;
    if let Ok(graph) = graph {
        fs::write(args.cbor.as_ref().unwrap(), graph.as_slice())
            .expect("Unable to write generated CBOR file");
    }
    println!("Generation took {:?}", Instant::now() - start);
}

/// `cleanup_certs` attempts to remove files that cannot be used from the indicated `certs_folder`
/// subject to the `report_only` parameter.
///
/// Where `report_only` is true, files are not cleaned up but are simply logged. Where `report_only`
/// is false, files are cleaned up, which means deleted if `error_folder` is absent or moved if present.
///
/// Files are elected for cleanup for the following reasons:
/// - File cannot be parsed as a certificate
/// - Certificate is not valid at indicated time `t`
/// - Certificate is not a CA certificate
/// - Certificate is self-signed
pub fn cleanup_certs(
    pe: &PkiEnvironment,
    certs_folder: &str,
    error_folder: &str,
    report_only: bool,
    t: u64,
) {
    for entry in WalkDir::new(certs_folder) {
        match entry {
            Ok(e) => {
                if e.file_type().is_dir() {
                    if e.path().to_str().unwrap() != certs_folder {
                        let s = e.path().to_str();
                        if let Some(s) = s {
                            println!("Recursing {}", e.path().display());
                            pe.log_message(
                                &PeLogLevels::PeInfo,
                                format!("Recursing {}", e.path().display()).as_str(),
                            );
                            cleanup_certs(pe, s, error_folder, report_only, t);
                        }
                    }
                } else {
                    let filename = e.path().to_str().unwrap();
                    if let Some(ext) = e.path().extension().and_then(OsStr::to_str) {
                        if !["der", "crt", "cer"].contains(&ext) {
                            // non-certificate extension
                            continue;
                        }
                    } else {
                        // no extension
                        continue;
                    }

                    let target = if let Ok(t) = get_file_as_byte_vec(e.path()) {
                        t
                    } else {
                        vec![]
                    };
                    if target.is_empty() {
                        pe.log_message(
                            &PeLogLevels::PeError,
                            format!("Failed to read target file at {}", filename).as_str(),
                        );
                        continue;
                    }

                    let mut delete_file = false;
                    let target_cert = parse_cert(target.as_slice(), filename);
                    match target_cert {
                        Some(tc) => {
                            if t > 0 {
                                let r =
                                    valid_at_time(pe, &tc.decoded_cert.tbs_certificate, t, true);
                                if let Err(_e) = r {
                                    delete_file = true;
                                    pe.log_message(
                                        &PeLogLevels::PeError,
                                        format!(
                                            "Not valid at indicated time of interest ({}): {}",
                                            t, filename
                                        )
                                        .as_str(),
                                    );
                                }
                            }

                            if is_self_signed(pe, &tc) {
                                delete_file = true;
                                pe.log_message(
                                    &PeLogLevels::PeError,
                                    format!("Self-signed: {}", filename).as_str(),
                                );
                            }

                            let bc = tc.get_extension(&PKIX_CE_BASIC_CONSTRAINTS);
                            if let Ok(Some(PDVExtension::BasicConstraints(bc))) = bc {
                                if !bc.ca {
                                    delete_file = true;
                                    pe.log_message(
                                        &PeLogLevels::PeError,
                                        format!("Not a CA per basicConstraints: {}", filename)
                                            .as_str(),
                                    );
                                }
                            } else {
                                delete_file = true;
                                pe.log_message(
                                    &PeLogLevels::PeError,
                                    format!("Missing basicConstraints: {}", filename).as_str(),
                                );
                            }
                        }
                        None => {
                            //parse_cert writes out a log messaage
                            delete_file = true;
                        }
                    }

                    if !report_only && delete_file {
                        if error_folder.is_empty() {
                            //delete file
                            let r = fs::remove_file(e.path());
                            if let Err(e) = r {
                                println!("Failed to delete {} with {:?}", filename, e);
                                pe.log_message(
                                    &PeLogLevels::PeError,
                                    format!("Failed to delete {} with {:?}", filename, e).as_str(),
                                );
                            }
                        } else {
                            let new_path = Path::new(error_folder);

                            let new_filename = new_path.join(e.path().file_name().unwrap());

                            // move file
                            let r = fs::rename(filename, new_filename);
                            if let Err(e) = r {
                                println!("Failed to delete {} with {:?}", filename, e);
                                pe.log_message(
                                    &PeLogLevels::PeError,
                                    format!("Failed to delete {} with {:?}", filename, e).as_str(),
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to unwrap entry: {}", e);
            }
        } // end match entry {
    } // end for entry in WalkDir::new(certs_folder)
}

/// `cleanup_tas` attempts to remove files that cannot be used from the indicated `tas_folder`
/// subject to the `report_only` parameter.
///
/// Where `report_only` is true, files are not cleaned up but are simply logged. Where `report_only`
/// is false, files are cleaned up, which means deleted if `error_folder` is absent or moved if present.
///
/// Files are elected for cleanup for the following reasons:
/// - File cannot be parsed as a trust anchor
/// - Trust anchor is not valid at indicated time `t`
pub fn cleanup_tas(
    pe: &PkiEnvironment,
    tas_folder: &str,
    error_folder: &str,
    report_only: bool,
    t: u64,
) {
    for entry in WalkDir::new(tas_folder) {
        match entry {
            Ok(e) => {
                if e.file_type().is_dir() {
                    if e.path().to_str().unwrap() != tas_folder {
                        let s = e.path().to_str();
                        if let Some(s) = s {
                            println!("Recursing {}", e.path().display());
                            pe.log_message(
                                &PeLogLevels::PeInfo,
                                format!("Recursing {}", e.path().display()).as_str(),
                            );
                            cleanup_tas(pe, s, error_folder, report_only, t);
                        }
                    }
                } else {
                    //TODO add support for 5914
                    let filename = e.path().to_str().unwrap();
                    if let Some(ext) = e.path().extension().and_then(OsStr::to_str) {
                        if !["der", "crt", "cer"].contains(&ext) {
                            // non-certificate extension
                            continue;
                        }
                    } else {
                        // no extension
                        continue;
                    }

                    let target = if let Ok(t) = get_file_as_byte_vec(e.path()) {
                        t
                    } else {
                        vec![]
                    };
                    if target.is_empty() {
                        pe.log_message(
                            &PeLogLevels::PeError,
                            format!("Failed to read target file at {}", filename).as_str(),
                        );
                        continue;
                    }

                    let mut delete_file = false;
                    let target_cert = parse_cert(target.as_slice(), filename);
                    match target_cert {
                        Some(tc) => {
                            if t > 0 {
                                let r =
                                    valid_at_time(pe, &tc.decoded_cert.tbs_certificate, t, true);
                                if let Err(_e) = r {
                                    delete_file = true;
                                    pe.log_message(
                                        &PeLogLevels::PeError,
                                        format!(
                                            "Not valid at indicated time of interest ({}): {}",
                                            t, filename
                                        )
                                        .as_str(),
                                    );
                                }
                            }
                        }
                        None => {
                            //parse_cert writes out a log messaage
                            delete_file = true;
                        }
                    }

                    if !report_only && delete_file {
                        if error_folder.is_empty() {
                            //delete file
                            let r = fs::remove_file(e.path());
                            if let Err(e) = r {
                                println!("Failed to delete {} with {:?}", filename, e);
                                pe.log_message(
                                    &PeLogLevels::PeError,
                                    format!("Failed to delete {} with {:?}", filename, e).as_str(),
                                );
                            }
                        } else {
                            let new_path = Path::new(error_folder);

                            let new_filename = new_path.join(e.path().file_name().unwrap());

                            // move file
                            let r = fs::rename(filename, new_filename);
                            if let Err(e) = r {
                                println!("Failed to delete {} with {:?}", filename, e);
                                pe.log_message(
                                    &PeLogLevels::PeError,
                                    format!("Failed to delete {} with {:?}", filename, e).as_str(),
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to unwrap entry: {}", e);
            }
        } // end match entry {
    } // end for entry in WalkDir::new(certs_folder)
}

/// `cleanup` implements the `cleanup` option using [`cleanup_certs`] for support.
pub fn cleanup(pe: &PkiEnvironment<'_>, args: &Pittv3Args) {
    let ca_folder = if let Some(ca_folder) = &args.ca_folder {
        ca_folder
    } else {
        println!("The ca-folder option must be specified when using the cleaup option");
        return;
    };

    let error_folder = if let Some(error_folder) = &args.error_folder {
        error_folder
    } else {
        ""
    };
    cleanup_certs(
        pe,
        ca_folder,
        error_folder,
        args.report_only,
        args.time_of_interest,
    );
}

/// `ta_cleanup` implements the `ta-cleanup` option using [`cleanup_tas`] for support.
pub fn ta_cleanup(pe: &PkiEnvironment<'_>, args: &Pittv3Args) {
    let ta_folder = if let Some(ta_folder) = &args.ta_folder {
        ta_folder
    } else {
        println!("The ta-folder option must be specified when using the ta-cleaup option");
        return;
    };

    let error_folder = if let Some(error_folder) = &args.error_folder {
        error_folder
    } else {
        ""
    };
    cleanup_tas(
        pe,
        ta_folder,
        error_folder,
        args.report_only,
        args.time_of_interest,
    );
}

use certval::{Error, Result};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
extern crate alloc;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref G_CRLS_FOLDER: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_2048/crls/"
        )
    };
    pub static ref G_CERTS_FOLDER: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_2048/certs/"
        )
    };
    pub static ref G_CERTS_FOLDER_4096: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_4096/certs/"
        )
    };
    pub static ref G_CRLS_FOLDER_4096: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_4096/crls/"
        )
    };
    pub static ref G_CERTS_FOLDER_P256: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_p256/certs/"
        )
    };
    pub static ref G_CRLS_FOLDER_P256: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_p256/crls/"
        )
    };
    pub static ref G_CERTS_FOLDER_P384: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_p384/certs/"
        )
    };
    pub static ref G_CRLS_FOLDER_P384: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_p384/crls/"
        )
    };
    pub static ref G_TA5914_2048_FOLDER: String = {
        format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/PKITS_data_2048/5914_tas/"
        )
    };
}

pub fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    if let Ok(mut f) = File::open(filename) {
        if let Ok(metadata) = std::fs::metadata(filename) {
            let mut buffer = vec![0; metadata.len() as usize];
            if let Ok(()) = f.read_exact(&mut buffer) {
                return Ok(buffer);
            }
        }
    }
    Err(Error::Unrecognized)
}

pub fn get_pkits_crl_bytes(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CRLS_FOLDER.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}

pub fn get_pkits_crl_ca_bytes(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}{}", G_CRLS_FOLDER.as_str(), fname, "CACRL.crl");
    let p = Path::new(f.as_str());
    if p.exists() {
        return get_file_as_byte_vec(Path::new(&p));
    } else {
        let f = format!("{}{}{}", G_CRLS_FOLDER.as_str(), fname, "CRL.crl");
        let p = Path::new(f.as_str());
        return get_file_as_byte_vec(Path::new(&p));
    }
}

pub fn get_pkits_cert_bytes(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes(fname: &str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER.as_str(), fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER.as_str(), fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_cert_bytes_p256(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER_P256.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes_p256(fname: &str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER_P256.as_str(), fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER_P256.as_str(), fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}

// pub fn get_pkits_cert_bytes_p384(fname: &str) -> Result<Vec<u8>> {
//     let f = format!("{}{}", G_CERTS_FOLDER_P384.as_str(), fname);
//     get_file_as_byte_vec(Path::new(&f))
// }
// pub fn get_pkits_ca_cert_bytes_p384(fname: &str) -> Result<Vec<u8>> {
//     let mut f = format!("{}{}{}", G_CERTS_FOLDER_P384.as_str(), fname, "CACert.crt");
//     if !Path::new(f.as_str()).exists() {
//         f = format!("{}{}{}", G_CERTS_FOLDER_P384.as_str(), fname, "Cert.crt");
//     }
//     get_file_as_byte_vec(Path::new(&f))
// }
// pub fn get_pkits_cert_bytes_4096(fname: &str) -> Result<Vec<u8>> {
//     let f = format!("{}{}", G_CERTS_FOLDER_4096.as_str(), fname);
//     get_file_as_byte_vec(Path::new(&f))
// }
// pub fn get_pkits_ca_cert_bytes_4096(fname: &str) -> Result<Vec<u8>> {
//     let mut f = format!("{}{}{}", G_CERTS_FOLDER_4096.as_str(), fname, "CACert.crt");
//     if !Path::new(f.as_str()).exists() {
//         f = format!("{}{}{}", G_CERTS_FOLDER_4096.as_str(), fname, "Cert.crt");
//     }
//     get_file_as_byte_vec(Path::new(&f))
// }
pub fn get_pkits_ta5914_2048_bytes(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_TA5914_2048_FOLDER.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}

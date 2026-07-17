use certval::{Error, Result};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
extern crate alloc;

pub static G_CRLS_FOLDER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/examples/PKITS_data_2048/crls/"
);
pub static G_CERTS_FOLDER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/examples/PKITS_data_2048/certs/"
);
// pub static G_CERTS_FOLDER_4096: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/tests/examples/PKITS_data_4096/certs/"
// );
// pub static G_CRLS_FOLDER_4096: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/tests/examples/PKITS_data_4096/crls/"
// );
pub static G_CERTS_FOLDER_P256: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/examples/PKITS_data_p256/certs/"
);
// pub static G_CRLS_FOLDER_P256: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/tests/examples/PKITS_data_p256/crls/"
// );
// pub static G_CERTS_FOLDER_P384: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/tests/examples/PKITS_data_p384/certs/"
// );
// pub static G_CRLS_FOLDER_P384: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/tests/examples/PKITS_data_p384/crls/"
// );
pub static G_TA5914_2048_FOLDER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/examples/PKITS_data_2048/5914_tas/"
);

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
    let f = format!("{}{}", G_CRLS_FOLDER, fname);
    get_file_as_byte_vec(Path::new(&f))
}

pub fn get_pkits_crl_ca_bytes(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}{}", G_CRLS_FOLDER, fname, "CACRL.crl");
    let p = Path::new(f.as_str());
    if p.exists() {
        get_file_as_byte_vec(Path::new(&p))
    } else {
        let f = format!("{}{}{}", G_CRLS_FOLDER, fname, "CRL.crl");
        let p = Path::new(f.as_str());
        get_file_as_byte_vec(Path::new(&p))
    }
}

pub fn get_pkits_cert_bytes(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER, fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes(fname: &str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER, fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER, fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_cert_bytes_p256(fname: &str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER_P256, fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes_p256(fname: &str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER_P256, fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER_P256, fname, "Cert.crt");
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
    let f = format!("{}{}", G_TA5914_2048_FOLDER, fname);
    get_file_as_byte_vec(Path::new(&f))
}

// PQC PKITS artifacts use .der for certs and a different CRL naming convention
#[cfg(feature = "pqc")]
pub fn get_pkits_cert_bytes_pqc(folder: &str, fname: &str) -> Result<Vec<u8>> {
    let base = fname.strip_suffix(".crt").unwrap_or(fname);
    let f = format!(
        "{}/tests/examples/{}/certs/{}.der",
        env!("CARGO_MANIFEST_DIR"),
        folder,
        base
    );
    get_file_as_byte_vec(Path::new(&f))
}

#[cfg(feature = "pqc")]
pub fn get_pkits_ca_cert_bytes_pqc(folder: &str, fname: &str) -> Result<Vec<u8>> {
    let f = format!(
        "{}/tests/examples/{}/certs/{}CACert.der",
        env!("CARGO_MANIFEST_DIR"),
        folder,
        fname
    );
    if Path::new(f.as_str()).exists() {
        get_file_as_byte_vec(Path::new(&f))
    } else {
        let f = format!(
            "{}/tests/examples/{}/certs/{}Cert.der",
            env!("CARGO_MANIFEST_DIR"),
            folder,
            fname
        );
        get_file_as_byte_vec(Path::new(&f))
    }
}

#[cfg(feature = "pqc")]
pub fn get_pkits_crl_bytes_pqc(folder: &str, fname: &str) -> Result<Vec<u8>> {
    let f = format!(
        "{}/tests/examples/{}/crls/{}",
        env!("CARGO_MANIFEST_DIR"),
        folder,
        fname
    );
    get_file_as_byte_vec(Path::new(&f))
}

#[cfg(feature = "pqc")]
pub fn get_pkits_crl_ca_bytes_pqc(folder: &str, fname: &str) -> Result<Vec<u8>> {
    let f = format!(
        "{}/tests/examples/{}/crls/{}CACert.crl",
        env!("CARGO_MANIFEST_DIR"),
        folder,
        fname
    );
    let p = Path::new(f.as_str());
    if p.exists() {
        get_file_as_byte_vec(p)
    } else {
        let f = format!(
            "{}/tests/examples/{}/crls/{}Cert.crl",
            env!("CARGO_MANIFEST_DIR"),
            folder,
            fname
        );
        get_file_as_byte_vec(Path::new(f.as_str()))
    }
}

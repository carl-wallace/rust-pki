//! Whether a certificate is self-signed, worded the same way by every frontend.

use alloc::format;
use alloc::string::{String, ToString};

use certval::{is_self_signed, Error, PDVCertificate, PkiEnvironment};
use const_oid::db::DB;

/// `Ok` with whether `cert` is self-signed, or why that could not be evaluated.
pub fn evaluate(pe: &PkiEnvironment, cert: &PDVCertificate) -> Result<bool, String> {
    match is_self_signed(pe, cert) {
        Ok(self_signed) => Ok(self_signed),
        Err(Error::Unrecognized) => {
            let oid = cert.decoded().signature_algorithm().oid;
            let alg = DB
                .by_oid(&oid)
                .map_or_else(|| oid.to_string(), ToString::to_string);
            Err(format!("unsupported signature algorithm {alg}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The sentence reporting `outcome` for the certificate `name`.
pub fn describe(name: &str, outcome: &Result<bool, String>) -> String {
    match outcome {
        Ok(true) => format!("{name} is self-signed"),
        Ok(false) => format!("{name} is not self-signed"),
        Err(e) => format!("{name} failed to evaluate with {e}"),
    }
}

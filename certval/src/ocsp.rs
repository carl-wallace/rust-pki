//! OCSP formats as described in [RFC 6960]
//!
//! A copy of the RustCrypto [x509-ocsp] crate, taken from RustCrypto/formats at commit `4c5fadb1`
//! (version 0.3.0-pre). Copyright (c) 2021-2025 The RustCrypto Project Developers, licensed
//! Apache-2.0 OR MIT.
//!
//! It was copied here because certval cannot publish while it depends on an x509-ocsp that has no
//! crates.io release. The latest published version is 0.2.1, which predates x509-cert 0.3. When
//! x509-ocsp 0.3 is published, this module will be replaced by `pub use x509_ocsp as ocsp`, so code
//! that uses these types through `certval::ocsp` need not change.
//!
//! Changes from upstream: the `builder` module and the builder impls inside the other files are
//! left out, as is `Nonce::generate`, which needed the `rand` feature. certval builds its requests
//! itself and generates its own nonces. The items are not re-exported at the crate root, where
//! names such as `Request`, `Signature` and `Version` would collide.
//!
//! [RFC 6960]: https://datatracker.ietf.org/doc/html/rfc6960
//! [x509-ocsp]: https://github.com/RustCrypto/formats/tree/master/x509-ocsp

mod basic;
mod cert_id;
mod cert_status;
mod request;
mod responder_id;
mod response;
mod time;

pub mod ext;

pub use basic::{BasicOcspResponse, ResponseData, SingleResponse};
pub use cert_id::CertId;
pub use cert_status::{CertStatus, RevokedInfo, UnknownInfo};
pub use request::{OcspRequest, Request, Signature, TbsRequest};
pub use responder_id::ResponderId;
pub use response::{AsResponseBytes, OcspNoCheck, OcspResponse, OcspResponseStatus, ResponseBytes};
pub use time::OcspGeneralizedTime;

use der::Enumerated;

/// OCSP `Version` as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    #[default]
    V1 = 0,
}

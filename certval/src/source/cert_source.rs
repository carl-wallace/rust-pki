//! The cert_source module provides implementation of a manually populated in-memory certificate
//! store with serialization and certification path building support.
//!
//! The following snip, similar to code in [`PITTv3`](../../pittv3/index.html), illustrates preparation
//! and use of a [`CertSource`] object.
//!
//! ```
//! use certval::PkiEnvironment;
//! use certval::CertSource;
//!
//! // the default PkiEnvironment uses `oid_lookup` to look up friendly names for OIDs
//! let mut pe = PkiEnvironment::default();
//!
//! let mut cert_source = CertSource::default();
//! // populate the cert_source.buffers_and_paths and cert_source.certs fields.
//! // See `populate_parsed_cert_vector` in `Pittv3` for file-system based sample. When initializing
//! // a set of partial paths, the cert_source.buffers_and_paths.partial_paths field can be empty,
//! // with population accurring via a call to find_all_partial_paths then index the certs,
//! // i.e., populate the name and spki maps. See `populate_parsed_cert_vector` usage in PITTv3 for
//! // a file system-based example.
//!
//! // add cert_source to provide access to intermediate CA certificates
//! pe.add_certificate_source(&cert_source);
//!
//! // add same object as a path builder to provide path building capabilities
//! pe.add_path_builder(&cert_source);
//! ```
//!
//! [`CertSource`] instances are used when preparing a serialized file containing intermediate CA
//! certificates and partial paths (see [`find_all_partial_paths`](../cert_source/struct.CertSource.html#method.find_all_partial_paths)).
//!

use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    string::{String, ToString},
};
use alloc::{format, vec, vec::Vec};
use core::cell::RefCell;

use ciborium::ser::into_writer;
use serde::{Deserialize, Serialize};

use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS,
    ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER,
};
use der::Decode;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::{
    compare_names,
    environment::pki_environment_traits::*,
    general_subtree_to_string, get_leaf_rdn, log_message,
    path_settings::get_time_of_interest,
    pdv_certificate::*,
    pdv_extension::*,
    pdv_trust_anchor::get_trust_anchor_name,
    source::ta_source::*,
    util::error::*,
    util::pdv_utilities::{
        collect_uris_from_aia_and_sia, is_self_issued, name_to_string, valid_at_time,
    },
    CertificateSource, CertificationPath, CertificationPathBuilder, CertificationPathSettings,
    ExtensionProcessing, NameConstraintsSet, PDVCertificate, PDVTrustAnchorChoice, PeLogLevels,
    PkiEnvironment, EXTS_OF_INTEREST, PS_MAX_PATH_LENGTH_CONSTRAINT,
};

#[cfg(feature = "std")]
use core::ops::Deref;

#[cfg(feature = "std")]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Mutex;

/// The CertFile struct associates a string, notionally containing a filename or URI, with a vector
/// of bytes. The vector of bytes is assumed to contain a binary DER encoded certificate.
#[derive(Clone, Serialize, Deserialize)]
pub struct CertFile {
    /// The filename field enables association of a string value, possibly a filename or URI, with a binary certificate
    pub filename: String,

    /// The bytes field stores a binary DER encoded certificate
    pub bytes: Vec<u8>,
}

impl PartialEq for CertFile {
    /// Equality only checks that the `bytes` fields are equal, i.e., the `filename` fields are ignored
    /// (so as to not return mismatch for cert from file vs one from URI)
    fn eq(&self, other: &CertFile) -> bool {
        self.bytes == other.bytes
    }
}

/// BuffersAndPaths is the target of serialization and deserialization. It features a vector
/// of [`CertFile`] structures (which contain buffers containing binary DER-encoded certificates)
/// and a vector of maps that feature vectors of indices of items in the buffers vector. Each vector
/// of indices denotes a partial certification path (featuring intermediate CAs only).
///
/// The first index in a vector of indices corresponds to a certificate signed by a trust anchor that
/// was available when partial paths were discovered. The last index is a leaf CA and is what is
/// used when building certification paths. For example, the authority key identifier from a target
/// certificate is used to as a map key to find partial paths beginning from shortest to longest.
/// Partial paths are subject to some basic immutable validation checks (i.e., name chaining, name
/// constraints and signature verification) as well as a validity check relative to specified time
/// of interest, which is typically current time.
///
/// This structure is deserialized into a field of a CertSource instance the the certs buffer and
/// name_map and skid_map fields are populated. See [CertSource] for a deserialization example.
///
/// Below is the JSON representation of a sample CBOR file featuring two intermediate CA
/// certificates. When this is paired with a TA store containing two trust anchors (corresponding to
/// the issuers of each intermediate CA certificate), the resulting partial paths vector is as shown,
/// with two partial paths.
///
/// ```json
/// {"buffers": [
///   {"filename": "/Users/somebody/Desktop/Pittv3/pitt_certs_focused/76.der",
///    "bytes": [48, 130, 5, 70, 48, 130, 4, 46, 160, 3, 2, 1, 2, 2, 2, 8, 123, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 108, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 24, 48, 22, 6, 3, 85, 4, 10, 19, 15, 85, 46, 83, 46, 32, 71, 111, 118, 101, 114, 110, 109, 101, 110, 116, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 68, 111, 68, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 80, 75, 73, 49, 39, 48, 37, 6, 3, 85, 4, 3, 19, 30, 68, 111, 68, 32, 73, 110, 116, 101, 114, 111, 112, 101, 114, 97, 98, 105, 108, 105, 116, 121, 32, 82, 111, 111, 116, 32, 67, 65, 32, 50, 48, 30, 23, 13, 50, 49, 49, 49, 49, 54, 49, 52, 53, 55, 49, 54, 90, 23, 13, 50, 52, 49, 49, 49, 54, 49, 52, 53, 55, 49, 54, 90, 48, 91, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 24, 48, 22, 6, 3, 85, 4, 10, 19, 15, 85, 46, 83, 46, 32, 71, 111, 118, 101, 114, 110, 109, 101, 110, 116, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 68, 111, 68, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 80, 75, 73, 49, 22, 48, 20, 6, 3, 85, 4, 3, 19, 13, 68, 111, 68, 32, 82, 111, 111, 116, 32, 67, 65, 32, 51, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 169, 236, 20, 114, 138, 232, 75, 112, 163, 218, 16, 3, 132, 166, 251, 167, 54, 13, 42, 58, 82, 22, 191, 48, 21, 82, 134, 5, 71, 32, 207, 170, 166, 205, 117, 196, 100, 110, 239, 241, 96, 35, 203, 10, 102, 64, 174, 180, 200, 104, 42, 0, 81, 104, 73, 55, 233, 89, 50, 77, 149, 188, 67, 39, 233, 64, 141, 58, 16, 206, 20, 188, 67, 24, 161, 249, 222, 204, 231, 133, 118, 115, 94, 24, 26, 35, 91, 189, 63, 31, 242, 237, 141, 25, 204, 3, 209, 64, 164, 143, 167, 32, 2, 76, 39, 90, 121, 54, 246, 163, 55, 33, 142, 0, 90, 6, 22, 202, 211, 85, 150, 111, 49, 41, 187, 114, 14, 203, 226, 72, 81, 242, 212, 55, 164, 53, 214, 111, 238, 23, 179, 177, 6, 171, 11, 25, 134, 232, 35, 109, 49, 27, 40, 120, 101, 197, 222, 98, 82, 188, 193, 125, 235, 238, 160, 93, 84, 4, 251, 178, 203, 43, 178, 35, 84, 145, 130, 76, 240, 191, 186, 116, 64, 59, 12, 4, 69, 128, 103, 92, 197, 235, 162, 87, 195, 26, 127, 10, 45, 189, 127, 185, 220, 193, 153, 176, 200, 7, 228, 12, 134, 54, 148, 58, 37, 47, 242, 125, 230, 151, 60, 27, 148, 180, 151, 89, 6, 201, 58, 228, 11, 217, 234, 233, 252, 59, 115, 52, 111, 253, 231, 152, 228, 243, 161, 194, 144, 95, 28, 245, 63, 46, 215, 25, 211, 127, 2, 3, 1, 0, 1, 163, 130, 2, 1, 48, 130, 1, 253, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 255, 248, 174, 19, 139, 146, 43, 121, 146, 65, 163, 118, 92, 44, 129, 158, 154, 197, 156, 120, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48, 71, 6, 3, 85, 29, 31, 4, 64, 48, 62, 48, 60, 160, 58, 160, 56, 134, 54, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 100, 105, 115, 97, 46, 109, 105, 108, 47, 99, 114, 108, 47, 68, 79, 68, 73, 78, 84, 69, 82, 79, 80, 69, 82, 65, 66, 73, 76, 73, 84, 89, 82, 79, 79, 84, 67, 65, 50, 46, 99, 114, 108, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 108, 138, 148, 162, 119, 177, 128, 114, 29, 129, 122, 22, 170, 242, 220, 206, 102, 238, 69, 192, 48, 124, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 112, 48, 110, 48, 74, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 62, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 100, 105, 115, 97, 46, 109, 105, 108, 47, 105, 115, 115, 117, 101, 100, 116, 111, 47, 68, 79, 68, 73, 78, 84, 69, 82, 79, 80, 69, 82, 65, 66, 73, 76, 73, 84, 89, 82, 79, 79, 84, 67, 65, 50, 95, 73, 84, 46, 112, 55, 99, 48, 32, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 20, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 100, 105, 115, 97, 46, 109, 105, 108, 48, 118, 6, 3, 85, 29, 32, 4, 111, 48, 109, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 36, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 39, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 42, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 13, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 17, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 39, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 40, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 41, 48, 15, 6, 3, 85, 29, 36, 1, 1, 255, 4, 5, 48, 3, 128, 1, 0, 48, 74, 6, 8, 43, 6, 1, 5, 5, 7, 1, 11, 4, 62, 48, 60, 48, 58, 6, 8, 43, 6, 1, 5, 5, 7, 48, 5, 134, 46, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 100, 105, 115, 97, 46, 109, 105, 108, 47, 105, 115, 115, 117, 101, 100, 98, 121, 47, 68, 79, 68, 82, 79, 79, 84, 67, 65, 51, 95, 73, 66, 46, 112, 55, 99, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 220, 151, 25, 58, 239, 169, 147, 36, 8, 107, 67, 226, 161, 188, 172, 8, 103, 168, 125, 124, 149, 86, 46, 253, 184, 144, 99, 66, 80, 93, 145, 42, 255, 179, 119, 84, 80, 102, 177, 13, 37, 98, 219, 204, 5, 181, 245, 112, 213, 153, 160, 199, 169, 231, 195, 62, 115, 28, 93, 155, 122, 192, 85, 139, 130, 253, 83, 83, 31, 123, 50, 184, 250, 12, 231, 3, 91, 60, 208, 247, 207, 80, 21, 12, 87, 106, 10, 32, 104, 251, 159, 225, 116, 156, 128, 116, 206, 78, 80, 236, 117, 185, 113, 85, 133, 41, 121, 27, 157, 248, 147, 248, 229, 0, 81, 245, 214, 44, 27, 132, 240, 166, 238, 46, 238, 71, 137, 111, 255, 169, 162, 45, 11, 153, 211, 165, 248, 28, 219, 4, 104, 235, 242, 222, 128, 134, 8, 108, 15, 106, 165, 245, 238, 2, 27, 244, 211, 233, 153, 99, 198, 127, 248, 247, 143, 110, 3, 74, 178, 16, 2, 235, 142, 187, 75, 39, 9, 207, 159, 198, 1, 194, 30, 15, 172, 37, 170, 160, 18, 234, 0, 185, 158, 188, 175, 76, 212, 243, 0, 98, 183, 196, 97, 157, 2, 239, 239, 197, 186, 183, 162, 236, 142, 115, 7, 252, 178, 82, 84, 22, 93, 190, 30, 102, 177, 158, 179, 85, 179, 89, 126, 183, 13, 23, 140, 41, 79, 12, 57, 24, 205, 76, 13, 213, 0, 142, 88, 175, 184, 69, 84, 32, 210, 4, 160, 3]},
///   {"filename": "/Users/somebody/Desktop/Pittv3/pitt_certs_focused/30.der",
///    "bytes": [48, 130, 4, 188, 48, 130, 3, 164, 160, 3, 2, 1, 2, 2, 2, 3, 4, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 91, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 24, 48, 22, 6, 3, 85, 4, 10, 19, 15, 85, 46, 83, 46, 32, 71, 111, 118, 101, 114, 110, 109, 101, 110, 116, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 68, 111, 68, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 80, 75, 73, 49, 22, 48, 20, 6, 3, 85, 4, 3, 19, 13, 68, 111, 68, 32, 82, 111, 111, 116, 32, 67, 65, 32, 51, 48, 30, 23, 13, 49, 57, 48, 52, 48, 50, 49, 51, 51, 55, 50, 53, 90, 23, 13, 50, 53, 48, 52, 48, 50, 49, 51, 51, 55, 50, 53, 90, 48, 93, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 24, 48, 22, 6, 3, 85, 4, 10, 19, 15, 85, 46, 83, 46, 32, 71, 111, 118, 101, 114, 110, 109, 101, 110, 116, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 68, 111, 68, 49, 12, 48, 10, 6, 3, 85, 4, 11, 19, 3, 80, 75, 73, 49, 24, 48, 22, 6, 3, 85, 4, 3, 19, 15, 68, 79, 68, 32, 69, 77, 65, 73, 76, 32, 67, 65, 45, 53, 57, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 192, 141, 136, 255, 19, 236, 62, 67, 222, 43, 175, 213, 114, 208, 4, 179, 207, 105, 203, 120, 160, 48, 43, 141, 9, 71, 101, 112, 227, 255, 46, 139, 179, 15, 135, 216, 112, 217, 8, 50, 28, 108, 244, 17, 202, 29, 78, 147, 229, 4, 77, 187, 208, 68, 206, 248, 58, 89, 4, 58, 224, 24, 144, 159, 233, 58, 67, 159, 22, 18, 91, 229, 208, 234, 213, 31, 154, 33, 215, 121, 174, 118, 53, 223, 234, 3, 66, 32, 200, 3, 45, 105, 171, 93, 177, 185, 78, 44, 6, 135, 23, 87, 64, 164, 193, 52, 170, 218, 203, 28, 164, 204, 158, 8, 210, 124, 227, 174, 61, 173, 127, 88, 216, 210, 230, 166, 77, 96, 143, 91, 49, 156, 120, 123, 237, 165, 201, 42, 39, 196, 220, 169, 148, 247, 234, 214, 123, 5, 131, 131, 254, 74, 129, 168, 169, 11, 47, 18, 245, 100, 149, 69, 8, 175, 78, 100, 96, 2, 178, 106, 129, 200, 167, 15, 136, 137, 247, 113, 58, 38, 209, 203, 131, 195, 3, 49, 50, 168, 206, 177, 37, 174, 244, 104, 208, 68, 170, 152, 50, 138, 196, 148, 108, 20, 44, 136, 129, 114, 13, 254, 125, 189, 232, 6, 53, 124, 139, 36, 118, 9, 99, 97, 8, 51, 4, 89, 87, 195, 215, 46, 103, 119, 210, 233, 58, 200, 62, 33, 71, 89, 123, 102, 56, 91, 172, 104, 191, 122, 11, 135, 240, 67, 55, 169, 143, 47, 2, 3, 1, 0, 1, 163, 130, 1, 134, 48, 130, 1, 130, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 108, 138, 148, 162, 119, 177, 128, 114, 29, 129, 122, 22, 170, 242, 220, 206, 102, 238, 69, 192, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 119, 20, 65, 166, 93, 149, 38, 208, 29, 255, 149, 59, 98, 140, 234, 183, 181, 93, 59, 146, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 103, 6, 3, 85, 29, 32, 4, 96, 48, 94, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 36, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 39, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 42, 48, 11, 6, 9, 96, 134, 72, 1, 101, 2, 1, 11, 59, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 13, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 17, 48, 12, 6, 10, 96, 134, 72, 1, 101, 3, 2, 1, 3, 39, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 12, 6, 3, 85, 29, 36, 4, 5, 48, 3, 128, 1, 0, 48, 55, 6, 3, 85, 29, 31, 4, 48, 48, 46, 48, 44, 160, 42, 160, 40, 134, 38, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 100, 105, 115, 97, 46, 109, 105, 108, 47, 99, 114, 108, 47, 68, 79, 68, 82, 79, 79, 84, 67, 65, 51, 46, 99, 114, 108, 48, 108, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 96, 48, 94, 48, 58, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 46, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 100, 105, 115, 97, 46, 109, 105, 108, 47, 105, 115, 115, 117, 101, 100, 116, 111, 47, 68, 79, 68, 82, 79, 79, 84, 67, 65, 51, 95, 73, 84, 46, 112, 55, 99, 48, 32, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 20, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 100, 105, 115, 97, 46, 109, 105, 108, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 77, 203, 205, 215, 101, 60, 152, 187, 134, 1, 209, 205, 201, 72, 211, 128, 92, 230, 37, 99, 39, 51, 197, 10, 94, 187, 205, 50, 88, 86, 50, 254, 72, 35, 62, 1, 36, 73, 191, 7, 218, 215, 143, 110, 69, 74, 221, 99, 128, 217, 75, 132, 125, 17, 93, 149, 89, 122, 29, 148, 81, 103, 6, 122, 88, 13, 14, 225, 180, 97, 132, 164, 24, 144, 128, 169, 195, 163, 74, 72, 18, 187, 172, 61, 190, 56, 13, 231, 70, 42, 148, 58, 125, 243, 139, 165, 106, 231, 250, 100, 219, 66, 165, 232, 165, 172, 55, 121, 41, 2, 173, 57, 114, 167, 39, 136, 7, 133, 12, 203, 216, 206, 230, 14, 137, 199, 95, 249, 252, 113, 130, 164, 155, 118, 198, 116, 152, 24, 151, 39, 238, 144, 100, 34, 158, 123, 6, 236, 174, 217, 248, 92, 183, 84, 28, 59, 27, 55, 242, 157, 227, 14, 205, 130, 247, 113, 202, 139, 151, 39, 45, 135, 7, 81, 150, 224, 130, 215, 28, 0, 98, 165, 73, 251, 91, 181, 57, 189, 117, 225, 246, 44, 188, 222, 45, 208, 129, 77, 55, 144, 124, 37, 46, 217, 132, 87, 151, 194, 179, 213, 68, 241, 129, 182, 220, 104, 77, 158, 38, 226, 175, 205, 193, 162, 101, 202, 242, 35, 133, 62, 224, 105, 91, 182, 232, 202, 208, 55, 219, 118, 189, 141, 181, 19, 169, 11, 148, 17, 63, 113, 55, 230, 46, 30, 158, 244]}],
/// "partial_paths": [
///  {"6C8A94A277B180721D817A16AAF2DCCE66EE45C0": [[0]],
///   "771441A65D9526D01DFF953B628CEAB7B55D3B92": [[1]]},
///  {"771441A65D9526D01DFF953B628CEAB7B55D3B92": [[0, 1]]}
///  ]}
/// ```
/// An ASCII hex representation of the CBOR that resulted in the above JSON presentation is below.
///
/// ```text
/// A2676275666665727382A26866696C656E616D6578382F55736572732F6377616C6C6163652F4465736B746F70
/// 2F5069747476332F706974745F63657274735F666F63757365642F37362E64657265627974657399054A183018
/// 820518461830188204182E18A003020102020208187B18300D0609182A18861848188618F70D01010B05001830
/// 186C18310B1830090603185504061302185518531831181818301606031855040A130F1855182E1853182E1820
/// 1847186F187618651872186E186D1865186E187418310C18300A06031855040B13031844186F184418310C1830
/// 0A06031855040B13031850184B1849183118271830182506031855040313181E1844186F184418201849186E18
/// 7418651872186F187018651872186118621869186C18691874187918201852186F186F18741820184318411820
/// 18321830181E170D183218311831183118311836183118341835183718311836185A170D183218341831183118
/// 311836183118341835183718311836185A1830185B18310B183009060318550406130218551853183118181830
/// 1606031855040A130F1855182E1853182E18201847186F187618651872186E186D1865186E187418310C18300A
/// 06031855040B13031844186F184418310C18300A06031855040B13031850184B18491831161830140603185504
/// 03130D1844186F184418201852186F186F1874182018431841182018331830188201182218300D0609182A1886
/// 1848188618F70D0101010500031882010F0018301882010A02188201010018A918EC141872188A18E8184B1870
/// 18A318DA1003188418A618FB18A718360D182A183A18521618BF18301518521886051847182018CF18AA18A618
/// CD187518C41864186E18EF18F11860182318CB0A1866184018AE18B418C81868182A00185118681849183718E9
/// 18591832184D189518BC1843182718E91840188D183A1018CE1418BC1843181818A118F918DE18CC18E7188518
/// 761873185E1818181A1823185B18BD183F181F18F218ED188D181918CC0318D1184018A4188F18A7182002184C
/// 1827185A1879183618F618A318371821188E00185A061618CA18D318551896186F1831182918BB18720E18CB18
/// E21848185118F218D4183718A4183518D6186F18EE1718B318B10618AB0B1819188618E81823186D1831181B18
/// 281878186518C518DE1862185218BC18C1187D18EB18EE18A0185D18540418FB18B218CB182B18B21823185418
/// 911882184C18F018BF18BA18741840183B0C04184518801867185C18C518EB18A2185718C3181A187F0A182D18
/// BD187F18B918DC18C1189918B018C80718E40C188618361894183A1825182F18F2187D18E61897183C181B1894
/// 18B4189718590618C9183A18E40B18D918EA18E918FC183B18731834186F18FD18E7189818E418F318A118C218
/// 90185F181C18F5183F182E18D7181918D3187F020301000118A318820201183018820118FD1830181F06031855
/// 181D182304181818301618801418FF18F818AE13188B1892182B18791892184118A31876185C182C1881189E18
/// 9A18C5189C187818300F06031855181D13010118FF0405183003010118FF18300E06031855181D0F010118FF04
/// 04030201061830184706031855181D181F0418401830183E1830183C18A0183A18A01838188618361868187418
/// 741870183A182F182F18631872186C182E1864186918731861182E186D1869186C182F18631872186C182F1844
/// 184F18441849184E185418451852184F185018451852184118421849184C1849185418591852184F184F185418
/// 4318411832182E18631872186C1830181D06031855181D0E04160414186C188A189418A2187718B11880187218
/// 1D1881187A1618AA18F218DC18CE186618EE184518C01830187C0608182B060105050701010418701830186E18
/// 30184A0608182B06010505071830021886183E1868187418741870183A182F182F18631872186C182E18641869
/// 18731861182E186D1869186C182F1869187318731875186518641874186F182F1844184F18441849184E185418
/// 451852184F185018451852184118421849184C1849185418591852184F184F1854184318411832185F18491854
/// 182E187018371863183018200608182B06010505071830011886141868187418741870183A182F182F186F1863
/// 18731870182E1864186918731861182E186D1869186C1830187606031855181D182004186F1830186D18300B06
/// 0918601886184801186502010B182418300B060918601886184801186502010B182718300B0609186018861848
/// 01186502010B182A18300C060A186018861848011865030201030D18300C060A18601886184801186503020103
/// 1118300C060A18601886184801186503020103182718300C060A18601886184801186503020103182818300C06
/// 0A18601886184801186503020103182918300F06031855181D1824010118FF0405183003188001001830184A06
/// 08182B0601050507010B04183E1830183C1830183A0608182B06010505071830051886182E1868187418741870
/// 183A182F182F18631872186C182E1864186918731861182E186D1869186C182F18691873187318751865186418
/// 621879182F1844184F18441852184F184F1854184318411833185F18491842182E18701837186318300D060918
/// 2A18861848188618F70D01010B050003188201010018DC18971819183A18EF18A91893182408186B184318E218
/// A118BC18AC08186718A8187D187C18951856182E18FD18B81890186318421850185D1891182A18FF18B3187718
/// 541850186618B10D1825186218DB18CC0518B518F5187018D5189918A018C718A918E718C3183E1873181C185D
/// 189B187A18C01855188B188218FD18531853181F187B183218B818FA0C18E703185B183C18D018F718CF185015
/// 0C1857186A0A1820186818FB189F18E11874189C1880187418CE184E185018EC187518B9187118551885182918
/// 79181B189D18F8189318F818E500185118F518D6182C181B188418F018A618EE182E18EE18471889186F18FF18
/// A918A2182D0B189918D318A518F8181C18DB04186818EB18F218DE1880188608186C0F186A18A518F518EE0218
/// 1B18F418D318E91899186318C6187F18F818F7188F186E03184A18B2100218EB188E18BB184B18270918CF189F
/// 18C60118C2181E0F18AC182518AA18A01218EA0018B9189E18BC18AF184C18D418F300186218B718C41861189D
/// 0218EF18EF18C518BA18B718A218EC188E18730718FC18B21852185416185D18BE181E186618B1189E18B31855
/// 18B31859187E18B70D17188C1829184F0C1839181818CD184C0D18D500188E185818AF18B818451854182018D2
/// 0418A003A26866696C656E616D6578382F55736572732F6377616C6C6163652F4465736B746F702F5069747476
/// 332F706974745F63657274735F666F63757365642F33302E6465726562797465739904C0183018820418BC1830
/// 18820318A418A0030201020202030418300D0609182A18861848188618F70D01010B05001830185B18310B1830
/// 090603185504061302185518531831181818301606031855040A130F1855182E1853182E18201847186F187618
/// 651872186E186D1865186E187418310C18300A06031855040B13031844186F184418310C18300A06031855040B
/// 13031850184B1849183116183014060318550403130D1844186F184418201852186F186F187418201843184118
/// 2018331830181E170D183118391830183418301832183118331833183718321835185A170D1832183518301834
/// 18301832183118331833183718321835185A1830185D18310B1830090603185504061302185518531831181818
/// 301606031855040A130F1855182E1853182E18201847186F187618651872186E186D1865186E187418310C1830
/// 0A06031855040B13031844186F184418310C18300A06031855040B13031850184B184918311818183016060318
/// 550403130F1844184F184418201845184D18411849184C182018431841182D183518391830188201182218300D
/// 0609182A18861848188618F70D0101010500031882010F0018301882010A02188201010018C0188D188818FF13
/// 18EC183E184318DE182B18AF18D5187218D00418B318CF186918CB187818A01830182B188D0918471865187018
/// E318FF182E188B18B30F188718D8187018D9081832181C186C18F41118CA181D184E189318E504184D18BB18D0
/// 184418CE18F8183A185904183A18E018181890189F18E9183A1843189F1612185B18E518D018EA18D5181F189A
/// 182118D7187918AE1876183518DF18EA031842182018C803182D186918AB185D18B118B9184E182C0618871718
/// 57184018A418C1183418AA18DA18CB181C18A418CC189E0818D2187C18E318AE183D18AD187F185818D818D218
/// E618A6184D1860188F185B1831189C1878187B18ED18A518C9182A182718C418DC18A9189418F718EA18D6187B
/// 051883188318FE184A188118A818A90B182F1218F51864189518450818AF184E186418600218B2186A188118C8
/// 18A70F1888188918F71871183A182618D118CB188318C3031831183218A818CE18B1182518AE18F4186818D018
/// 4418AA18981832188A18C41894186C14182C1888188118720D18FE187D18BD18E8061835187C188B1824187609
/// 18631861081833041859185718C318D7182E1867187718D218E9183A18C8183E182118471859187B1866183818
/// 5B18AC186818BF187A0B188718F01843183718A9188F182F020301000118A31882011886183018820118821830
/// 181F06031855181D1823041818183016188014186C188A189418A2187718B118801872181D1881187A1618AA18
/// F218DC18CE186618EE184518C01830181D06031855181D0E04160414187714184118A6185D1895182618D0181D
/// 18FF1895183B1862188C18EA18B718B5185D183B189218300E06031855181D0F010118FF040403020118861830
/// 186706031855181D18200418601830185E18300B060918601886184801186502010B182418300B060918601886
/// 184801186502010B182718300B060918601886184801186502010B182A18300B06091860188618480118650201
/// 0B183B18300C060A186018861848011865030201030D18300C060A186018861848011865030201031118300C06
/// 0A18601886184801186503020103182718301206031855181D13010118FF0408183006010118FF02010018300C
/// 06031855181D18240405183003188001001830183706031855181D181F0418301830182E1830182C18A0182A18
/// A01828188618261868187418741870183A182F182F18631872186C182E1864186918731861182E186D1869186C
/// 182F18631872186C182F1844184F18441852184F184F1854184318411833182E18631872186C1830186C060818
/// 2B060105050701010418601830185E1830183A0608182B06010505071830021886182E1868187418741870183A
/// 182F182F18631872186C182E1864186918731861182E186D1869186C182F186918731873187518651864187418
/// 6F182F1844184F18441852184F184F1854184318411833185F18491854182E187018371863183018200608182B
/// 06010505071830011886141868187418741870183A182F182F186F186318731870182E1864186918731861182E
/// 186D1869186C18300D0609182A18861848188618F70D01010B0500031882010100184D18CB18CD18D71865183C
/// 189818BB18860118D118CD18C9184818D31880185C18E6182518631827183318C50A185E18BB18CD1832185818
/// 56183218FE18481823183E011824184918BF0718DA18D7188F186E1845184A18DD1863188018D9184B1884187D
/// 11185D18951859187A181D18941851186706187A18580D0E18E118B41861188418A418181890188018A918C318
/// A3184A18481218BB18AC183D18BE18380D18E71846182A1894183A187D18F3188B18A5186A18E718FA186418DB
/// 184218A518E818A518AC1837187918290218AD1839187218A7182718880718850C18CB18D818CE18E60E188918
/// C7185F18F918FC1871188218A4189B187618C61874189818181897182718EE189018641822189E187B0618EC18
/// AE18D918F8185C18B71854181C183B181B183718F2189D18E30E18CD188218F7187118CA188B18971827182D18
/// 87071851189618E0188218D7181C00186218A5184918FB185B18B5183918BD187518E118F6182C18BC18DE182D
/// 18D01881184D18371890187C1825182E18D918841857189718C218B318D5184418F1188118B618DC1868184D18
/// 9E182618E218AF18CD18C118A2186518CA18F218231885183E18E01869185B18B618E818CA18D0183718DB1876
/// 18BD188D18B51318A90B189411183F1871183718E6182E181E189E18F46D7061727469616C5F706174687382A2
/// 782836433841393441323737423138303732314438313741313641414632444343453636454534354330818100
/// 782837373134343141363544393532364430314446463935334236323843454142374235354433423932818101
/// A17828373731343431413635443935323644303144464639353342363238434541423742353544334239328182
/// 0001
/// ```
///
/// The command below can be used to validate a target certificate issued by the CA in the 0th slot.
///
/// ```text
/// ./pittv3 -t ~/Desktop/Pittv3/pitt_tas_focused/ --cbor ~/Desktop/Pittv3/pitt_focused.cbor -v -e ~/Desktop/somecert.der
/// ```
///
/// The following output results in the location specified in the logging configuration. It shows
/// two certification paths were found and validated.
///
/// ```text
/// Stats for ~/Desktop/somecert.der
/// * Paths found: 2
/// * Valid paths found: 2
/// * Invalid paths found: 0
/// * Status codes
/// - Success: 2 - Result folder indices: [0, 1]
/// Total paths found: 2
/// Total valid paths found: 2
/// Total invalid paths found: 0
/// 5.016054ms to deserialize graph and perform build and validation operation(s) for 1 file(s)
/// ```
/// A dump of the partial certification paths included in the CBOR file illustrates why two paths
/// were found instead of three. When reading the vector containing the indices that compose a
/// partial certification path, the rightmost element (i.e., last element) issued the target and the
/// leftmost element (i.e., first) was issued by a trust anchor. Note, if the contents of the set of
/// trust anchors changes some partial paths may be orphaned.
///
/// ```text
/// $ ./target/release/pittv3 -b ~/Desktop/Pittv3/pitt_focused.cbor --list-partial-paths
/// 2022-01-21T15:36:21.755270-05:00 INFO pittv3::pitt_utils - PITTv3 start
/// 2022-01-21T15:36:21.756035-05:00 DEBUG pittv3::pitt_utils - DoD Root CA 3:
/// 2022-01-21T15:36:21.756048-05:00 DEBUG pittv3::pitt_utils -     * Issued by: \[0\] - DoD Interoperability Root CA 2,
/// 2022-01-21T15:36:21.756055-05:00 DEBUG pittv3::pitt_utils - DOD EMAIL CA-59:
/// 2022-01-21T15:36:21.756059-05:00 DEBUG pittv3::pitt_utils -     * Issued by: \[1\] - DoD Root CA 3,
/// 2022-01-21T15:36:21.756064-05:00 DEBUG pittv3::pitt_utils - DOD EMAIL CA-59:
/// 2022-01-21T15:36:21.756068-05:00 DEBUG pittv3::pitt_utils -     * Issued by: \[0, 1\] - DoD Interoperability Root CA 2,
/// 2022-01-21T15:36:21.756096-05:00 INFO pittv3::pitt_utils - PITTv3 end
/// ```
/// The discovered paths are the second and third available, as left CA certificate in the first
/// partial path did not issue the target certificate being validated. This is illustrated below by
/// listing all partial paths for the target certificate.
///
/// ```text
/// $ ./pittv3 -b ~/Desktop/Pittv3/pitt_focused.cbor --list-partial-paths-for-target ~/Desktop/somecert.der
/// 2022-01-21T15:40:41.462043-05:00 INFO pittv3::pitt_utils - PITTv3 start
/// 2022-01-21T15:40:41.462870-05:00 DEBUG pittv3::pitt_utils - DOD EMAIL CA-59:
/// 2022-01-21T15:40:41.462884-05:00 DEBUG pittv3::pitt_utils -     * Issued by: \[1\] - DoD Root CA 3,
/// 2022-01-21T15:40:41.462890-05:00 DEBUG pittv3::pitt_utils - DOD EMAIL CA-59:
/// 2022-01-21T15:40:41.462895-05:00 DEBUG pittv3::pitt_utils -     * Issued by: \[0, 1\] - DoD Interoperability Root CA 2,
/// 2022-01-21T15:40:41.462906-05:00 DEBUG pittv3::pitt_utils - Index: 0 ; SKID: 6C8A94A277B180721D817A16AAF2DCCE66EE45C0 ; Issuer: DoD Interoperability Root CA 2; DoD Root CA 3
/// 2022-01-21T15:40:41.462915-05:00 DEBUG pittv3::pitt_utils - Index: 1 ; SKID: 771441A65D9526D01DFF953B628CEAB7B55D3B92 ; Issuer: DoD Root CA 3; DOD EMAIL CA-59
/// 2022-01-21T15:40:41.462920-05:00 INFO pittv3::pitt_utils - Found 2 partial paths featuring 2 different intermediate CA certificates
/// 2022-01-21T15:40:41.462944-05:00 INFO pittv3::pitt_utils - PITTv3 end
/// ```
/// To complete the picture, below are dump of the buffers contained in the CBOR file and in the
/// operative trust anchors folder:
///
/// ```text
/// $ ./pittv3 -b ~/Desktop/Pittv3/pitt_focused.cbor --list-buffers
/// 2022-01-21T15:43:08.765425-05:00 INFO pittv3::pitt_utils - PITTv3 start
/// 2022-01-21T15:43:08.766190-05:00 DEBUG pittv3::pitt_utils - Index: 0; SKID: 6C8A94A277B180721D817A16AAF2DCCE66EE45C0; Iss: DoD Interoperability Root CA 2; Sub: DoD Root CA 3
/// 2022-01-21T15:43:08.766208-05:00 DEBUG pittv3::pitt_utils - Index: 1; SKID: 771441A65D9526D01DFF953B628CEAB7B55D3B92; Iss: DoD Root CA 3; Sub: DOD EMAIL CA-59
/// 2022-01-21T15:43:08.766233-05:00 INFO pittv3::pitt_utils - PITTv3 end
/// ```
/// ```text
/// $ ./pittv3 -b ~/Desktop/Pittv3/pitt_focused.cbor --list-trust-anchors -t ~/Desktop/Pittv3/pitt_tas_focused/
/// 2022-01-21T15:43:38.552252-05:00 INFO pittv3::pitt_utils - PITTv3 start
/// 2022-01-21T15:43:38.553131-05:00 DEBUG pittv3::pitt_utils - Index: 0; SKID: FFF8AE138B922B799241A3765C2C819E9AC59C78; Subject: DoD Interoperability Root CA 2
/// 2022-01-21T15:43:38.553151-05:00 DEBUG pittv3::pitt_utils - Index: 1; SKID: 6C8A94A277B180721D817A16AAF2DCCE66EE45C0; Subject: DoD Root CA 3
/// 2022-01-21T15:43:38.553176-05:00 INFO pittv3::pitt_utils - PITTv3 end
/// ```
/// The resulting paths will flow as follows:
/// - From the target through the certificate at Index 1 to the trust anchor at Index 1
/// - From the target through the certificates at indices 1 and 0 to the trust anchor at Index 0.
///
#[derive(Clone, Serialize, Deserialize)]
pub struct BuffersAndPaths {
    /// List of buffers containing binary DER-encoded certificates
    pub buffers: Vec<CertFile>,

    /// Maps skid of leaf CA (i.e., last index in each vector) to a vector of indices into buffers
    #[cfg(feature = "std")]
    pub partial_paths: Arc<Mutex<RefCell<PartialPaths>>>,

    /// Maps skid of leaf CA (i.e., last index in each vector) to a vector of indices into buffers
    #[cfg(not(feature = "std"))]
    pub partial_paths: RefCell<PartialPaths>,
}

/// Type used to represent partial certification paths in [`BuffersAndPaths`] struct
pub type PartialPaths = Vec<BTreeMap<String, Vec<Vec<usize>>>>;

impl Default for BuffersAndPaths {
    /// BuffersAndPaths::new instantiates a new empty BuffersAndPaths, i.e., both buffers and
    /// partial_paths contain empty vectors.
    fn default() -> Self {
        Self::new()
    }
}

impl BuffersAndPaths {
    /// BuffersAndPaths::new instantiates a new empty BuffersAndPaths, i.e., both buffers and
    /// partial_paths contain empty vectors.
    pub fn new() -> BuffersAndPaths {
        BuffersAndPaths {
            buffers: Vec::new(),
            #[cfg(feature = "std")]
            partial_paths: Arc::new(Mutex::new(RefCell::new(Vec::new()))),
            #[cfg(not(feature = "std"))]
            partial_paths: RefCell::new(Vec::new()),
        }
    }
}

/// The [`CertSource`] structure serves two purposes. First, it serves as a source of certificates by
/// maintaining a vector of certificate buffers and a corresponding vector of parsed certificates.
/// Second, it serves as a path builder implementation by maintaining a map of partial certificate
/// paths that can be serialized/deserialized.
///
/// Preparation of a [`CertSource`] requires four steps:
///   1. Create an empty [`CertSource`] instance via [`CertSource::new`] or [`CertSource::default`]
///   2. Populate the [`buffers_and_paths`](`CertSource`) member using desired sources, i.e., by deserializing a
///      CBOR file, by reading certificates from files, by downloading certificates via URIs, etc.
///   3. Call [`populate_parsed_cert_vector`](fn.populate_parsed_cert_vector.html) passing a reference to the [`buffers_and_paths`](`CertSource`) member and
///      a reference to the [`certs`](`CertSource`) member.
///   4. Prepare key identifier-based and name-based maps.
///
/// These steps allows an immutable vector of buffers to be used to produce a vector of long-lived
/// parsed certificate instances. The snip below, similar to code found in the PITTv3 utility, demonstrates preparation of
/// a CertSource structure from a CBOR file. In this snip, read_cbor reads a Vec<u8> from the file
/// indicated by the `cbor_file` variable then the `from_reader` function from the
/// [Ciborium](https://docs.rs/ciborium/latest/ciborium/) library deserializes the structure into
/// the [`BuffersAndPaths`] instance of the [`CertSource`] instance. Subsequent calls to
/// [`populate_parsed_cert_vector`](fn.populate_parsed_cert_vector.html) and
/// preparation of name and SKID maps must occur before using a CertSource instance.
///
/// ```ignore
///     let cbor = read_cbor(cbor_file);
///     let mut cert_source = CertSource::new();
///     cert_source.buffers_and_paths = from_reader(cbor.as_slice()).unwrap();
///     let r = populate_parsed_cert_vector(
///      &pe,
///      &cert_source.buffers_and_paths,
///      &cps,
///      &mut cert_source.certs,
///     );
///     if let Err(e) = r {
///      log_message(
///          &PeLogLevels::PeError,
///          format!("Failed to populate cert vector with: {:?}", e).as_str(),
///      );
///     }
///
///     cert_source.index_certs();
/// ```
///
/// The [`CertSource`] instance can then be passed to a [`PkiEnvironment`] instance to serve both as
/// a source of certificates and as a path building implementation, as shown below.
///
/// ```ignore
///    pe.add_certificate_source(&cert_source);
///    pe.add_path_builder(&cert_source);
/// ```
///
/// The general idea is to prepare an as comprehensive as possible set of partial certification paths
/// for the target environment in an offline manner then serialize it for deserialization later. This
/// should facilitate fairly robust certification path building in no-std apps. Deserialization of
/// partial paths moves the expensive path building aspects to offline (for most cases) while enabling
/// simple map lookups to serve the general case. The pace of new CA introduction is slow in many PKIs,
/// but this is not a universal truth, so dynamic building is possible and is demonstrated in
/// [`PITTv3`](../../pittv3/index.html).
///
/// Dynamic building support can return a list of AIAs and SIAs encountered during path discovery for
/// consideration, i.e., enabling additional certs to be downloaded before repeating the steps above to
/// gather new paths. Dynamic building consists of augmenting the buffers deserialized
/// from CBOR, re-parsing and re-indexing, then re-discovering all partial paths.
/// [`PITTv3`](../../pittv3/index.html) demonstrates an approach to performing these steps.
#[derive(Clone)]
pub struct CertSource<'a> {
    /// Contains list of parsed certificates prepared by the caller. The order of the certificates
    /// MUST be the same as the order of buffers in the buffers_and_paths.buffers field. If a buffer
    /// cannot be parsed successfully (or is otherwise rejected immediately, i.e., expired), the
    /// corresponding element in the certs field should be set to None.
    pub certs: Vec<Option<PDVCertificate<'a>>>,

    /// Contains list of buffers referenced by certs field and, optionally, partial paths
    /// relationships between certificates corresponding to those buffers. This field is the target
    /// of serialization/deserialization.
    pub buffers_and_paths: BuffersAndPaths,

    /// Maps certificate SKIDs to keys in the `certs` field. Typically, the SKID value is read from
    /// a SKID extension. If no extension is present, the value is calculated as the SHA256 hash of
    /// the SubjectPublicKeyInfoOwned field from the certificate.
    pub skid_map: BTreeMap<String, Vec<usize>>,

    /// Maps certificate subject names to keys in the `certs` field.
    pub name_map: BTreeMap<String, Vec<usize>>,
}

impl<'a> Default for CertSource<'a> {
    /// CertSource::default instantiates a new empty CertSource. The caller is responsible for populating
    /// the buffers_and_paths member then calling populate_parsed_cert_vector to populate the certs
    /// member then preparing skid and name maps prior to using instance.
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CertSource<'a> {
    /// CertSource::new instantiates a new empty CertSource. The caller is responsible for populating
    /// the buffers_and_paths member then calling populate_parsed_cert_vector to populate the certs
    /// member then preparing skid and name maps prior to using instance.
    pub fn new() -> CertSource<'a> {
        CertSource {
            certs: Vec::new(),
            buffers_and_paths: BuffersAndPaths::default(),
            skid_map: BTreeMap::new(),
            name_map: BTreeMap::new(),
        }
    }

    /// Log certificate details to PkiEnvironment's logging mechanism at debug level.
    pub fn log_certs(&self) {
        if self.certs.is_empty() {
            log_message(&PeLogLevels::PeInfo, "No certificates present");
        }

        for (i, c) in self.certs.iter().enumerate() {
            if let Some(cert) = c {
                let skid = hex_skid_from_cert(cert);
                let sub = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                let iss = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer);
                log_message(
                    &PeLogLevels::PeInfo,
                    format!(
                        "Index: {}; SKID: {}; Issuer: {}; Subject: {}",
                        i, skid, iss, sub
                    )
                    .as_str(),
                );
            }
        }
    }

    /// Log AIA and SIA details to PkiEnvironment's logging mechanism at debug level.
    pub fn log_all_aia_and_sia(&self, fresh_uris: &mut Vec<String>) {
        for c in self.certs.iter().flatten() {
            collect_uris_from_aia_and_sia(c, fresh_uris);
        }

        if fresh_uris.is_empty() {
            log_message(&PeLogLevels::PeInfo, "No AIA or SIA URIs observed");
            return;
        }

        fresh_uris.sort();
        for u in fresh_uris {
            log_message(&PeLogLevels::PeInfo, u.as_str());
        }
    }

    /// Log AIA and SIA details to PkiEnvironment's logging mechanism at debug level.
    pub fn log_all_name_constraints(&self) {
        let mut logged_some = false;
        for (i, c) in self.certs.iter().enumerate() {
            if let Some(cert) = c {
                let nc_ext = cert.get_extension(&ID_CE_NAME_CONSTRAINTS);
                if let Ok(Some(PDVExtension::NameConstraints(nc))) = nc_ext {
                    let skid = hex_skid_from_cert(cert);
                    let sub = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                    let iss = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer);
                    if let Some(perm) = &nc.permitted_subtrees {
                        logged_some = true;
                        log_message(
                            &PeLogLevels::PeInfo,
                            format!("Index: {}; SKID: {}; {}; Subject: {}", i, skid, iss, sub)
                                .as_str(),
                        );
                        log_message(&PeLogLevels::PeInfo, "Permitted Name Constraints");
                        for gs in perm {
                            log_message(
                                &PeLogLevels::PeInfo,
                                format!("- {}", general_subtree_to_string(gs)).as_str(),
                            );
                        }
                    }
                    if let Some(excl) = &nc.excluded_subtrees {
                        logged_some = true;
                        log_message(
                            &PeLogLevels::PeInfo,
                            format!("Index: {}; SKID: {}; {}; Subject: {}", i, skid, iss, sub)
                                .as_str(),
                        );
                        log_message(&PeLogLevels::PeInfo, "Excluded Name Constraints");
                        for gs in excl {
                            log_message(
                                &PeLogLevels::PeInfo,
                                format!("- {}", general_subtree_to_string(gs)).as_str(),
                            );
                        }
                    }
                }
            }
        }
        if !logged_some {
            log_message(&PeLogLevels::PeInfo, "No name constraints observed");
        }
    }

    /// Log partial path details to PkiEnvironment's logging mechanism at debug level.
    pub fn log_partial_paths(&self) {
        #[cfg(feature = "std")]
        let partial_paths_guard = if let Ok(g) = self.buffers_and_paths.partial_paths.lock() {
            g
        } else {
            return;
        };
        #[cfg(feature = "std")]
        let partial_paths = partial_paths_guard.deref().borrow();

        #[cfg(not(feature = "std"))]
        let partial_paths = &self.buffers_and_paths.partial_paths.borrow();

        if partial_paths.is_empty() {
            log_message(&PeLogLevels::PeInfo, "No partial paths available");
            return;
        }

        let mut counts = vec![];

        for (i, outer) in partial_paths.iter().enumerate() {
            counts.push(0);
            for key in outer.keys() {
                let inner = &outer[key];
                counts[i] += inner.len();
                let mut label = key.clone();
                if self.skid_map.contains_key(key) {
                    for c in &self.skid_map[key] {
                        let cert = &self.certs[*c];
                        if let Some(cert) = cert {
                            label = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                            break;
                        }
                    }
                }

                log_message(&PeLogLevels::PeInfo, format!("{}: ", label).as_str());

                for v in inner {
                    let cert = &self.certs[v[0]];
                    let vlabel = if let Some(cert) = cert {
                        get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer)
                    } else {
                        "".to_string()
                    };
                    log_message(
                        &PeLogLevels::PeInfo,
                        format!("\t* TA subject: {} - {:?}, ", vlabel, v).as_str(),
                    );
                }
            }
        }
        let mut non_null_certs = 0;
        for _ in self.certs.iter().flatten() {
            non_null_certs += 1;
        }
        let mut message = format!("{} certificates yielded: ", non_null_certs);
        for (i, count) in counts.iter().enumerate() {
            if 0 == i {
                message.push_str(format!("\n - {} paths with 1 certificate", count).as_str());
            } else if counts[i] != 0 {
                message.push_str(
                    format!(";\n - {} paths with {} certificates", count, i + 1).as_str(),
                );
            }
        }
        log_message(&PeLogLevels::PeInfo, message.as_str());
    }

    /// Logs info about partial paths and corresponding buffers for a given target
    pub fn log_paths_for_target(&'a self, target: &'a PDVCertificate<'a>, time_of_interest: u64) {
        if let Err(_e) = valid_at_time(&target.decoded_cert.tbs_certificate, time_of_interest, true)
        {
            log_message(
                &PeLogLevels::PeError,
                format!(
                    "No paths found because target is not valid at indicated time of interest ({})",
                    time_of_interest
                )
                .as_str(),
            );
            return;
        }

        #[cfg(feature = "std")]
        let partial_paths_guard = if let Ok(g) = self.buffers_and_paths.partial_paths.lock() {
            g
        } else {
            return;
        };
        #[cfg(feature = "std")]
        let partial_paths = partial_paths_guard.deref().borrow();

        #[cfg(not(feature = "std"))]
        let partial_paths = &self.buffers_and_paths.partial_paths.borrow();

        if partial_paths.is_empty() {
            if self.certs.is_empty() {
                log_message(&PeLogLevels::PeInfo, "No partial paths present");
            }
            return;
        }

        let mut akid_hex = "".to_string();
        let mut name_vec = vec![&target.decoded_cert.tbs_certificate.issuer];
        let akid_ext = target.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = akid_ext {
            if let Some(kid) = &akid.key_identifier {
                akid_hex = buffer_to_hex(kid.as_bytes());
            } else if let Some(names) = &akid.authority_cert_issuer {
                for n in names {
                    if let GeneralName::DirectoryName(dn) = n {
                        name_vec.push(dn);
                    }
                }
            }
        }

        if akid_hex.is_empty() {
            // try to use name map to find AKID
            for n in name_vec {
                let name_str = name_to_string(n);
                if self.name_map.contains_key(&name_str) {
                    for i in &self.name_map[&name_str] {
                        if let Some(cert) = &self.certs[*i] {
                            let skid = hex_skid_from_cert(cert);
                            if !skid.is_empty() {
                                log_message(
                                    &PeLogLevels::PeDebug,
                                    format!(
                                        "Using calculated key identifier in lieu of AKID for {}",
                                        name_str
                                    )
                                    .as_str(),
                                );
                                akid_hex = skid;
                                break;
                            }
                        }
                    }
                }
            }
        }

        let mut indices = vec![];
        let mut counter = 0;

        if !akid_hex.is_empty() {
            let key = akid_hex;
            for outer in partial_paths.iter() {
                if !outer.contains_key(&key) {
                    continue;
                }
                let inner = &outer[&key];
                let mut label = key.clone();
                for c in &self.skid_map[&key] {
                    let cert = &self.certs[*c];
                    if let Some(cert) = cert {
                        label = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                        break;
                    }
                }

                log_message(&PeLogLevels::PeInfo, format!("{}: ", label).as_str());

                for v in inner {
                    if v.is_empty() {
                        log_message(
                            &PeLogLevels::PeError,
                            format!("Empty partial paths vector for {}: . Skipping.", label)
                                .as_str(),
                        );
                        continue;
                    }

                    // This block accounts for CAs that use different names for same SKID. Could add name constraints check here too, maybe.
                    let last_index = if let Some(li) = v.last() {
                        li
                    } else {
                        continue;
                    };
                    let issuer = &self.certs[*last_index];
                    if let Some(ca) = issuer {
                        if !compare_names(
                            &ca.decoded_cert.tbs_certificate.subject,
                            &target.decoded_cert.tbs_certificate.issuer,
                        ) {
                            log_message(&PeLogLevels::PeError, "Encountered CA that is likely using same SKID with different names. Skipping partial path due to name mismatch.");
                            break;
                        }
                    }

                    let mut vlabel = "".to_string();
                    for ii in v {
                        if !indices.contains(ii) {
                            indices.push(*ii);
                        }
                    }
                    for ii in v {
                        let cert = &self.certs[*ii];
                        if let Some(cert) = cert {
                            vlabel = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer);
                            break;
                        }
                    }
                    counter += 1;
                    log_message(
                        &PeLogLevels::PeInfo,
                        format!("\t* TA subject: {} - {:?}, ", vlabel, v).as_str(),
                    );
                }
            }
        } else {
            let fname = get_filename_from_cert_metadata(target);
            log_message(
                &PeLogLevels::PeError,
                format!(
                    "Missing AKID in target and failed to find by name - {}",
                    fname
                )
                .as_str(),
            );
        }

        for (i, c) in self.certs.iter().enumerate() {
            if indices.contains(&i) {
                if let Some(cert) = c {
                    let skid = hex_skid_from_cert(cert);
                    let sub = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                    let iss = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer);
                    log_message(
                        &PeLogLevels::PeInfo,
                        format!(
                            "Index: {}; SKID: {}; Issuer: {}; Subject: {}",
                            i, skid, iss, sub
                        )
                        .as_str(),
                    );
                }
            }
        }
        log_message(
            &PeLogLevels::PeInfo,
            format!(
                "Found {} partial paths featuring {} different intermediate CA certificates",
                counter,
                indices.len()
            )
            .as_str(),
        );
    }

    /// Logs info about partial paths and corresponding buffers for a given target
    pub fn log_paths_for_leaf_ca(&'a self, target: &'a PDVCertificate<'a>) {
        #[cfg(feature = "std")]
        let partial_paths_guard = if let Ok(g) = self.buffers_and_paths.partial_paths.lock() {
            g
        } else {
            return;
        };
        #[cfg(feature = "std")]
        let partial_paths = partial_paths_guard.deref().borrow();

        #[cfg(not(feature = "std"))]
        let partial_paths = &self.buffers_and_paths.partial_paths.borrow();

        if partial_paths.is_empty() {
            if self.certs.is_empty() {
                log_message(&PeLogLevels::PeInfo, "No partial paths present");
            }
            return;
        }

        let mut skid_hex = "".to_string();
        let skid_ext = target.get_extension(&ID_CE_SUBJECT_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = skid_ext {
            skid_hex = buffer_to_hex(skid.0.as_bytes());
        }

        if skid_hex.is_empty() {
            skid_hex = hex_skid_from_cert(target);
        }

        let mut indices = vec![];
        let mut counter = 0;

        if !skid_hex.is_empty() {
            let key = skid_hex;
            for outer in partial_paths.iter() {
                if !outer.contains_key(&key) {
                    continue;
                }
                let inner = &outer[&key];
                let mut label = key.clone();
                for c in &self.skid_map[&key] {
                    let cert = &self.certs[*c];
                    if let Some(cert) = cert {
                        label = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                        break;
                    }
                }

                log_message(&PeLogLevels::PeInfo, format!("{}: ", label).as_str());

                for v in inner {
                    let mut vlabel = "".to_string();
                    for ii in v {
                        if !indices.contains(ii) {
                            indices.push(*ii);
                        }
                    }
                    for ii in v {
                        let cert = &self.certs[*ii];
                        if let Some(cert) = cert {
                            vlabel = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer);
                            break;
                        }
                    }
                    counter += 1;
                    log_message(
                        &PeLogLevels::PeInfo,
                        format!("\t* TA subject: {} - {:?}, ", vlabel, v).as_str(),
                    );
                }
            }
        } else {
            let fname = get_filename_from_cert_metadata(target);
            log_message(
                &PeLogLevels::PeError,
                format!(
                    "Missing SKID in leaf CA and failed to calculate one - {}",
                    fname
                )
                .as_str(),
            );
        }

        for (i, c) in self.certs.iter().enumerate() {
            if indices.contains(&i) {
                if let Some(cert) = c {
                    let skid = hex_skid_from_cert(cert);
                    let sub = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.subject);
                    let iss = get_leaf_rdn(&cert.decoded_cert.tbs_certificate.issuer);
                    log_message(
                        &PeLogLevels::PeInfo,
                        format!(
                            "Index: {}; SKID: {}; Issuer: {}; Subject: {}",
                            i, skid, iss, sub
                        )
                        .as_str(),
                    );
                }
            }
        }
        log_message(
            &PeLogLevels::PeInfo,
            format!(
                "Found {} partial paths featuring {} different intermediate CA certificates",
                counter,
                indices.len()
            )
            .as_str(),
        );
    }

    //TODO restore (probably by changing maps to rely on interior mutability)
    // index_certs prepares internally used key identifier and name maps after the caller has modified
    // the buffers_and_paths and certs fields.
    // pub fn index_certs(&mut self) {
    //     for (i, cert) in self.certs.iter().enumerate() {
    //         if let Some(cert) = cert {
    //             let hex_skid = hex_skid_from_cert(cert);
    //             if self.skid_map.contains_key(&hex_skid) {
    //                 let mut v = self.skid_map[&hex_skid].clone();
    //                 v.push(i);
    //                 self.skid_map.insert(hex_skid, v);
    //             } else {
    //                 self.skid_map.insert(hex_skid, vec![i]);
    //             }
    //
    //             let name_str = name_to_string(&cert.decoded_cert.tbs_certificate.subject);
    //             if self.name_map.contains_key(&name_str) {
    //                 let mut v = self.name_map[&name_str].clone();
    //                 v.push(i);
    //                 self.name_map.insert(name_str, v);
    //             } else {
    //                 self.name_map.insert(name_str, vec![i]);
    //             }
    //         }
    //     }
    // }

    fn pub_key_in_path(&self, prospective_cert: &PDVCertificate<'a>, path: &[usize]) -> bool {
        for i in path {
            let path_item = &self.certs[*i];
            if let Some(path_item) = path_item {
                if path_item
                    .decoded_cert
                    .tbs_certificate
                    .subject_public_key_info
                    == prospective_cert
                        .decoded_cert
                        .tbs_certificate
                        .subject_public_key_info
                {
                    return true;
                }
            } else {
                // the index references an empty slot where an un-parseable or time invalid buffer was found
                return false;
            }
        }
        false
    }

    fn get_operative_path_len_constraint(&self, path: &[usize]) -> u8 {
        let mut path_len_constraint = 15;
        for i in path {
            if let Some(ca_cert) = &self.certs[*i] {
                if !is_self_issued(&ca_cert.decoded_cert) {
                    if path_len_constraint == 0 {
                        return 0;
                    }
                    path_len_constraint -= 1;
                }

                let pdv_ext = ca_cert.get_extension(&ID_CE_BASIC_CONSTRAINTS);
                if let Ok(Some(PDVExtension::BasicConstraints(bc))) = pdv_ext {
                    // (k)  If certificate i is a version 3 certificate, verify that the
                    //       basicConstraints extension is present and that cA is set to
                    //       TRUE.  (If certificate i is a version 1 or version 2
                    //       certificate, then the application MUST either verify that
                    //       certificate i is a CA certificate through out-of-band means
                    //       or reject the certificate.  Conforming implementations may
                    //       choose to reject all version 1 and version 2 intermediate
                    //       certificates.)
                    if !bc.ca {
                        return 0;
                    }

                    if let Some(pl) = bc.path_len_constraint {
                        // (m)  If pathLenConstraint is present in the certificate and is
                        //       less than max_path_length, set max_path_length to the value
                        //       of pathLenConstraint.
                        path_len_constraint = if path_len_constraint > pl {
                            pl
                        } else {
                            path_len_constraint
                        }
                    }
                } else {
                    // no basic constraints
                    return 0;
                }
            } else {
                return 0;
            }
        }
        path_len_constraint
    }

    /// check_validity_in_partial_path takes a set of indices and returns true if all are valid at time of interest and false
    /// otherwise. if there is no time of interest, true is returned.
    pub fn check_validity_in_partial_path(
        &self,
        path: &[usize],
        cps: &CertificationPathSettings,
    ) -> bool {
        let time_of_interest = get_time_of_interest(cps);
        if 0 == time_of_interest {
            return true;
        }
        for i in path.iter() {
            if let Some(ca_cert) = &self.certs[*i] {
                if let Err(_e) = valid_at_time(
                    &ca_cert.decoded_cert.tbs_certificate,
                    time_of_interest,
                    false,
                ) {
                    return false;
                }
            }
        }
        true
    }

    /// check_names_in_partial_path takes a vector of indices that comprise a prospective partial
    /// path and checks for name constraints violations. This only checks for violations in the
    /// partial path itself. Issues when paired with some trust anchors or targets may still exist.
    pub fn check_names_in_partial_path(&self, path: &[usize]) -> bool {
        let mut permitted_subtrees = NameConstraintsSet::default();
        let mut excluded_subtrees = NameConstraintsSet::default();
        let mut perm_names_set = false;

        // Iterate over the list of intermediate CA certificates plus target to check name chaining
        for (pos, i) in path.iter().enumerate() {
            if let Some(ca_cert) = &self.certs[*i] {
                let self_issued = is_self_issued(&ca_cert.decoded_cert);

                if (pos + 1) == path.len() || !self_issued {
                    if !permitted_subtrees.subject_within_permitted_subtrees(
                        &ca_cert.decoded_cert.tbs_certificate.subject,
                    ) {
                        return false;
                    }

                    if excluded_subtrees.subject_within_excluded_subtrees(
                        &ca_cert.decoded_cert.tbs_certificate.subject,
                    ) {
                        return false;
                    }

                    let san = if let Ok(Some(PDVExtension::SubjectAltName(san))) =
                        ca_cert.get_extension(&ID_CE_SUBJECT_ALT_NAME)
                    {
                        Some(san)
                    } else {
                        None
                    };

                    if !permitted_subtrees.san_within_permitted_subtrees(&san) {
                        return false;
                    }

                    if excluded_subtrees.san_within_excluded_subtrees(&san) {
                        return false;
                    }
                }

                if pos + 1 != path.len() {
                    if let Ok(Some(PDVExtension::NameConstraints(nc))) =
                        ca_cert.get_extension(&ID_CE_NAME_CONSTRAINTS)
                    {
                        if let Some(excl) = &nc.excluded_subtrees {
                            excluded_subtrees.calculate_union(excl);
                        }
                        if let Some(perm) = &nc.permitted_subtrees {
                            permitted_subtrees.calculate_intersection(perm);
                        }

                        if perm_names_set && permitted_subtrees.are_any_empty() {
                            return false;
                        } else if !perm_names_set && permitted_subtrees.are_any_empty() {
                            perm_names_set = true;
                        }
                    }
                }
            }
        } // end for (pos, ca_cert_ref) in v.iter_mut().enumerate() {

        true
    }

    fn find_prospective_issuers(&self, target: &'_ PDVCertificate<'_>) -> Vec<String> {
        let mut retval: Vec<String> = vec![];

        let mut akid_hex = "".to_string();
        let mut name_vec = vec![&target.decoded_cert.tbs_certificate.issuer];
        let akid_ext = target.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = akid_ext {
            if let Some(kid) = &akid.key_identifier {
                akid_hex = buffer_to_hex(kid.as_bytes());
            } else if let Some(names) = &akid.authority_cert_issuer {
                for n in names {
                    if let GeneralName::DirectoryName(dn) = n {
                        name_vec.push(dn);
                    }
                }
            }
        }

        if !akid_hex.is_empty() {
            retval.push(akid_hex);
        }
        for n in name_vec {
            let name_str = name_to_string(n);
            if self.name_map.contains_key(&name_str) {
                for i in &self.name_map[&name_str] {
                    if let Some(c) = &self.certs[*i] {
                        let skid = hex_skid_from_cert(c);
                        if !retval.contains(&skid) {
                            retval.push(skid);
                        }
                    }
                }
            }
        }

        retval
    }

    /// find_all_partial_paths_internal is a slow recursive builder intended for offline use prior
    /// to serializing a set of partial paths. Partial paths are represented as a vector of maps,
    /// where the maps are keyed using an ASCII hex key identifier with a vector of indices as the
    /// value: Vec<BTreeMap<String, Vec<usize>>>. The key identifier value used as the key is that of
    /// the last element in the vector of indices. Key identifier values are typically read from
    /// a subject key identifier extension, but if that is absent a value is calculated.
    ///
    /// The 0th element in the outer vector features a map that contains paths that feature one CA
    /// certificate, i.e., CAs that are issued by an available trust anchor. The 1st element in the
    /// outer vector features a map that contains paths that feature two CA certificates, i.e., a
    /// copy of an item in the 0th element with one certificate added.
    ///
    /// To build a path for a given target certificate, one iterates over the outer vector and saves
    /// vectors of indices from the map element corresponding to the desired key identifier. The
    /// resulting set of partial paths will proceed from shortest available path to longest.
    ///
    fn find_all_partial_paths_internal(
        &self,
        pe: &'_ PkiEnvironment<'_>,
        //todo remove param
        _ta_vec: Vec<&PDVTrustAnchorChoice<'_>>,
        cps: &CertificationPathSettings,
        pass: u8,
        partial_paths: &mut Vec<BTreeMap<String, Vec<Vec<usize>>>>,
    ) {
        // Instantiate a map that will aggregate paths built relative to the 0th or pass-1 row in
        // self.buffers_and_paths.partial_paths, if any.
        let mut new_additions: BTreeMap<String, Vec<Vec<usize>>> = BTreeMap::new();

        // iterate over all certs in the self.certs vector.
        for (cur_cert_index, cur_cert) in self.certs.iter().enumerate() {
            // skip over elements that don't have a cert (these correspond to buffers in
            // self.buffers_and_paths.buffers that could not be parsed when self.certs was prepared.
            if let Some(cur_cert) = cur_cert {
                let cur_cert_hex_skid = hex_skid_from_cert(cur_cert);
                if 0 == pass {
                    let ta = pe.get_trust_anchor_for_target(cur_cert);
                    if let Ok(ta) = ta {
                        // RFC 5914 TAs do not necessary have to have a name, if this is one of those, ignore it
                        let ta_name = get_trust_anchor_name(&ta.decoded_ta);
                        if let Ok(ta_name) = ta_name {
                            if compare_names(&cur_cert.decoded_cert.tbs_certificate.issuer, ta_name)
                            {
                                let defer_cert = DeferDecodeSigned::from_der(cur_cert.encoded_cert);
                                if let Ok(defer_cert) = defer_cert {
                                    let spki = get_subject_public_key_info_from_trust_anchor(
                                        &ta.decoded_ta,
                                    );
                                    let r = pe.verify_signature_message(
                                        pe,
                                        defer_cert.tbs_field,
                                        cur_cert.decoded_cert.signature.raw_bytes(),
                                        &cur_cert.decoded_cert.tbs_certificate.signature,
                                        spki,
                                    );
                                    if let Ok(_r) = r {
                                        let new_path = vec![cur_cert_index];
                                        if new_additions.contains_key(&cur_cert_hex_skid) {
                                            if !new_additions[&cur_cert_hex_skid]
                                                .contains(&new_path)
                                            {
                                                let mut v =
                                                    new_additions[&cur_cert_hex_skid].clone();
                                                v.push(new_path);
                                                new_additions.insert(cur_cert_hex_skid.clone(), v);
                                            }
                                        } else {
                                            new_additions
                                                .insert(cur_cert_hex_skid.clone(), vec![new_path]);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    let defer_cert = DeferDecodeSigned::from_der(cur_cert.encoded_cert);
                    if let Ok(defer_cert) = defer_cert {
                        // look for matches in map from previous row of partial_paths
                        let last_row = &partial_paths[(pass - 1) as usize];

                        // get list of SKIDs for possible issuers (based on AKID and name lookups)
                        let prospective_issuers = self.find_prospective_issuers(cur_cert);
                        for k in prospective_issuers {
                            //log_message(&PeLogLevels::PeDebug, format!("LAST ROW FOR PASS #{} {:?}", pass, last_row.keys()).as_str());
                            if !last_row.contains_key(&k) {
                                continue;
                            }
                            let prospective_paths = &last_row[&k];
                            for prospective_path in prospective_paths {
                                let prospective_ca_cert =
                                    &self.certs[prospective_path[prospective_path.len() - 1]];
                                if let Some(prospective_ca_cert) = prospective_ca_cert {
                                    if 0 == self.get_operative_path_len_constraint(prospective_path)
                                    {
                                        continue;
                                    }

                                    // should path settings be used more generally than time of interest?
                                    // Not doing that at present because policy and name constraints
                                    // are more variable than use of current time as time of interest
                                    if compare_names(
                                        &cur_cert.decoded_cert.tbs_certificate.issuer,
                                        &prospective_ca_cert.decoded_cert.tbs_certificate.subject,
                                    ) && self.check_names_in_partial_path(prospective_path)
                                        && self
                                            .check_validity_in_partial_path(prospective_path, cps)
                                    {
                                        let r = pe.verify_signature_message(
                                            pe,
                                            defer_cert.tbs_field,
                                            cur_cert.decoded_cert.signature.raw_bytes(),
                                            &cur_cert.decoded_cert.tbs_certificate.signature,
                                            &prospective_ca_cert
                                                .decoded_cert
                                                .tbs_certificate
                                                .subject_public_key_info,
                                        );
                                        if let Ok(_r) = r {
                                            if !self.pub_key_in_path(cur_cert, prospective_path) {
                                                let mut new_path = prospective_path.clone();
                                                new_path.push(cur_cert_index);
                                                if new_additions
                                                    .contains_key(&cur_cert_hex_skid.clone())
                                                {
                                                    if !new_additions[&cur_cert_hex_skid]
                                                        .contains(&new_path)
                                                    {
                                                        let mut v = new_additions
                                                            [&cur_cert_hex_skid]
                                                            .clone();
                                                        v.push(new_path);
                                                        new_additions
                                                            .insert(cur_cert_hex_skid.clone(), v);
                                                    }
                                                } else {
                                                    new_additions.insert(
                                                        cur_cert_hex_skid.clone(),
                                                        vec![new_path],
                                                    );
                                                }
                                            }
                                        }
                                    } // end compare_names
                                }
                            }
                        }
                    }
                } // end if 0 == pass {
            } // end if let Some(cur_cert) = cur_cert {
        }
        if !new_additions.is_empty() {
            //log_message(&PeLogLevels::PeDebug, format!("NEW ADDITIONS FOR PASS #{}: {:?}", pass, new_additions).as_str());
            partial_paths.push(new_additions);
            // 13 because the number of passes does not count TA or target
            if (PS_MAX_PATH_LENGTH_CONSTRAINT - 2) > pass {
                self.find_all_partial_paths_internal(pe, _ta_vec, cps, pass + 1, partial_paths);
            }
        }
    }

    /// serialize_partial_paths returns a buffer containing a CBOR encoding of the buffers_and_paths
    /// field of a CertSource instance. This can be deserialized then used as input to the process
    /// to prepare a new CertSource instance for use.
    pub fn serialize_partial_paths(
        &self,
        format: CertificationPathBuilderFormats,
    ) -> Result<Vec<u8>> {
        if CertificationPathBuilderFormats::Cbor != format {
            log_message(&PeLogLevels::PeError, "Format other than CBOR requested when serializing partial paths. Only CBOR is accepted presently.");
            return Err(Error::Unrecognized);
        }

        let mut ppcounter = 0;

        #[cfg(feature = "std")]
        let partial_paths_guard = if let Ok(g) = self.buffers_and_paths.partial_paths.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let partial_paths = partial_paths_guard.deref().borrow();

        #[cfg(not(feature = "std"))]
        let partial_paths = &self.buffers_and_paths.partial_paths.borrow();

        for outer in partial_paths.iter() {
            for key in outer.keys() {
                let inner = &outer[key];
                ppcounter += inner.len();
            }
        }
        log_message(
            &PeLogLevels::PeInfo,
            format!(
                "Serializing {} buffers and {} partial paths",
                self.buffers_and_paths.buffers.len(),
                ppcounter
            )
            .as_str(),
        );

        // drop mutex so serde can claim it
        #[cfg(feature = "std")]
        std::mem::drop(partial_paths);
        #[cfg(feature = "std")]
        std::mem::drop(partial_paths_guard);

        let mut buffer = Vec::new();
        let r = into_writer(&self.buffers_and_paths, &mut buffer);
        match r {
            Ok(_) => Ok(buffer),
            Err(e) => {
                log_message(
                    &PeLogLevels::PeError,
                    format!(
                        "Failed to generate CBOR file containing partial paths with error: {:?}",
                        e
                    )
                    .as_str(),
                );
                Err(Error::Unrecognized)
            }
        }
    }

    /// find_all_partial_paths is a slow recursive builder intended for offline use prior to
    /// serializing a set of partial paths.
    pub fn find_all_partial_paths(
        &self,
        pe: &'_ PkiEnvironment<'_>,
        cps: &CertificationPathSettings,
    ) {
        let mut ta_vec = vec![];
        if let Ok(tav) = pe.get_trust_anchors() {
            ta_vec = tav;
        }

        #[cfg(feature = "std")]
        let partial_paths_guard = if let Ok(g) = self.buffers_and_paths.partial_paths.lock() {
            g
        } else {
            return;
        };
        #[cfg(feature = "std")]
        let mut partial_paths = partial_paths_guard.deref().borrow_mut();

        #[cfg(not(feature = "std"))]
        let mut partial_paths = self.buffers_and_paths.partial_paths.borrow_mut();

        self.find_all_partial_paths_internal(pe, ta_vec, cps, 0, &mut partial_paths);
    }
}

impl CertificationPathBuilder for CertSource<'_> {
    /// find_paths_for_target takes a target certificate and a source for trust anchors and returns
    /// a vector of CertificationPath objects.
    fn get_paths_for_target<'a, 'reference>(
        &'a self,
        pe: &'a PkiEnvironment<'a>,
        target: &'a PDVCertificate<'a>,
        paths: &'reference mut Vec<CertificationPath<'a>>,
        threshold: usize,
        time_of_interest: u64,
    ) -> Result<()>
    where
        'a: 'reference,
    {
        if let Err(_e) = valid_at_time(&target.decoded_cert.tbs_certificate, time_of_interest, true)
        {
            log_message(
                &PeLogLevels::PeError,
                format!(
                    "No paths found because target is not valid at indicated time of interest ({})",
                    time_of_interest
                )
                .as_str(),
            );
            return Ok(());
        }

        let ta = pe.get_trust_anchor_for_target(target);
        if let Ok(ta) = ta {
            let path = CertificationPath::new(ta, vec![], target);
            paths.push(path);
        }

        let mut akid_hex = "".to_string();
        let mut name_vec = vec![&target.decoded_cert.tbs_certificate.issuer];
        let akid_ext = target.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = akid_ext {
            if let Some(kid) = &akid.key_identifier {
                akid_hex = buffer_to_hex(kid.as_bytes());
            } else if let Some(names) = &akid.authority_cert_issuer {
                for n in names {
                    if let GeneralName::DirectoryName(dn) = n {
                        name_vec.push(dn);
                    }
                }
            }
        }

        let paths_count = paths.len();

        let mut ii = 0;
        while ii < 2 {
            ii += 1;
            if !akid_hex.is_empty() {
                #[cfg(feature = "std")]
                let partial_paths_guard = if let Ok(g) = self.buffers_and_paths.partial_paths.lock()
                {
                    g
                } else {
                    return Err(Error::Unrecognized);
                };
                #[cfg(feature = "std")]
                let partial_paths = partial_paths_guard.deref().borrow();
                #[cfg(not(feature = "std"))]
                let partial_paths = &self.buffers_and_paths.partial_paths.borrow();

                for p in partial_paths.iter() {
                    if p.contains_key(&akid_hex) {
                        let indices_vec = &p[&akid_hex];
                        for indices in indices_vec {
                            if !above_threshold(indices, threshold) {
                                continue;
                            }

                            // This block accounts for CAs that use different names for same SKID. Could add name constraints check here too, maybe.
                            let last_index = if let Some(li) = indices.last() {
                                li
                            } else {
                                continue;
                            };
                            let issuer = &self.certs[*last_index];
                            if let Some(ca) = issuer {
                                if !compare_names(
                                    &ca.decoded_cert.tbs_certificate.subject,
                                    &target.decoded_cert.tbs_certificate.issuer,
                                ) {
                                    log_message(&PeLogLevels::PeError, "Encountered CA that is likely using same SKID with different names. Skipping partial path due to name mismatch.");
                                    continue;
                                }
                            }

                            let mut ta = None;
                            let mut intermediates = vec![];
                            let mut found_blank = false;
                            for (i, index) in indices.iter().enumerate() {
                                if let Some(cert) = &self.certs[*index] {
                                    intermediates.push(cert);
                                    if 0 == i {
                                        let mut ta_akid_hex = "".to_string();
                                        let mut ta_name_vec =
                                            vec![&target.decoded_cert.tbs_certificate.issuer];
                                        let ca_akid_ext =
                                            cert.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
                                        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(
                                            ca_akid,
                                        ))) = ca_akid_ext
                                        {
                                            if let Some(ca_kid) = &ca_akid.key_identifier {
                                                ta_akid_hex = buffer_to_hex(ca_kid.as_bytes());
                                            } else if let Some(names) =
                                                &ca_akid.authority_cert_issuer
                                            {
                                                for n in names {
                                                    if let GeneralName::DirectoryName(dn) = n {
                                                        ta_name_vec.push(dn);
                                                    }
                                                }
                                            }
                                        }

                                        if !ta_akid_hex.is_empty() {
                                            if let Ok(new_ta) =
                                                pe.get_trust_anchor_by_hex_skid(&ta_akid_hex)
                                            {
                                                ta = Some(new_ta);
                                            }
                                        } else {
                                            let fname = get_filename_from_cert_metadata(cert);
                                            log_message(
                                                &PeLogLevels::PeError,
                                                format!(
                                                    "Missing AKID for trust anchor - {}",
                                                    fname
                                                )
                                                .as_str(),
                                            );
                                            if let Ok(new_ta) = pe.get_trust_anchor_for_target(cert)
                                            {
                                                log_message(
                                                    &PeLogLevels::PeError,
                                                    "Found trust anchor by name",
                                                );
                                                ta = Some(new_ta);
                                            }
                                        }
                                    }
                                } else {
                                    // some cert slots are empty (due to parse or validity error). skip those.
                                    found_blank = true;
                                    break;
                                }
                            }
                            if !found_blank {
                                if let Some(ta) = ta {
                                    let path = CertificationPath::new(ta, intermediates, target);
                                    if !pub_key_repeats(&path) {
                                        ii = 2;
                                        paths.push(path);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                let fname = get_filename_from_cert_metadata(target);
                log_message(
                    &PeLogLevels::PeError,
                    format!(
                        "Missing AKID in target and failed to find by name - {}",
                        fname
                    )
                    .as_str(),
                );
            }

            if akid_hex.is_empty() || paths_count == paths.len() {
                // try to use name map to find AKID
                let mut changed = false;
                for n in &name_vec {
                    let name_str = name_to_string(n);
                    if self.name_map.contains_key(&name_str) {
                        for i in &self.name_map[&name_str] {
                            if let Some(cert) = &self.certs[*i] {
                                let skid = hex_skid_from_cert(cert);
                                if !skid.is_empty() {
                                    log_message(
                                        &PeLogLevels::PeDebug,
                                        format!(
                                            "Using calculated key identifier in lieu of AKID for {}",
                                            name_str
                                        )
                                            .as_str(),
                                    );
                                    akid_hex = skid;
                                    changed = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if !changed {
                    ii = 2;
                }
            }
        }

        Ok(())
    }
}

impl CertificateSource for CertSource<'_> {
    fn get_certificates_for_skid(&'_ self, skid: &[u8]) -> Result<Vec<&PDVCertificate<'_>>> {
        let hex_skid = buffer_to_hex(skid);
        let mut retval = vec![];
        if self.skid_map.contains_key(hex_skid.as_str()) {
            for i in &self.skid_map[&hex_skid] {
                if let Some(cert) = &self.certs[*i] {
                    retval.push(cert);
                }
            }
        }

        if retval.is_empty() {
            Err(Error::NotFound)
        } else {
            Ok(retval)
        }
    }

    fn get_certificates_for_name(&'_ self, name: &Name) -> Result<Vec<&PDVCertificate<'_>>> {
        let name_str = name_to_string(name);
        let mut retval = vec![];
        if self.name_map.contains_key(name_str.as_str()) {
            for i in &self.name_map[&name_str] {
                if let Some(cert) = &self.certs[*i] {
                    retval.push(cert);
                }
            }
        }

        if retval.is_empty() {
            Err(Error::NotFound)
        } else {
            Ok(retval)
        }
    }

    fn get_certificates(&'_ self) -> Result<Vec<&PDVCertificate<'_>>> {
        let mut v = vec![];
        for ta in self.certs.iter().flatten() {
            v.push(ta);
        }

        Ok(v)
    }

    fn get_encoded_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<Vec<u8>>> {
        let hex_skid = buffer_to_hex(skid);
        let mut retval = vec![];
        if self.skid_map.contains_key(hex_skid.as_str()) {
            for i in &self.skid_map[&hex_skid] {
                if let Some(cert) = &self.certs[*i] {
                    retval.push(cert.encoded_cert.to_owned().to_vec());
                }
            }
        }

        if retval.is_empty() {
            Err(Error::NotFound)
        } else {
            Ok(retval)
        }
    }

    fn get_encoded_certificates_for_name(&self, name: &Name) -> Result<Vec<Vec<u8>>> {
        let name_str = name_to_string(name);
        let mut retval = vec![];
        if self.name_map.contains_key(name_str.as_str()) {
            for i in &self.name_map[&name_str] {
                if let Some(cert) = &self.certs[*i] {
                    retval.push(cert.encoded_cert.to_owned().to_vec());
                }
            }
        }

        if retval.is_empty() {
            Err(Error::NotFound)
        } else {
            Ok(retval)
        }
    }

    fn get_encoded_certificates(&self) -> Result<Vec<Vec<u8>>> {
        let mut v = vec![];
        for cert in self.certs.iter().flatten() {
            v.push(cert.encoded_cert.to_owned().to_vec());
        }
        Ok(v)
    }
}

fn above_threshold(v: &[usize], t: usize) -> bool {
    if 0 == t {
        return true;
    }

    for i in v {
        if *i > t - 1 {
            // if at least one item is above the threshold, let it pass
            return true;
        }
    }
    false
}

fn pub_key_repeats(path: &CertificationPath<'_>) -> bool {
    let mut spki_array: Vec<&SubjectPublicKeyInfoOwned> =
        vec![get_subject_public_key_info_from_trust_anchor(
            &path.trust_anchor.decoded_ta,
        )];
    for c in &path.intermediates {
        let ca = *c;
        if spki_array.contains(&&ca.decoded_cert.tbs_certificate.subject_public_key_info) {
            return true;
        } else {
            spki_array.push(&c.decoded_cert.tbs_certificate.subject_public_key_info);
        }
    }
    false
}

/// The populate_cert_map is used to prepare a vector of [`PDVCertificate`] instances. This is typically be done
/// in support of preparing a [`CertSource`] instance, where the `bap` parameter is `buffer_and_paths`
/// field of a [`CertSource`] instance and the `cert_store` parameter is the `certs` field of the same
/// [`CertSource`] instance. It takes a [`BuffersAndPaths`] instance that includes the buffers that
/// will be parsed to populate the vector.
pub fn populate_parsed_cert_vector<'a, 'reference>(
    bap: &'a BuffersAndPaths,
    cps: &CertificationPathSettings,
    cert_store: &'reference mut Vec<Option<PDVCertificate<'a>>>,
) -> Result<()>
where
    'a: 'reference,
{
    let time_of_interest = get_time_of_interest(cps);
    for (i, cert_file) in bap.buffers.iter().enumerate() {
        if let Ok(cert) = Certificate::from_der(bap.buffers[i].bytes.as_slice()) {
            let valid = if let 0 = time_of_interest {
                true
            } else {
                let r = valid_at_time(&cert.tbs_certificate, time_of_interest, false);
                if r.is_err() {
                    log_message(
                        &PeLogLevels::PeError,
                        format!(
                            "Certificate from {} is not valid at indicated time of interest",
                            cert_file.filename
                        )
                        .as_str(),
                    );
                }
                matches!(r, Ok(_x))
            };

            if valid {
                let mut md = Asn1Metadata::new();
                md.insert(
                    MD_LOCATOR,
                    Asn1MetadataTypes::String(cert_file.filename.clone()),
                );

                let mut pdvcert = PDVCertificate {
                    encoded_cert: bap.buffers[i].bytes.as_slice(),
                    decoded_cert: cert,
                    metadata: Some(md),
                    parsed_extensions: ParsedExtensions::new(),
                };
                pdvcert.parse_extensions(EXTS_OF_INTEREST);
                cert_store.push(Some(pdvcert));
            } else {
                cert_store.push(None);
            }
        } else {
            cert_store.push(None);
        }
    }
    Ok(())
}

/// get_filename_from_ta_metadata returns the string from the MD_LOCATOR in the metadata or an
/// empty string.
pub fn get_filename_from_cert_metadata(cert: &PDVCertificate<'_>) -> String {
    if let Some(md) = &cert.metadata {
        if let Asn1MetadataTypes::String(filename) = &md[MD_LOCATOR] {
            return filename.to_owned();
        }
    }
    "".to_string()
}

#[cfg(feature = "std")]
#[test]
fn get_certificates_test() {
    use crate::encode_dn_from_string;
    use crate::file_utils::cert_folder_to_vec;
    use der::Decode;
    use hex_literal::hex;

    let mut cert_store = CertSource::new();
    let pe = PkiEnvironment::default();
    assert!(cert_folder_to_vec(
        &pe,
        "tests/examples/PKITS_data_2048/certs",
        &mut cert_store.buffers_and_paths.buffers,
        1647258133,
    )
    .is_ok());
    let cps = CertificationPathSettings::default();
    assert!(populate_parsed_cert_vector(
        &cert_store.buffers_and_paths,
        &cps,
        &mut cert_store.certs
    )
    .is_ok());
    for (i, cert) in cert_store.certs.iter().enumerate() {
        if let Some(cert) = cert {
            let hex_skid = hex_skid_from_cert(cert);
            if cert_store.skid_map.contains_key(&hex_skid) {
                let mut v = cert_store.skid_map[&hex_skid].clone();
                v.push(i);
                cert_store.skid_map.insert(hex_skid, v);
            } else {
                cert_store.skid_map.insert(hex_skid, vec![i]);
            }

            let name_str = name_to_string(&cert.decoded_cert.tbs_certificate.subject);
            if cert_store.name_map.contains_key(&name_str) {
                let mut v = cert_store.name_map[&name_str].clone();
                v.push(i);
                cert_store.name_map.insert(name_str, v);
            } else {
                cert_store.name_map.insert(name_str, vec![i]);
            }
        }
    }

    let v = cert_store
        .get_certificates_for_skid(&hex!("A83C099D67F6D847BAA2D0FC18725688406D9595"))
        .unwrap();
    assert_eq!(v.len(), 1);
    let r = cert_store.get_certificates_for_skid(&hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    assert!(r.is_err());
    assert_eq!(r.err(), Some(Error::NotFound));

    let en = encode_dn_from_string("C=US,O=Test Certificates 2011,CN=Valid EE Certificate Test1")
        .unwrap();
    let n = Name::from_der(en.as_slice()).unwrap();
    let en2 = encode_dn_from_string("C=US,O=Test Certificates 2011,CN=Does Not Exist").unwrap();
    let n2 = Name::from_der(en2.as_slice()).unwrap();
    let v = cert_store.get_certificates_for_name(&n).unwrap();
    assert_eq!(v.len(), 1);
    let r = cert_store.get_certificates_for_name(&n2);
    assert!(r.is_err());
    assert_eq!(r.err(), Some(Error::NotFound));

    let v = cert_store.get_certificates().unwrap();
    // there are 405 certs in the folder, but some fail to parse
    assert_eq!(399, v.len());

    let v = cert_store
        .get_encoded_certificates_for_skid(&hex!("A83C099D67F6D847BAA2D0FC18725688406D9595"))
        .unwrap();
    assert_eq!(v.len(), 1);
    let r = cert_store
        .get_encoded_certificates_for_skid(&hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    assert!(r.is_err());
    assert_eq!(r.err(), Some(Error::NotFound));

    let v = cert_store.get_encoded_certificates_for_name(&n).unwrap();
    assert_eq!(v.len(), 1);
    let r = cert_store.get_encoded_certificates_for_name(&n2);
    assert!(r.is_err());
    assert_eq!(r.err(), Some(Error::NotFound));

    let v = cert_store.get_encoded_certificates().unwrap();
    assert_eq!(399, v.len());
}

//! Reading DoD InstallRoot streams as trust anchor and CA material.
//!
//! DoD PKE publishes trust material as `.ir4` files at `crl.gds.disa.mil/pke/config`. One is a bare
//! RFC 4073 `ContentCollection` — a `SEQUENCE OF ContentInfo` — holding four separately signed CMS
//! messages, three for WCF. Each message's payload is an RFC 5934 `TAMPUpdate`, and what a message
//! is *for* comes from the label at the end of its target URI (`<url>;<stream>;<kind>`) rather than
//! from anything structural: `Root`, `CA`, `Untrusted` and `RemoveCertificateHintList` entries are
//! all the same `add` entries underneath.
//!
//! So one file legitimately contributes to both sides of a run — the anchors a path terminates at
//! and the intermediates it is built through — and the routing is by message kind. That is why this
//! returns the two sets separately rather than a single pile for the caller to sort: nothing about
//! which input row a user dropped the file into can decide the question, and asking them to know
//! which half a stream holds would be asking them to know the profile.
//!
//! **A stream is read as a store, not as an update to apply, so only the additions matter.** TAMP
//! describes changing a trust store held over time; a run assembles its inputs once. The `remove`
//! and `change` entries and the withdrawn path-building hints have no store here to act on.
//!
//! **The signatures are not checked here.** Each message is signed, and by DoD's model any
//! code-signing certificate chaining to a DoD root may sign one, so verifying is ordinary path
//! validation rather than anything TAMP-specific — but it needs anchors, which is precisely what a
//! run reading its anchors *from this file* does not yet have. Until that is built the material is
//! unverified, and a caller is expected to say so rather than let a signed distribution pass for a
//! bag of certificates by omission.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use der::{Decode, Encode};
use log::info;
use x509_cert::anchor::TrustAnchorChoice;

use rfc5934::dod::{StreamKind, StreamTarget};
use rfc5934::message::TampMessage;
use rfc5934::signed::SignedData;
use rfc5934::{ContentCollection, TampUpdate, TrustAnchorUpdate};

use certval::util::pdv_utilities::is_self_signed;
use certval::{parse_cert, CertFile, PkiEnvironment};

/// What one InstallRoot stream contributed, kept apart by the kind of message each came from.
#[derive(Clone, Default)]
pub struct InstallRootInputs {
    /// Stream names read from the target URIs, in the order the messages appear — `DoD`, `ECA`,
    /// `JITC`, `WCF`. Normally one name repeated, since a file is one stream's four messages.
    pub streams: Vec<String>,

    /// Anchors from the `Root` message, each the `TrustAnchorChoice` as published rather than the
    /// certificate extracted from it. The choice is what the update carries, and carrying it whole
    /// keeps the `TrustAnchorInfo` constraints beside the key they constrain.
    pub anchors: Vec<CertFile>,

    /// Intermediates from the `CA` message, as bare certificates: these are path-building material
    /// and go into a certificate source, which holds certificates.
    pub cas: Vec<CertFile>,

    /// Certificates the `Untrusted` message names.
    pub untrusted: Vec<CertFile>,

    /// How many messages the collection held, whether or not this recognized their kind.
    pub messages: usize,

    /// How many entries of the `CA` message were self-signed and left out of [`cas`](Self::cas).
    /// A folder of certificates is screened the same way: path-building material is what sits
    /// between an anchor and a target, and a self-signed certificate admitted there is an anchor
    /// being offered as an intermediate.
    pub self_signed_cas: usize,
}

impl InstallRootInputs {
    /// True when nothing was found to contribute, whatever the file turned out to say.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty() && self.cas.is_empty() && self.untrusted.is_empty()
    }

    /// The stream this file belongs to, when every message agreed on one.
    ///
    /// `None` for an empty collection and for the case no published file exhibits — several streams
    /// in one collection — because a single name would then be a claim about the file that is not
    /// true of all of it.
    pub fn stream(&self) -> Option<&str> {
        let first = self.streams.first()?;
        self.streams
            .iter()
            .all(|s| s == first)
            .then_some(first.as_str())
    }
}

/// Reads `bytes` as an InstallRoot stream, or `None` when they are not one.
///
/// `None` covers both "this is some other kind of file" and "this is a content collection holding
/// something that is not a TAMP update", which are the same thing to a caller deciding whether this
/// input was InstallRoot material. A stream whose messages decode but carry no anchors is a
/// successful read of a file with nothing in it, and returns `Some` with empty sets.
///
/// `name` labels what the certificates came from, and is the file name where there is one. A
/// browser has the bytes without a path, which is why this takes them rather than reading them.
pub fn installroot_from_bytes(
    pe: &PkiEnvironment,
    name: &str,
    bytes: &[u8],
) -> Option<InstallRootInputs> {
    let path = name;
    let collection = ContentCollection::from_der(bytes).ok()?;

    let mut inputs = InstallRootInputs::default();
    for content_info in collection.0.iter() {
        // Anything that is not a signed TAMP update is skipped rather than failing the file: RFC
        // 4073 collections are open-ended by design, and a member this does not understand is not
        // evidence that the members it does understand are wrong.
        let Ok(signed_data) = content_info.content.decode_as::<SignedData>() else {
            continue;
        };
        let Ok(TampMessage::Update(update)) =
            TampMessage::from_encapsulated(&signed_data.encap_content_info)
        else {
            continue;
        };
        inputs.messages += 1;
        collect_update(pe, path, &update, &mut inputs);
    }

    if 0 == inputs.messages {
        return None;
    }
    Some(inputs)
}

/// Reads the file at `path` as an InstallRoot stream, or `None` when it is not one. The file half
/// of [`installroot_from_bytes`], which is where the documentation is.
#[cfg(feature = "std")]
pub fn read_installroot(pe: &PkiEnvironment, path: &str) -> Option<InstallRootInputs> {
    let bytes = certval::get_file_as_byte_vec_pem(std::path::Path::new(path)).ok()?;
    installroot_from_bytes(pe, path, &bytes)
}

/// Sorts one message's entries into the set its label says they belong to.
fn collect_update(
    pe: &PkiEnvironment,
    path: &str,
    update: &TampUpdate,
    inputs: &mut InstallRootInputs,
) {
    let target = StreamTarget::parse(&update.msg_ref.target);
    let (stream, kind) = match &target {
        Some(t) => (t.stream, t.kind),
        // A target this profile does not describe leaves nothing to route by.
        None => return,
    };
    inputs.streams.push(stream.to_string());

    for (i, entry) in update.updates.iter().enumerate() {
        let choice = match entry {
            TrustAnchorUpdate::Add(choice) => choice,
            // A removal names a key to stop trusting and a change edits an anchor already
            // installed; both describe a store rather than contributing to one.
            TrustAnchorUpdate::Remove(_) | TrustAnchorUpdate::Change(_) => continue,
        };

        let name = format!("{path}#{stream};{};{i}", kind.label());
        match kind {
            StreamKind::Root => {
                if let Ok(bytes) = choice.to_der() {
                    inputs.anchors.push(CertFile {
                        filename: name,
                        bytes,
                    });
                }
            }
            StreamKind::Ca => {
                if let Some(bytes) = certificate_der(choice) {
                    let self_signed = parse_cert(bytes.as_slice(), &name)
                        .map(|cert| is_self_signed(pe, &cert))
                        .unwrap_or(false);
                    if self_signed {
                        info!("Ignoring a self-signed object in the CA message of {path}");
                        inputs.self_signed_cas += 1;
                    } else {
                        inputs.cas.push(CertFile {
                            filename: name,
                            bytes,
                        });
                    }
                }
            }
            StreamKind::Untrusted => {
                if let Some(bytes) = certificate_der(choice) {
                    inputs.untrusted.push(CertFile {
                        filename: name,
                        bytes,
                    });
                }
            }
            StreamKind::RemoveCertificateHintList => {}
            StreamKind::Other(_) => {}
        }
    }
}

/// The bare certificate an `add` entry carries, for the sets that hold certificates.
///
/// An anchor may be expressed three ways and only two of them have a certificate to give: a
/// `TrustAnchorInfo` carries one optionally, under path controls, and the `Certificate` arm is one.
/// The `TbsCertificate` arm is a key and a name without the signature that would make it a
/// certificate, so there is nothing here to hand to a certificate source.
fn certificate_der(choice: &TrustAnchorChoice) -> Option<Vec<u8>> {
    match choice {
        TrustAnchorChoice::Certificate(cert) => cert.to_der().ok(),
        TrustAnchorChoice::TaInfo(info) => info
            .cert_path
            .as_ref()
            .and_then(|controls| controls.certificate.as_ref())
            .and_then(|cert| cert.to_der().ok()),
        TrustAnchorChoice::TbsCertificate(_) => None,
    }
}

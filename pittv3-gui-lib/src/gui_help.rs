//! In-app help shared by GUI frontends.
//!
//! Deliberately short. This used to carry a user guide — what PITTv3 is, how to assemble trust
//! material, what each control means — which is now the PITTv3 User's Guide, and prose maintained
//! in two places drifts in one of them. What stays here is what someone needs *while looking at the
//! window*: where the manual is, and the few behaviours that are properties of this application
//! rather than of certification path validation.
//!
//! Authored as components rather than rendered markdown so the content ships inside the binary with
//! no extra dependencies and inherits the application stylesheet in every frontend.

use dioxus::prelude::*;

/// Help for a PITTv3 GUI frontend: where the manual is, and whatever the frontend adds.
#[component]
pub fn HelpView(
    /// Base URL of the published manual, with a trailing slash.
    ///
    /// Supplied by the frontend because the two reach it differently: the browser application is
    /// served alongside the manual, so a relative URL keeps the link same-origin and adds no second
    /// host to a page whose point is that nothing leaves it. The desktop has no origin to be
    /// relative to and needs an absolute one.
    manual_url: String,
    /// Notes belonging to this frontend, rendered under a heading of their own.
    ///
    /// The shared part is the same everywhere; what differs is what each application can do, and
    /// hiding that difference behind one set of words would make the help wrong in one of them.
    #[props(default)]
    notes: Option<Element>,
) -> Element {
    let manual = manual_url.clone();
    let pdf = format!("{manual_url}pittv3-book.pdf");
    rsx! {
        div { class: "help-view",
            h2 { "PITTv3" }
            p {
                "Builds and validates X.509 certification paths per RFC 5280, as augmented by "
                "RFC 5937, against configurable sets of trust anchors and intermediate CA "
                "certificates, with optional revocation status determination via CRLs and OCSP."
            }

            h2 { "The manual" }
            p {
                "The "
                a { href: "{manual}", target: "_blank", "PITTv3 User's Guide" }
                " explains trust stores and partial paths, and covers each interface in turn. "
                "It is also available as a "
                a { href: "{pdf}", target: "_blank", "PDF" }
                " for use away from a network."
            }

            if let Some(notes) = notes {
                h2 { "Notes" }
                {notes}
            }

            h2 { "Source" }
            p {
                "PITTv3 is open source, including the "
                code { "certval" }
                " path validation library it is built on: "
                a {
                    href: "https://github.com/carl-wallace/rust-pki",
                    target: "_blank",
                    "rust-pki"
                }
                "."
            }
        }
    }
}

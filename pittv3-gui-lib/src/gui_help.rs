//! In-app help and FAQ content shared by GUI frontends.
//!
//! Authored as components (rather than rendered markdown) so the content ships inside the binary
//! with no extra dependencies and inherits the application stylesheet in every frontend.

use dioxus::prelude::*;

/// User guide and FAQ for PITTv3 GUI frontends
#[component]
pub fn HelpView() -> Element {
    rsx! {
        div { class: "help-view",
            h2 { "What is PITTv3?" }
            p {
                "The PKI Interoperability Test Tool v3 (PITTv3) builds and validates X.509 "
                "certification paths per RFC 5280 using configurable sets of trust anchors, "
                "intermediate CA certificates and end entity certificates, with optional "
                "revocation status determination via CRLs and OCSP."
            }

            h2 { "Quick start: validating a certificate" }
            ul {
                li {
                    "Pick a trust anchor / CA store. The built-in stores come from the certval "
                    "trust store "
                    "providers and supply trust anchors, and for most environments the "
                    "intermediate CA certificates as well, so nothing else need be assembled. "
                    "Choose the custom entry to supply your own instead."
                }
                li {
                    "Add trust anchors to the Trust Anchors list. Each entry may be a folder, a "
                    "certificate, a PEM or PKCS#7 bundle, or a CBOR trust anchor store — what an "
                    "entry is comes from the path and then from its contents, so they need not be "
                    "sorted by kind. Everything listed is combined, and an anchor named twice is "
                    "carried once."
                }
                li {
                    "Add intermediate CA certificates the same way, or leave the list empty and "
                    "enable Dynamic Build to fetch them via AIA/SIA. A built-in store that carries "
                    "intermediates supplies these itself, and anything listed is added to them."
                }
                li {
                    "Add the certificates to validate to the End Entity Certificates list, as "
                    "files or as folders to traverse. To judge what a server is actually serving, "
                    "name it under From a TLS Server instead: the handshake's certificate joins "
                    "that list, anything sent with it joins the CA list, and a stapled OCSP "
                    "response joins the revocation artifacts."
                }
                li {
                    "Run. Results appear in the Results view, one expandable entry per certificate "
                    "validated, showing its status and the paths considered for it."
                }
            }

            h2 { "Reading results" }
            ul {
                li {
                    strong { "Valid" }
                    " — at least one certification path validated successfully."
                }
                li {
                    strong { "Valid (revocation undetermined)" }
                    " — a path passed every RFC 5280 check but revocation status could not be "
                    "determined for at least one certificate (for example, no CRL or OCSP "
                    "responder was reachable)."
                }
                li {
                    strong { "Revoked" }
                    " — the target certificate was determined to be revoked."
                }
                li {
                    strong { "Invalid" }
                    " — paths were found but none validated; the failing certificate is "
                    "highlighted in the path detail along with at least one reason."
                }
                li {
                    strong { "No paths found" }
                    " — the builder could not connect the target to any trust anchor. The result "
                    "lists what was missing: whether any trust anchor was loaded, whether any "
                    "loaded certificate has the target's issuer name, and whether the target is "
                    "within its validity period at the time of interest."
                }
            }

            h2 { "Generating a CBOR store" }
            p {
                "The Generate action builds a CBOR file containing intermediate CA certificates "
                "and partial certification paths from a TA folder and CA folder. Pair it with "
                "Chase SIA and AIA to harvest additional intermediates from the network. The "
                "resulting file speeds up later validation runs and can be reused across "
                "frontends (desktop, web, WASM)."
            }

            h2 { "Settings" }
            p {
                "Validation behavior beyond the common options is governed by a JSON settings "
                "file (the CLI's --settings input). The settings editor groups values into "
                "tabs; fields marked \"default\" are absent from the file and use certval "
                "defaults, so a minimal file only pins what you changed. The Revocation tab "
                "offers a composed mode selection (None / CRL or OCSP / CRL only / OCSP only); "
                "the individual toggles remain available under Advanced, and unusual "
                "combinations display as Custom."
            }

            h2 { "Revocation checking" }
            ul {
                li {
                    "Revocation checking is on by default: without CRLs or reachable OCSP "
                    "responders, otherwise-valid paths report as Valid (revocation undetermined)."
                }
                li {
                    "Add CRLs and OCSP responses you already hold to the CRLs and OCSP Responses "
                    "list. They are read and left alone, and what each artifact is comes from its "
                    "contents rather than its name. A response is matched to the certificate it "
                    "answers about, so it does not matter which one you added it for."
                }
                li {
                    "CRL Folder is a different thing: an index, written as well as read, from "
                    "which CRLs not valid at the time of interest are deleted. Point it at a "
                    "working folder, never at material you want to keep."
                }
                li {
                    "Otherwise let dynamic builds fetch CRLs from distribution points; OCSP "
                    "responders are taken from AIA extensions."
                }
                li {
                    "The OCSP nonce setting controls whether requests carry a nonce and whether "
                    "responses must echo it."
                }
            }

            h2 { "FAQ" }
            p { strong { "Why did my run report no paths found?" } }
            p {
                "Expand that certificate's entry in the Results view: the reasons are listed "
                "there, beneath its status. The most common causes: the "
                "trust anchor folder does not contain the root that issued the chain, the CBOR "
                "store and CA folder lack the needed intermediates (add them or enable Dynamic "
                "Build), or the certificates are not valid at the selected time of interest. A CA "
                "folder needs no store: its certificates are read into the graph at validation "
                "time, alongside those of a CBOR store when one is also supplied."
            }
            p { strong { "What does the time of interest do?" } }
            p {
                "All validity period checks are evaluated at the time of interest rather than "
                "the current time; a value of 0 disables validity checking entirely."
            }
            p { strong { "Why is a revoked certificate reported as undetermined?" } }
            p {
                "A revoked verdict requires a signed statement (CRL or OCSP response) covering "
                "the certificate; if none can be obtained the status is undetermined, not "
                "revoked. Check that a current CRL for the issuing CA is available."
            }
            p { strong { "Where do results files go?" } }
            p {
                "When a Results Folder is specified, artifacts from each processed path are "
                "written beneath it (grouped by a hash of the target). The in-app Results view "
                "does not require a results folder."
            }
            p { strong { "Does the log output still exist?" } }
            p {
                "Yes: runs stream their log output to the Results view, and a log4rs "
                "configuration file can direct full logging to files or the console as before."
            }
        }
    }
}

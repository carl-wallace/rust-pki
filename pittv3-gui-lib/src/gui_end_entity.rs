//! The end entity group: the certificates a run will judge, however they were obtained.
//!
//! Shared because the two frontends had drifted into three presentations of one idea. The desktop
//! showed a certificates row and a host row together; the browser put them behind a radio, so
//! choosing "TLS server" *hid* the file input — and loading a file and taking a host's chain are not
//! alternatives. Someone comparing what a server serves against a copy they were sent wants both.
//! The prose explaining the handshake had been written twice and had already begun to differ.
//!
//! **What is shared is the TLS-server half**, which is the half that had drifted. The certificates
//! row is injected whole, because the difference there is irreducible rather than cosmetic: the
//! desktop's entries are filesystem paths and may name folders, the browser's are byte buffers from
//! an `<input type="file">`. Same division as [`BrowseRow`](crate::gui_rows::BrowseRow), which takes
//! a browse callback because choosing a file is the one part of a row that is not portable.

use dioxus::prelude::*;

/// Why the peek button is disabled, or `None` when it is not.
///
/// Distinct from the status line, and the distinction is worth keeping: this is answered *before*
/// anything is attempted, so it names a condition the user can fix in the form — an empty host, a
/// handshake already running, a privacy tier that does no retrieving. A refusal that happens once a
/// request is made — a policy that declines the host, a handshake that fails — is an outcome and
/// belongs in the status instead.
pub type BlockedBecause = Option<String>;

/// Builds the sentence describing what taking a host's certificates does.
///
/// `actor` is the subject, because that genuinely differs and is not cosmetic: in the browser a
/// service makes the connection, which means the host and the fact that it was asked about leave the
/// machine, while a desktop opens the socket itself. Everything after that clause is identical, so
/// it is written here once.
pub fn peek_explanation(actor: &str) -> String {
    format!(
        "{actor} completes a handshake and keeps what the host sent: its own certificate joins the \
         end entity list, anything sent with it joins the CA certificates path building draws on, \
         and a stapled OCSP response is kept as revocation data. Nothing is requested over the \
         connection. Making the handshake does not judge the certificate \u{2014} that is what \
         Validate is for."
    )
}

/// The end entity certificates a run will validate, and the ways of obtaining them.
///
/// The explanation is the label's tooltip rather than a paragraph on the page: it describes a
/// control the reader has already decided to use by the time it matters, and inline it stood
/// between two fields that belong together.
#[component]
pub fn EndEntityGroup(
    /// The frontend's own complete certificates row, emitting `.label-cell` and `.field` children
    /// into the surrounding grid.
    certificates_row: Element,
    peek_host: Signal<String>,
    on_peek: EventHandler<()>,
    /// Subject of the sentence describing the handshake, e.g. "The service" or "This app".
    peek_actor: String,
    #[props(default)] peek_blocked_because: BlockedBecause,
    #[props(default)] peek_status: String,
) -> Element {
    let blocked = peek_blocked_because.clone();
    rsx! {
        fieldset {
            legend { "End Entity Certificate" }
            div { class: "controls",
                {certificates_row}

                div {
                    title: peek_explanation(&peek_actor),
                    class: "visible label-cell",
                    label { r#for: "peek-host", "From a TLS server: " }
                }
                div { class: "field",
                    input {
                        id: "peek-host",
                        r#type: "text",
                        placeholder: "example.com or example.com:8443",
                        value: "{peek_host}",
                        oninput: move |ev| peek_host.set(ev.value()),
                    }
                    button {
                        r#type: "button",
                        disabled: blocked.is_some(),
                        onclick: move |_| on_peek.call(()),
                        "Get certificates"
                    }
                }

                // Why it will not act, then what happened when it did. A reader who has been stopped
                // needs the first; a reader who has just run it needs the second. Both are short
                // enough to sit inline, unlike the explanation above.
                if let Some(reason) = peek_blocked_because {
                    div { class: "field", span { class: "hint", "{reason}" } }
                }
                if !peek_status.is_empty() {
                    div { class: "field", span { class: "hint", "{peek_status}" } }
                }
            }
        }
    }
}

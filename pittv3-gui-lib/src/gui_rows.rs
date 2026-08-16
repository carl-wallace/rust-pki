//! Labeled input rows shared by the GUI frontends.
//!
//! These are the building blocks of the argument-shaped forms (Validate, Generate, Diagnostics on
//! the desktop) as distinct from the override-aware settings form in
//! [`gui_settings`](crate::gui_settings), whose rows carry `Option` values and a default/override
//! hint. Both kinds exist on purpose; a row here binds a [`Signal`] directly because the value it
//! edits always has one.
//!
//! Everything here is renderer-agnostic and free of filesystem access, so it compiles for wasm32 as
//! well as the host. Choosing a file or folder is the one part that is not portable, so
//! [`BrowseRow`] takes the browse action as a callback and each frontend supplies its own — a
//! native dialog on the desktop, and nothing (or an upload control) in the browser.

use dioxus::prelude::*;

use pittv3_lib::help::arg_help;

/// The tooltip for a row: an explicit `title` when the frontend supplies one, otherwise the help
/// text for the argument the row's `name` identifies. Defaulting this way means a control is
/// described in the same words as the CLI flag that sets it, without every call site repeating the
/// description, and a row whose name is not an argument simply gets no tooltip.
fn tooltip(title: String, name: &str) -> String {
    if title.is_empty() {
        arg_help(name).to_string()
    } else {
        title
    }
}

/// Current time in Unix-epoch seconds. Uses `web_time` so the same call works in the browser and on
/// the host.
pub fn now_as_unix_epoch() -> u64 {
    match web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => 0,
    }
}

/// Formats Unix-epoch seconds as a `datetime-local` value (`YYYY-MM-DDTHH:MM:SS`) in UTC.
///
/// Built on `der::DateTime` rather than a platform clock API so the same rendering serves the
/// desktop and the browser; the browser previously showed local time here and the desktop UTC,
/// which made the same stored setting read differently in the two frontends.
pub fn epoch_to_datetime_local(secs: u64) -> String {
    match x509_cert::der::DateTime::from_unix_duration(core::time::Duration::from_secs(secs)) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minutes(),
            dt.seconds()
        ),
        Err(_) => String::new(),
    }
}

/// Parses a `datetime-local` value (`YYYY-MM-DDTHH:MM` or `...:SS`, interpreted as UTC) back to
/// Unix-epoch seconds; inverse of [`epoch_to_datetime_local`].
pub fn datetime_local_to_epoch(value: &str) -> Option<u64> {
    let v = value.trim();
    let rfc3339 = match v.len() {
        16 => format!("{v}:00Z"), // picker omitted the seconds component
        19 => format!("{v}Z"),
        _ => return None,
    };
    rfc3339
        .parse::<x509_cert::der::DateTime>()
        .ok()
        .map(|dt| dt.unix_duration().as_secs())
}

/// The `datetime-local` value mirroring a time-of-interest epoch string, so a picker shows the
/// selected time; empty when the time is disabled (0) or mid-edit (not yet a valid epoch).
pub fn toi_datetime_value(toi: &str) -> String {
    match toi.trim().parse::<u64>() {
        Ok(secs) if secs != 0 => epoch_to_datetime_local(secs),
        _ => String::new(),
    }
}

/// Table row with a labeled text input and no accompanying selection dialog.
///
/// `title` overrides the label's tooltip; left empty it falls back to the argument help for `name`.
#[component]
pub fn TextRow(
    label: String,
    name: String,
    sig: Signal<String>,
    #[props(default)] title: String,
) -> Element {
    let title = tooltip(title, &name);
    rsx! {
        tr {
            td {
                div { title, class: "visible",
                    label { r#for: name.clone(), "{label}: " }
                }
            }
            td { class: "grow",
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
        }
    }
}

/// Table row with a labeled text input and a browse button. The browse action is supplied by the
/// frontend, since choosing a file or folder is the one part of this row that is not portable.
///
/// An input that accepts either a file or a folder can supply a second action as `on_browse_alt`,
/// rendered as an extra button labeled `alt_label`. That is for the frontends whose native dialog
/// chooses one kind or the other: where a single dialog can offer both, the row keeps one button
/// and the platform difference stays inside the frontend.
#[component]
pub fn BrowseRow(
    label: String,
    name: String,
    sig: Signal<String>,
    on_browse: EventHandler<()>,
    #[props(default)] title: String,
    #[props(default)] on_browse_alt: Option<EventHandler<()>>,
    #[props(default)] alt_label: String,
) -> Element {
    let title = tooltip(title, &name);
    rsx! {
        tr {
            td {
                div { title, class: "visible",
                    label { r#for: name.clone(), "{label}: " }
                }
            }
            td { class: "grow",
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
            td { class: "nowrap",
                button {
                    r#type: "button",
                    onclick: move |_| on_browse.call(()),
                    "..."
                }
                if let Some(on_browse_alt) = on_browse_alt {
                    button {
                        r#type: "button",
                        onclick: move |_| on_browse_alt.call(()),
                        "{alt_label}"
                    }
                }
            }
        }
    }
}

/// Table row for a time of interest held as an epoch string: the epoch field, a Now button, and a
/// human-readable picker mirroring it in UTC.
#[component]
pub fn TimeRow(
    label: String,
    name: String,
    sig: Signal<String>,
    #[props(default)] title: String,
) -> Element {
    let title = tooltip(title, &name);
    rsx! {
        tr {
            td {
                div { title, class: "visible",
                    label { r#for: name.clone(), "{label}: " }
                }
            }
            td { class: "grow",
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
            td { class: "nowrap",
                button {
                    r#type: "button",
                    onclick: move |_| sig.set(now_as_unix_epoch().to_string()),
                    "Now"
                }
                // Editable human-readable picker mirroring the epoch field (UTC). onchange fires
                // only on a complete datetime, so it never clobbers a mid-edit epoch value.
                input {
                    r#type: "datetime-local",
                    step: "1",
                    value: toi_datetime_value(&sig()),
                    onchange: move |ev| {
                        if let Some(secs) = datetime_local_to_epoch(&ev.value()) {
                            sig.set(secs.to_string());
                        }
                    },
                }
            }
        }
    }
}

/// Labeled checkbox cell for use within a table row
#[component]
pub fn CheckboxCell(
    label: String,
    name: String,
    sig: Signal<bool>,
    #[props(default)] title: String,
) -> Element {
    let title = tooltip(title, &name);
    rsx! {
        td { class: "check",
            div { title, class: "visible",
                label { r#for: name.clone(), "{label}: " }
                input {
                    r#type: "checkbox",
                    name,
                    checked: sig(),
                    onchange: move |ev| sig.set(ev.checked()),
                }
            }
        }
    }
}

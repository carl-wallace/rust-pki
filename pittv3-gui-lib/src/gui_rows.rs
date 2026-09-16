//! Labeled input rows shared by the GUI frontends.
//!
//! A row emits two grid children -- a label cell and a field cell -- for a `.controls` grid to
//! place, plus an optional hint on its own line. It emits no container of its own, so a caller
//! composes rows into a group and decides how that group is framed.
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

/// Row with a labeled text input and no accompanying selection dialog.
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
        div { title, class: "visible label-cell",
            label { r#for: name.clone(), "{label}: " }
        }
        div { class: "field",
            input {
                r#type: "text",
                name,
                value: "{sig}",
                oninput: move |ev| sig.set(ev.value()),
            }
        }
    }
}

/// Row with a labeled text input and a browse button. The browse action is supplied by the
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
    /// Label for the browse button. Defaults to an ellipsis, which is the right thing to say when
    /// it is the only button on the row: the dialog it opens takes whatever the row accepts. A row
    /// carrying `on_browse_alt` should name both buttons instead, since beside one that names a
    /// kind an ellipsis reads as "more options" rather than as the other kind.
    #[props(default)]
    primary_label: String,
) -> Element {
    let primary_label = match primary_label.is_empty() {
        true => "\u{2026}".to_string(),
        false => primary_label,
    };
    let title = tooltip(title, &name);
    rsx! {
        div { title, class: "visible label-cell",
            label { r#for: name.clone(), "{label}: " }
        }
        div { class: "field",
            input {
                r#type: "text",
                name,
                value: "{sig}",
                oninput: move |ev| sig.set(ev.value()),
            }
            button {
                r#type: "button",
                onclick: move |_| on_browse.call(()),
                "{primary_label}"
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

/// Row for a time of interest held as an epoch string: the epoch field, a Now button, and a
/// human-readable picker mirroring it in UTC.
#[component]
pub fn TimeRow(
    label: String,
    name: String,
    sig: Signal<String>,
    #[props(default)] title: String,
) -> Element {
    let title = tooltip(title, &name);
    // The picker's own text while it is being edited, rather than a value derived from the epoch on
    // every render. Typing a datetime passes through states the epoch box must not be given -- an
    // incomplete one, and a complete one that is not meant, like the year 0202 on the way to 2026 --
    // and a `value` bound straight to the epoch would also be re-imposed by any re-render the rest
    // of the view triggers, wiping an edit in progress. Reseeded from the epoch whenever that
    // changes from elsewhere: the Now button, or the settings file being read again.
    let mut draft = use_signal(|| toi_datetime_value(&sig()));
    use_effect(move || draft.set(toi_datetime_value(&sig())));
    rsx! {
        div { title, class: "visible label-cell",
            label { r#for: name.clone(), "{label}: " }
        }
        div { class: "field",
            input {
                r#type: "text",
                name,
                value: "{sig}",
                // Empty is not "unset", it is *now* -- resolved when the run starts rather than
                // when this was typed. Saying so in the box is the only place a reader looks.
                placeholder: "run time",
                title: "Unix epoch seconds. Leave it blank to judge against now or 0 to disable validity checks, resolved when the run starts.",
                oninput: move |ev| sig.set(ev.value()),
            }
            // Clears rather than stamping the current epoch. A button labelled Now that writes the
            // instant it was pressed leaves a time that was current once and silently is not any
            // more, and nothing on screen distinguishes it from a time chosen deliberately -- which
            // is how a run comes to be judged against whenever the button was last touched. Pinning
            // an instant is what the picker beside this is for, and it should be deliberate.
            button {
                r#type: "button",
                title: "Clears the box, which is how now is represented: the time is resolved when the run starts rather than being fixed to this moment.",
                onclick: move |_| sig.set(String::new()),
                "Now"
            }
            // Editable human-readable picker mirroring the epoch field (UTC).
            input {
                r#type: "datetime-local",
                // Seconds only once there is a committed time to refine. A `datetime-local` yields
                // no value at all until every field it shows is filled, so a seconds field on an
                // empty picker means date and time can both be set and nothing is committed -- the
                // control stays blank and so does the epoch box.
                //
                // Keyed on the epoch rather than on the draft, which is the whole of it: a draft
                // grows non-empty the instant the first complete value is typed, so keying on it
                // would add the seconds field mid-edit, leave it blank, and invalidate the value
                // that had just been entered. The control could never settle. The epoch only
                // changes once a value has actually been committed, by which point the draft has
                // been normalised to a full timestamp and the seconds field has something to show.
                step: if sig().trim().is_empty() { "60" } else { "1" },
                // The label's tooltip does not reach in here, and this is the one control whose
                // behaviour is worth a word: it is the element's own, not something the row chose.
                title: "Fully specify the time or use the date picker.",
                value: "{draft}",
                // Every event this control might deliver commits, because which of them it does
                // deliver varies: the picker widget settles the value at once and fires `change`,
                // while editing the fields by hand may only ever produce `input`. Committing from
                // whichever arrives means the epoch box fills as the value becomes complete rather
                // than waiting for a blur that a user with no reason to click away never gives it.
                //
                // `draft` holds what the control shows so that a re-render elsewhere in the view
                // does not re-impose a normalised value over an edit in progress, and an
                // incomplete value simply does not parse, so nothing is committed from one.
                oninput: move |ev| {
                    draft.set(ev.value());
                    if let Some(secs) = datetime_local_to_epoch(&ev.value()) {
                        sig.set(secs.to_string());
                    }
                },
                onchange: move |ev| {
                    draft.set(ev.value());
                    if let Some(secs) = datetime_local_to_epoch(&ev.value()) {
                        sig.set(secs.to_string());
                    }
                },
                onblur: move |_| {
                    if let Some(secs) = datetime_local_to_epoch(&draft()) {
                        sig.set(secs.to_string());
                    }
                },
            }
        }
    }
}

/// Labeled checkbox: the box and the text it belongs to, as one field-column item.
///
/// Emits no label column of its own, so several of these sit together on one row under a shared
/// label -- a checkbox states its own name, and giving each one a label column would spread a pair
/// of related switches across the width of the form.
#[component]
pub fn CheckboxCell(
    label: String,
    name: String,
    sig: Signal<bool>,
    #[props(default)] title: String,
    /// Whether the control is settable, as on [`CheckboxRow`] and with one difference worth
    /// stating: a cell is disabled here when another setting makes it *irrelevant* rather than
    /// when one dictates its value, so the signal is left alone. The value the user last chose
    /// stays visible and comes back when the control does, and the run ignores it meanwhile.
    #[props(default)]
    disabled: bool,
) -> Element {
    let title = tooltip(title, &name);
    rsx! {
        div { title, class: "visible",
            label { r#for: name.clone(), "{label}: " }
            input {
                r#type: "checkbox",
                name,
                checked: sig(),
                disabled,
                onchange: move |ev| sig.set(ev.checked()),
            }
        }
    }
}

/// Grid row pairing a checkbox with the sentence explaining what it changes.
///
/// Emits a `.label-cell` and a `.field` into the surrounding `.controls` grid rather than a
/// self-contained row, which is what lets several of them share one grid and so one label-column
/// width: a checkbox per grid lands at a different x in every row, because `max-content` is
/// measured per grid.
///
/// [`CheckboxCell`] remains for the case it was built for — several checkboxes side by side in one
/// field, where the labels are meant to sit next to their boxes rather than in a column.
#[component]
pub fn CheckboxRow(
    label: String,
    name: String,
    sig: Signal<bool>,
    /// What the checkbox changes. Carried as the label's tooltip rather than shown beside it: a
    /// sentence per checkbox is a paragraph of standing text explaining controls the reader has
    /// mostly already understood, and it pushes the run button off the view. Falls back to the
    /// argument help for `name`, so a control named after a flag is described in the flag's words.
    #[props(default)]
    title: String,
    /// Whether the control is settable. A checkbox whose value is dictated by another setting is
    /// shown disabled rather than hidden, so the state it is being held at stays visible: hiding it
    /// would leave the run behaving in a way nothing on screen accounts for. The caller is
    /// responsible for holding the signal at the value it displays.
    #[props(default)]
    disabled: bool,
) -> Element {
    let title = tooltip(title, &name);
    rsx! {
        div { title, class: "visible label-cell",
            label { r#for: name.clone(), "{label}: " }
        }
        div { class: "field",
            input {
                r#type: "checkbox",
                name,
                checked: sig(),
                disabled,
                onchange: move |ev| sig.set(ev.checked()),
            }
        }
    }
}

/// Row holding a *pool* of inputs rather than one: any number of paths, each a file or a
/// folder, added and removed one at a time.
///
/// This is the row a frontend uses where the arguments take a `Vec<String>` — trust anchors, CA
/// certificates, targets, revocation artifacts. The single-path [`BrowseRow`] remains for the
/// arguments that name one thing, which after the pools were added are the ones naming an *output*:
/// the store a generate run writes, the folder the Mozilla CSV tool fills.
///
/// What the pool holds is reported as a count, not as a row per entry, which is how the browser
/// frontend reports an upload and what keeps a pool of any size to one line. The paths are the
/// count's tooltip, so they remain available without being on the page. A pool is emptied whole;
/// there is deliberately no per-entry control, since a row of them for every path is the clutter
/// this replaced. Everything arrives through `on_add`, which supplies however many paths a
/// frontend's picker returned; a native multi-select adds several at once, and a frontend with no
/// picker at all can leave the button off by passing `None`.
///
/// What the pool *contributes* is what the count reports, where a frontend can work it out: a
/// `.p7c` of cross-certificates is six certificates and not one file, and a folder is however many
/// certificates are in it, so the number of entries is rarely the number a run will have. A
/// frontend passes that as `contents`; the entry count stands in until it does, and where no
/// frontend can say. The figure describes the material as it was last read, which for a folder is a
/// moment that has passed -- what each input actually contributed is reported by the run.
#[component]
pub fn PathListRow(
    label: String,
    name: String,
    sig: Signal<Vec<String>>,
    #[props(default)] title: String,
    #[props(default)] on_add: Option<EventHandler<()>>,
    #[props(default)] on_add_alt: Option<EventHandler<()>>,
    #[props(default)] alt_label: String,
    /// Shown under the rows when the pool is empty, to say what belongs here.
    #[props(default)]
    hint: String,
    /// What the entries contribute, worded by the frontend because the noun differs by pool
    /// ("6 trust anchors", "3 CRLs, 1 OCSP response"). Shown in place of the entry count; empty
    /// where the frontend has nothing to say yet.
    #[props(default)]
    contents: String,
) -> Element {
    let title = tooltip(title, &name);
    let entries = sig();
    // What the pool holds, as a count. The paths themselves are the tooltip, so the whole of a
    // pool is available on hover without any of it taking room on the page.
    let entry_count = match entries.len() {
        1 => "1 entry".to_string(),
        n => format!("{n} entries"),
    };
    let loaded = match contents.is_empty() {
        true => entry_count,
        false => contents.clone(),
    };
    let listing = entries.join("\n");
    rsx! {
        div { title, class: "visible label-cell",
            label { r#for: name.clone(), "{label}: " }
        }
        div { class: "field",
            if let Some(on_add) = on_add {
                button {
                    r#type: "button",
                    onclick: move |_| on_add.call(()),
                    "Add\u{2026}"
                }
            }
            if let Some(on_add_alt) = on_add_alt {
                button {
                    r#type: "button",
                    onclick: move |_| on_add_alt.call(()),
                    "{alt_label}"
                }
            }
            if !entries.is_empty() {
                span { class: "pool-count", title: "{listing}", "{loaded}" }
                button {
                    r#type: "button",
                    onclick: move |_| sig.write().clear(),
                    "Clear"
                }
            }
        }
        if entries.is_empty() && !hint.is_empty() {
            span { class: "hint", "{hint}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The picker and the epoch box show one value, so what the picker is handed has to be what it
    /// hands back. Both directions, at a second that exercises every field.
    #[test]
    fn the_picker_value_round_trips_through_an_epoch() {
        // 2022-03-23T12:49:43Z
        let secs = 1_648_039_783;
        let picker = epoch_to_datetime_local(secs);
        assert_eq!(picker, "2022-03-23T12:49:43");
        assert_eq!(datetime_local_to_epoch(&picker), Some(secs));
        assert_eq!(toi_datetime_value(&secs.to_string()), picker);
    }

    /// A picker that omits the seconds field is the ordinary case -- a user who sets the date and
    /// the time and leaves seconds alone -- so it has to parse rather than being read as junk.
    #[test]
    fn a_picker_value_without_seconds_is_accepted() {
        assert_eq!(
            datetime_local_to_epoch("2022-03-23T12:49"),
            Some(1_648_039_740)
        );
    }

    /// Everything a half-filled picker can emit has to be refused, or a mid-edit value would land
    /// in the epoch box as a time nobody chose.
    #[test]
    fn an_incomplete_picker_value_is_refused() {
        for partial in ["", "2022-03-23", "2022-03-23T", "2022-03", "not a time"] {
            assert_eq!(datetime_local_to_epoch(partial), None, "{partial}");
        }
    }

    /// Blank is *run time*, not a moment, so the picker shows nothing rather than claiming one.
    /// Same for a disabled (0) time and for an epoch box being typed into.
    #[test]
    fn the_picker_is_empty_when_no_time_is_in_effect() {
        assert_eq!(toi_datetime_value(""), "");
        assert_eq!(toi_datetime_value("0"), "");
        assert_eq!(toi_datetime_value("16480"), "1970-01-01T04:34:40");
        assert_eq!(toi_datetime_value("abc"), "");
    }
}

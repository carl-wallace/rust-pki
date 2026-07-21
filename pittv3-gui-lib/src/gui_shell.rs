//! Application shell shared by GUI frontends: a left sidebar of task views with a content area.
//!
//! Frontends supply their own view labels and render the selected view as children, so desktop,
//! browser (WASM) and web frontends share one look and feel while keeping frontend-specific
//! behavior (file dialogs, uploads, run orchestration) to themselves.

use dioxus::prelude::*;

/// Left-sidebar navigation over an application's task views. `items` supplies the view labels in
/// display order, `selected` the index of the active view and `busy_item` an optional index to
/// decorate with a busy indicator (e.g., a Results view while a run is in flight). The selected
/// view's content is supplied as children.
#[component]
pub fn AppShell(
    items: Vec<&'static str>,
    selected: usize,
    #[props(default)] busy_item: Option<usize>,
    on_select: EventHandler<usize>,
    children: Element,
) -> Element {
    rsx! {
        div { class: "app-shell",
            nav { class: "sidebar",
                for (i , label) in items.iter().enumerate() {
                    button {
                        class: if selected == i { "nav-active" } else { "" },
                        onclick: move |_| on_select.call(i),
                        if busy_item == Some(i) {
                            "{label} ⏳"
                        } else {
                            "{label}"
                        }
                    }
                }
            }
            div { class: "view", {children} }
        }
    }
}

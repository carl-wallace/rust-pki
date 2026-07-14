# PITTv3 GUI library

This crate provides user interface components shared by GUI frontends to the PKI Interoperability
Test Tool v3 (PITTv3), i.e., desktop applications built using dioxus-desktop and WASM-based
applications. Components are written against the Dioxus signals API and avoid renderer-specific
dependencies; frontends supply renderer-specific behaviors, like closing a window, via callback
props.

The `gui_settings` module provides a form for editing `CertificationPathSettings` values that are
persisted as JSON. The `gui_utils` module provides persistence for `Pittv3Args` values along with
helpers for extracting typed values from Dioxus form events.

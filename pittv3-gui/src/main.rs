#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod gui;
mod logging;
mod peek;
mod save;
mod stores;
mod window_state;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

use crate::gui::App;

/// Window title: the application and the version of this build, from the manifest.
///
/// The version is in the title bar rather than in the form because it is the one fact about the
/// application that is not about the run in front of you, and a title bar is where a person looks
/// to tell two windows -- or two installed copies -- apart. The browser frontend shows a build time
/// beside its version, which this deliberately does not: that stamp exists because a hosted page is
/// replaced in place and the version string alone cannot say whether the page is the deployment
/// just made. An installed binary is not replaced behind the user's back, so the version answers it.
const TITLE: &str = concat!("PITTv3 ", env!("CARGO_PKG_VERSION"));

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_window(
                WindowBuilder::new()
                    .with_resizable(true)
                    .with_title(TITLE)
                    .with_inner_size(LogicalSize::new(820.0, 800.0)),
            ),
        )
        .launch(App)
}

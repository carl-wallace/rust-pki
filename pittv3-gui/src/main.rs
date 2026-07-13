#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod gui;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

use crate::gui::App;

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_window(
                WindowBuilder::new()
                    .with_resizable(true)
                    .with_title("PITTv3")
                    .with_inner_size(LogicalSize::new(820.0, 800.0)),
            ),
        )
        .launch(App)
}

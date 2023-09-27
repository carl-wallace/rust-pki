#![doc = include_str!("../README.md")]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

mod gui;
use pittv3_gui_lib::gui_settings::SettingsProps;
use pittv3_lib::args;

use crate::gui::App;
use dioxus_desktop::Config;
use dioxus_desktop::WindowBuilder;

fn main() {
    dioxus_desktop::launch_with_props(
        App,
        SettingsProps {
            x: "Foo".to_string(),
        },
        Config::new().with_window(
            WindowBuilder::new()
                .with_resizable(true)
                .with_title("PITTv3")
                .with_inner_size(dioxus_desktop::LogicalSize::new(820.0, 800.0)),
        ),
    );
}

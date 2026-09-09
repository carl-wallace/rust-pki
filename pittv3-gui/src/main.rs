#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod gui;
mod logging;
mod peek;
mod save;
mod stores;
mod window_state;

use dioxus::desktop::tao::window::Icon;
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

/// The application icon, decoded from the PNG committed beside this source.
///
/// `Icon::from_rgba` takes **raw pixels**, not an encoded image, which is the trap here: pbyk ships
/// a 262,144-byte file named `keys-arrow-256.ico` that is not an ICO at all, but 256 x 256 x 4 raw
/// bytes. Decoding the PNG instead keeps one readable image in the repository rather than an opaque
/// blob, and costs nothing at build time -- `png` is already in the dependency tree.
///
/// `None` on any failure: an application that will not start because its icon did not decode is a
/// worse outcome than one wearing the toolkit's default.
fn window_icon() -> Option<Icon> {
    let decoder = png::Decoder::new(include_bytes!("../assets/pittv3.png").as_slice());
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    buf.truncate(info.buffer_size());
    Icon::from_rgba(buf, info.width, info.height).ok()
}

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_window(
                WindowBuilder::new()
                    .with_resizable(true)
                    .with_title(TITLE)
                    .with_window_icon(window_icon())
                    .with_inner_size(LogicalSize::new(820.0, 800.0)),
            ),
        )
        .launch(App)
}

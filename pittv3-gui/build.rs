//! Embeds a Windows application manifest that asks for Common Controls v6.
//!
//! rfd's `common-controls-v6` feature imports `TaskDialogIndirect` from comctl32.dll, which only
//! v6 exports. Without a manifest naming v6 the loader binds the v5.82 comctl32.dll instead, and
//! the process fails to start with "Entry Point Not Found". `rustc-link-arg` rather than
//! `rustc-link-arg-bins` because the test executables link the same rfd code.

fn main() {
    let cfg = |key| std::env::var(key).unwrap_or_default();
    if cfg("CARGO_CFG_TARGET_OS") == "windows" && cfg("CARGO_CFG_TARGET_ENV") == "msvc" {
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' \
             name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
             processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
    }
}

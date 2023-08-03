#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)] // removed due to issue with Clap derive, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;
mod args;
mod options_std;
mod pitt_log;
mod stats;
mod std_utils;

mod no_std_utils;
mod options_no_std;
mod options_std_app;

mod gui;

#[cfg(not(feature = "gui"))]
use clap::Parser;

#[cfg(not(feature = "gui"))]
use log::debug;

use crate::args::*;

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(feature = "std")] {
        use options_std::*;
    } else if #[cfg(feature = "std_app")] {
        use options_std_app::*;
    } else if #[cfg(not(feature = "std_app"))] {
        use options_no_std::*;
    }
}

cfg_if! {
    if #[cfg(feature = "gui")] {
        use crate::gui::*;
        use dioxus_desktop::Config;
        use dioxus_desktop::WindowBuilder;
        fn main() {
            dioxus_desktop::launch_cfg(App, Config::new().with_window(WindowBuilder::new().with_resizable(true).with_title("PITTv3")
            .with_inner_size(dioxus_desktop::LogicalSize::new(775.0, 800.0)),),);
        }
    }
    else if #[cfg(feature = "std_app")] {
        use log::LevelFilter;
        use log4rs::append::console::ConsoleAppender;
        use log4rs::config::{Appender, Config, Root};
        use log4rs::encode::pattern::PatternEncoder;

        /// Point of entry for PITTv3 application.
        #[tokio::main]
        async fn main() {
            let args = Pittv3Args::parse();

            let mut logging_configured = false;

            if let Some(logging_config) = &args.logging_config {
                if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
                    println!(
                        "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                        logging_config, e
                    );
                } else {
                    logging_configured = true;
                }
            }

            if !logging_configured {
                // if there's no config, prepare one using stdout
                let stdout = ConsoleAppender::builder()
                    .encoder(Box::new(PatternEncoder::new("{m}{n}")))
                    .build();
                match Config::builder()
                    .appender(Appender::builder().build("stdout", Box::new(stdout)))
                    .build(Root::builder().appender("stdout").build(LevelFilter::Info)) {
                    Ok(config) => {
                            let handle = log4rs::init_config(config);
                            if let Err(e) = handle {
                                println!(
                                    "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                                    e
                                );
                            }
                        }
                    Err(e) => {
                        println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
                    }
                }
            }
            debug!("PITTv3 start");

            // process options available under std, revocation,std and remote features
            #[cfg(feature = "std")]
            options_std(&args).await;

            #[cfg(not(feature = "std"))]
            options_std_app(&args);

            debug!("PITTv3 end");
        }
    }
    else if #[cfg(not(feature = "std_app"))] {
        /// Point of entry for PITTv3 application.
        fn main() {
            let args = Pittv3Args::parse();

            debug!("PITTv3 start");

            // process options available under std, revocation,std and remote features
            #[cfg(feature = "std")]
            options_std(&args).await;

            #[cfg(not(feature = "std"))]
            {
                // process options available under no-default features and revocation feature
                options_no_std(&args);
            }

            debug!("PITTv3 end");
        }
    }
}

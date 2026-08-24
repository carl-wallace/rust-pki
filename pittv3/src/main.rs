#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)] // removed due to issue with Clap derive, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

mod cliargs;

use clap::Parser;
use log::debug;

use pittv3_lib::args::Pittv3Args;

use crate::cliargs::Pittv3CliArgs;

#[cfg(feature = "std_app")]
use log::LevelFilter;
#[cfg(feature = "std_app")]
use log4rs::append::console::ConsoleAppender;
#[cfg(feature = "std_app")]
use log4rs::config::{Appender, Config, Root};
#[cfg(feature = "std_app")]
use log4rs::encode::pattern::PatternEncoder;

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(feature = "std_app")] {
        /// Point of entry for PITTv3 application.
        #[tokio::main]
        async fn main() {
            let args: Pittv3Args = Pittv3CliArgs::parse().into();

            let mut logging_configured = false;

            if let Some(logging_config) = &args.logging_config {
                if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
                    println!(
                        "ERROR: failed to configure logging using {logging_config} with {e:?}. Continuing without logging."
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
                                    "ERROR: failed to configure logging for stdout with {e:?}. Continuing without logging."
                                );
                            }
                        }
                    Err(e) => {
                        println!("ERROR: failed to prepare default logging configuration with {e:?}. Continuing without logging");
                    }
                }
            }
            debug!("PITTv3 start");

            // Which entry point this resolves to is pittv3-lib's decision, not ours: its modules
            // gate on its own features, which cargo may have unified above the ones we asked for.
            let report = pittv3_lib::run(&args).await;
            if let Some(e) = &report.error {
                eprintln!("error: {e}");
                std::process::exit(1);
            }

            debug!("PITTv3 end");
        }
    }
    else if #[cfg(not(feature = "std_app"))] {
        /// Point of entry for PITTv3 application.
        fn main() {
            let args: Pittv3Args = Pittv3CliArgs::parse().into();

            debug!("PITTv3 start");

            // See the note in the other main: pittv3-lib picks its own entry point.
            let _report = pittv3_lib::run_blocking(&args);

            debug!("PITTv3 end");
        }
    }
}

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

use clap::Parser;
use log::{debug};

use crate::args::*;

#[cfg(feature = "std_app")]
use log::LevelFilter;
#[cfg(feature = "std_app")]
use log4rs::append::console::ConsoleAppender;
#[cfg(feature = "std_app")]
use log4rs::config::{Appender, Config, Root};
#[cfg(feature = "std_app")]
use log4rs::encode::pattern::PatternEncoder;

#[cfg(feature = "std_app")]
use std::env;

#[cfg(feature = "std_app")]
use clap::CommandFactory;

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(feature = "std")] {
        use options_std::*;
    }
    else {
        #[cfg(feature = "std_app")]
        use options_std_app::*;

        #[cfg(not(feature = "std_app"))]
        use options_no_std::*;
    }
}

cfg_if! {
    if #[cfg(feature = "std_app")] {
        /// Point of entry for PITTv3 application.
        #[tokio::main]
        async fn main() {
            // when testing no-default-features, skip the display of help then exit when there are no params
            // because the no-std build only has one param (to validate all paths instead of one).
            #[cfg(feature = "std_app")]
                {
                    let e = env::args_os();
                    if 1 == e.len() {
                        let mut a = Pittv3Args::command();
                        if let Err(_e) = a.print_help() {
                            println!("Error printing help. Try again with -h parameter.")
                        }
                        return;
                    }
                }
            let args = Pittv3Args::parse();

            #[cfg(feature = "std_app")]
            let mut logging_configured = false;

            #[cfg(not(feature = "std_app"))]
            let logging_configured = false;

            #[cfg(feature = "std_app")]
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

            #[cfg(feature = "std_app")]
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
            {
                // process options available under std_app feature
                #[cfg(feature = "std_app")]
                options_std_app(&args);

                // process options available under no-default features and revocation feature
                #[cfg(not(feature = "std_app"))]
                options_no_std(&args);
            }

            debug!("PITTv3 end");
        }
    }
    else {
        /// Point of entry for PITTv3 application.
        #[cfg(not(feature = "std_app"))]
        fn main() {
            // when testing no-default-features, skip the display of help then exit when there are no params
            // because the no-std build only has one param (to validate all paths instead of one).
            #[cfg(feature = "std_app")]
            {
                let e = env::args_os();
                if 1 == e.len() {
                    let mut a = Pittv3Args::command();
                    if let Err(_e) = a.print_help() {
                        println!("Error printing help. Try again with -h parameter.")
                    }
                    return;
                }
            }
            let args = Pittv3Args::parse();

            #[cfg(feature = "std_app")]
            let mut logging_configured = false;

            #[cfg(feature = "std_app")]
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

            #[cfg(feature = "std_app")]
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
            {
                // process options available under std_app feature
                #[cfg(feature = "std_app")]
                options_std_app(&args);

                // process options available under no-default features and revocation feature
                #[cfg(not(feature = "std_app"))]
                options_no_std(&args);
            }

            debug!("PITTv3 end");
        }
    }
}

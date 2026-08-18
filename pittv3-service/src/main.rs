//! Runs the PITTv3 service: the relay, server-side validation, and the browser application that
//! uses them.

use std::path::PathBuf;

use actix_web::{web, App, HttpServer};
use clap::Parser;
use log::info;

use pittv3_service::config::{ServiceConfig, ServiceState};
use pittv3_service::routes;

/// Command line for the service. A deployment with more to say than these arguments cover supplies
/// a configuration file, which carries the whole of [`ServiceConfig`], including the network policy
/// and the budgets; the arguments then override what they name.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to listen on.
    #[clap(short, long)]
    bind: Option<String>,

    /// JSON file holding the full service configuration, including the network policy and the
    /// retrieval budgets.
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// Directory of static files making up the browser application, i.e., what `trunk build`
    /// produced. Serving it here is what puts the application and the endpoints on one origin.
    #[clap(long)]
    client_dir: Option<PathBuf>,

    /// Directory of trust stores to offer, read at startup and never written to. Takes a folder
    /// per store holding `ta.cbor` and `ca.cbor`, as Export PKI Environment writes them, or flat
    /// `<id>_ta.cbor`/`<id>_ca.cbor` pairs, as the trust store providers generate them. These are
    /// offered alongside the built-in stores, and replace one of the same name.
    #[clap(long)]
    stores: Option<PathBuf>,

    /// Offers only the stores named by --stores, leaving out the ones built from the trust store
    /// providers. For a deployment that means to serve a chosen catalogue and nothing else.
    #[clap(long)]
    no_builtin_stores: bool,

    /// Permits server-side path building that chases authority and subject information access
    /// URIs. Off unless asked for: it turns one uploaded certificate into a good deal of outbound
    /// retrieval.
    #[clap(long)]
    allow_dynamic_build: bool,

    /// Refuses `POST /api/validate`, leaving the relay and the stores. A deployment that wants
    /// certificates never to leave the browser runs this way.
    #[clap(long)]
    no_validation: bool,

    /// Stops server-side validation retrieving the CRLs named by the paths it builds, leaving
    /// revocation status undetermined unless the caller supplied the data.
    #[clap(long)]
    no_revocation_fetch: bool,
}

fn load_config(args: &Args) -> Result<ServiceConfig, String> {
    let mut config = match &args.config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            serde_json::from_str::<ServiceConfig>(&text)
                .map_err(|e| format!("failed to parse {}: {e}", path.display()))?
        }
        None => ServiceConfig::default(),
    };

    if let Some(bind) = &args.bind {
        config.bind = bind.clone();
    }
    if args.client_dir.is_some() {
        config.client_dir = args.client_dir.clone();
    }
    if args.stores.is_some() {
        config.stores_dir = args.stores.clone();
    }
    if args.no_builtin_stores {
        config.builtin_stores = false;
    }
    if args.allow_dynamic_build {
        config.allow_dynamic_build = true;
    }
    if args.no_validation {
        config.enable_validation = false;
    }
    if args.no_revocation_fetch {
        config.fetch_revocation_data = false;
    }
    Ok(config)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let config = match load_config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let bind = config.bind.clone();
    let client_dir = config.client_dir.clone();
    let body_limit = config.limits.max_body_bytes;

    let state = match ServiceState::new(config) {
        Ok(s) => web::Data::new(s),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // The stores are named rather than counted: the built-in ones are not otherwise logged, and
    // which catalogue a service came up with is the first thing to check when a client is offered
    // something unexpected.
    let offered = state
        .stores
        .listing()
        .iter()
        .map(|d| d.id.clone())
        .collect::<Vec<String>>()
        .join(", ");
    info!(
        "Serving {} trust store(s) [{offered}]; validation {}, chasing {}",
        state.stores.len(),
        enabled(state.config.enable_validation),
        enabled(state.config.allow_dynamic_build)
    );

    HttpServer::new(move || {
        let app = App::new()
            .app_data(state.clone())
            // The cap is applied by the JSON extractor rather than by a handler, so an oversized
            // body is refused as it arrives instead of after it has been buffered and decoded.
            .app_data(web::JsonConfig::default().limit(body_limit))
            .configure(routes::configure);

        // Mounted last so nothing under the application directory can shadow an endpoint, and
        // serving index.html for unmatched paths so the application's own routing works on reload.
        match &client_dir {
            Some(dir) => app.service(
                actix_files::Files::new("/", dir)
                    .index_file("index.html")
                    .prefer_utf8(true),
            ),
            None => app,
        }
    })
    .bind(&bind)?
    .run()
    .await
}

fn enabled(flag: bool) -> &'static str {
    match flag {
        true => "enabled",
        false => "disabled",
    }
}

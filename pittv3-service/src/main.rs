//! Runs the PITTv3 service: the relay, server-side validation, and the browser application that
//! uses them.

use std::path::PathBuf;

use actix_web::dev::Service;
use actix_web::http::header::{HeaderValue, CACHE_CONTROL};
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

    /// Refuses `POST /api/tls`, so the service will not complete a handshake with a host on a
    /// client's behalf. For a deployment whose relay is meant to reach PKI repositories and
    /// nothing else.
    #[clap(long)]
    no_tls_peek: bool,
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
    if args.no_tls_peek {
        config.allow_tls_peek = false;
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
        "Serving {} trust store(s) [{offered}]; validation {}, chasing {}, host handshakes {}",
        state.stores.len(),
        enabled(state.config.enable_validation),
        enabled(state.config.allow_dynamic_build),
        enabled(state.config.allow_tls_peek)
    );

    HttpServer::new(move || {
        let app = App::new()
            // Cache-Control for the browser application. Trunk content-hashes the js and wasm but
            // NOT index.html, so a browser holding a stale index.html asks for the previous build's
            // hashed assets, gets 404s, and the application does not start. Serving the app from
            // this binary means there is no web server in front to set the header, so it is set
            // here or not at all -- and "not at all" is what made a redeploy look like a code bug
            // more than once. The policy is the one in pittv3-wasm/apache.htaccess.
            .wrap_fn(|req, srv| {
                // Endpoint responses are left alone: they are not static files, and a handler that
                // has something to say about caching its own answer should not be overridden here.
                let served_from_disk =
                    !(req.path().starts_with("/api/") || req.path().starts_with("/stores/"));
                let policy = cache_control_for(req.path());
                let fut = srv.call(req);
                async move {
                    let mut res = fut.await?;
                    if served_from_disk && !res.headers().contains_key(CACHE_CONTROL) {
                        res.headers_mut()
                            .insert(CACHE_CONTROL, HeaderValue::from_static(policy));
                    }
                    Ok(res)
                }
            })
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

/// Cache-Control for a static file the service serves, keyed on whether its name carries a content
/// hash.
///
/// Trunk emits `<name>-<16 hex>.js` and `<name>-<16 hex>_bg.wasm`, whose contents cannot change
/// without the name changing, so those are safe to keep for a year. Everything else -- index.html
/// above all -- must be revalidated, because the same name will hold different bytes after the next
/// deploy.
///
/// Deliberately conservative: the hash is looked for in the **file name** only, so an asset under a
/// hashed *directory* (Trunk's `snippets/<crate>-<hash>/…`) revalidates rather than being pinned. A
/// wrong "immutable" cannot be withdrawn for a year, while an unnecessary revalidation costs one
/// conditional request answered with 304.
fn cache_control_for(path: &str) -> &'static str {
    const IMMUTABLE: &str = "public, max-age=31536000, immutable";
    const REVALIDATE: &str = "no-cache, must-revalidate";

    let file = match path.rsplit('/').next() {
        Some(f) => f,
        None => return REVALIDATE,
    };
    match content_hashed(file) {
        true => IMMUTABLE,
        false => REVALIDATE,
    }
}

/// Whether `file` carries a Trunk content hash: a `-` followed by exactly 16 hex digits, ending the
/// stem. Matching the shape rather than any hex run keeps a name like `crl-2026.der` out of it.
fn content_hashed(file: &str) -> bool {
    let stem = file
        .strip_suffix("_bg.wasm")
        .or_else(|| file.strip_suffix(".wasm"))
        .or_else(|| file.strip_suffix(".js"))
        .unwrap_or("");
    match stem.rfind('-') {
        Some(dash) => {
            let tail = &stem[dash + 1..];
            tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

fn enabled(flag: bool) -> &'static str {
    match flag {
        true => "enabled",
        false => "disabled",
    }
}

#[cfg(test)]
mod cache_tests {
    use super::{cache_control_for, content_hashed};

    /// The names Trunk actually produced for the deployed bundle.
    #[test]
    fn trunk_hashed_assets_are_pinned() {
        assert!(content_hashed("pittv3-wasm-60c2dfcf11d6e584_bg.wasm"));
        assert!(content_hashed("pittv3-wasm-60c2dfcf11d6e584.js"));
        assert_eq!(
            cache_control_for("/pittv3-wasm-60c2dfcf11d6e584_bg.wasm"),
            "public, max-age=31536000, immutable"
        );
    }

    /// index.html is the one that must never be pinned -- it is unhashed and names the hashed
    /// assets, so a stale copy points at a previous deploy's files and the app fails to start.
    #[test]
    fn the_document_and_anything_unhashed_revalidates() {
        for path in [
            "/",
            "/index.html",
            "/resources/dod_nipr_prod_ta.cbor",
            "/snippets/dioxus-web-5b126e270dcd269f/src/js/eval.js",
        ] {
            assert_eq!(
                cache_control_for(path),
                "no-cache, must-revalidate",
                "{path} should revalidate"
            );
        }
    }

    /// A hash-shaped test rather than "contains hex": a plausible unhashed name must not be pinned,
    /// because a wrong immutable cannot be withdrawn for a year.
    #[test]
    fn a_name_that_merely_contains_hex_is_not_treated_as_hashed() {
        assert!(!content_hashed("bundle-abc123.js"));
        assert!(!content_hashed("crl-2026.der"));
        assert!(!content_hashed("app.js"));
        // 16 hex digits, but not in the stem-terminal position Trunk uses.
        assert!(!content_hashed("60c2dfcf11d6e584-app.js"));
    }
}

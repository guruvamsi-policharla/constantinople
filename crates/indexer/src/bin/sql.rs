//! SQL server bin that exposes Constantinople's SQL metadata schema
//! (`block_meta`, `tx_meta`) over `store.sql.v1.Service`.
//!
//! The upstream `exoware-sql` binary hard-codes its schema to a demo
//! `orders_kv` table, which is the wrong shape for the explorer. This
//! tiny wrapper binary calls [`build_meta_schema`] and reuses the SDK's
//! `SqlServer` + Connect stack so the explorer can subscribe to
//! `block_meta` rows over HTTP.
//!
//! Usage:
//!
//! ```bash
//! cargo run -p constantinople-indexer --bin sql -- \
//!   run --store-url http://127.0.0.1:8090 --port 8091
//! ```

use axum::{Router, routing::get};
use clap::{Parser, Subcommand};
use constantinople_indexer::sql_schema::build_meta_schema;
use exoware_sdk::StoreClient;
use exoware_sql::{SqlServer, sql_connect_stack};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "sql",
    version,
    about = "SQL server over Constantinople's metadata tables"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve `store.sql.v1.Service` against the given store URL.
    Run {
        /// URL of the exoware Store the SQL writer publishes to.
        #[arg(long)]
        store_url: String,
        /// Bind address (default `0.0.0.0`).
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        /// Listen port (default `8091`, matching the local-deploy default).
        #[arg(long, default_value_t = 8091)]
        port: u16,
    },
}

async fn health() -> &'static str {
    "ok"
}

fn build_server(
    store_url: &str,
) -> Result<Arc<SqlServer>, Box<dyn std::error::Error + Send + Sync>> {
    let client = StoreClient::new(store_url);
    let schema = build_meta_schema(client).map_err(|e| format!("configure schema: {e}"))?;
    let server = SqlServer::new(schema)?;
    Ok(Arc::new(server))
}

async fn run(
    store_url: &str,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = build_server(store_url)?;
    // The explorer hits this server from a browser; allow any origin so
    // local dev (Vite on a different port) can connect without a proxy.
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(sql_connect_stack(server))
        .layer(tower_http::cors::CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "constantinople sql server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Run {
            store_url,
            host,
            port,
        } => run(&store_url, host, port).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sql failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

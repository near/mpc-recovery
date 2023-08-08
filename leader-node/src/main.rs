use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
enum Cli {
    Start {
        /// ECDSA threshold
        #[arg(long, env("MPC_RECOVERY_THRESHOLD"))]
        threshold: usize,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install global collector configured based on RUST_LOG env var.
    let mut subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() {
        // Disable colored logging as it messes up GCP's log formatting
        subscriber = subscriber.with_ansi(false);
    }
    subscriber.init();
    let _span = tracing::trace_span!("cli").entered();

    match Cli::parse() {
        Cli::Start {
            threshold,
            web_port,
        } => leader_node::web::run(web_port, threshold).await,
    }
}

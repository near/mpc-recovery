use cait_sith::protocol::Participant;
use clap::Parser;
use local_ip_address::local_ip;
use sign_node::protocol::MpcSignProtocol;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Parser, Debug)]
enum Cli {
    Start {
        /// Node ID
        #[arg(long, value_parser = parse_participant, env("MPC_RECOVERY_NODE_ID"))]
        node_id: Participant,
        /// The leader node's URL
        #[arg(long, env("MPC_RECOVERY_LEADER_URL"))]
        leader_url: Url,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
    },
}

fn parse_participant(arg: &str) -> Result<Participant, std::num::ParseIntError> {
    let participant_id: u32 = arg.parse()?;
    Ok(participant_id.into())
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
            node_id,
            leader_url,
            web_port,
        } => {
            let (sender, receiver) = mpsc::channel(8);

            let my_ip = local_ip()?;
            let my_address = Url::parse(&format!("http://{my_ip}:{web_port}"))?;
            tracing::info!("my address: {}", my_address);
            let (protocol, protocol_state) =
                MpcSignProtocol::init(node_id, my_address, leader_url, receiver);
            let protocol = tokio::spawn(async move {
                protocol.run().await.unwrap();
            });
            let backend = tokio::spawn(async move {
                sign_node::web::run(web_port, sender, protocol_state)
                    .await
                    .unwrap();
            });

            let (backend_result, protocol_result) = tokio::join!(backend, protocol);
            backend_result?;
            protocol_result?;
        }
    }

    Ok(())
}

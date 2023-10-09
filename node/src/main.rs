use cait_sith::protocol::Participant;
use clap::Parser;
use local_ip_address::local_ip;
use mpc_recovery_node::protocol::MpcSignProtocol;
use near_crypto::{InMemorySigner, SecretKey};
use near_primitives::types::AccountId;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Parser, Debug)]
enum Cli {
    Start {
        /// Node ID
        #[arg(long, value_parser = parse_participant, env("MPC_RECOVERY_NODE_ID"))]
        node_id: Participant,
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_RECOVERY_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// MPC contract id
        #[arg(long, env("MPC_RECOVERY_CONTRACT_ID"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_RECOVERY_ACCOUNT"))]
        account: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
    },
}

fn parse_participant(arg: &str) -> Result<Participant, std::num::ParseIntError> {
    let participant_id: u32 = arg.parse()?;
    Ok(participant_id.into())
}

fn main() -> anyhow::Result<()> {
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
            near_rpc,
            web_port,
            mpc_contract_id,
            account,
            account_sk,
        } => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (sender, receiver) = mpsc::channel(16384);

                    let my_ip = local_ip()?;
                    let my_address = Url::parse(&format!("http://{my_ip}:{web_port}"))?;
                    tracing::info!(%my_address, "address detected");
                    let rpc_client = near_fetch::Client::new(&near_rpc);
                    tracing::debug!(rpc_addr = rpc_client.rpc_addr(), "rpc client initialized");
                    let signer = InMemorySigner::from_secret_key(account, account_sk);
                    let (protocol, protocol_state) = MpcSignProtocol::init(
                        node_id,
                        my_address,
                        mpc_contract_id.clone(),
                        rpc_client.clone(),
                        signer.clone(),
                        receiver,
                    );
                    tracing::debug!("protocol initialized");
                    let protocol_handle = tokio::spawn(async move {
                        protocol.run().await.unwrap();
                    });
                    tracing::debug!("protocol thread spawned");
                    let mpc_contract_id_cloned = mpc_contract_id.clone();
                    let web_handle = tokio::spawn(async move {
                        mpc_recovery_node::web::run(
                            web_port,
                            mpc_contract_id_cloned,
                            rpc_client,
                            signer,
                            sender,
                            protocol_state,
                        )
                        .await
                        .unwrap();
                    });
                    tracing::debug!("protocol http server spawned");

                    protocol_handle.await?;
                    web_handle.await?;
                    tracing::debug!("spinning down");

                    anyhow::Ok(())
                })?;
            mpc_recovery_node::indexer::run(&near_rpc, mpc_contract_id)?;
        }
    }

    Ok(())
}

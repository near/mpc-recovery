use crate::protocol::{MpcSignProtocol, SignQueue};
use crate::{indexer, storage, web};
use cait_sith::protocol::Participant;
use clap::Parser;
use local_ip_address::local_ip;
use near_crypto::{InMemorySigner, SecretKey};
use near_primitives::types::AccountId;
use std::sync::Arc;
use std::thread;
use tokio::sync::{mpsc, RwLock};
use tracing_subscriber::EnvFilter;
use url::Url;

use mpc_keys::hpke;

#[derive(Parser, Debug)]
pub enum Cli {
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
        // TODO: need to add in CipherPK type for parsing.
        /// The cipher public key used to encrypt messages between nodes.
        #[arg(long, env("MPC_RECOVERY_CIPHER_PK"))]
        cipher_pk: String,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_RECOVERY_CIPHER_SK"))]
        cipher_sk: String,
        /// NEAR Lake Indexer options
        #[clap(flatten)]
        indexer_options: indexer::Options,
        /// Storage options
        #[clap(flatten)]
        storage_options: storage::Options,
    },
}

fn parse_participant(arg: &str) -> Result<Participant, std::num::ParseIntError> {
    let participant_id: u32 = arg.parse()?;
    Ok(participant_id.into())
}

impl Cli {
    pub fn into_str_args(self) -> Vec<String> {
        match self {
            Cli::Start {
                node_id,
                near_rpc,
                mpc_contract_id,
                account,
                account_sk,
                web_port,
                cipher_pk,
                cipher_sk,
                indexer_options,
                storage_options,
            } => {
                let mut args = vec![
                    "start".to_string(),
                    "--node-id".to_string(),
                    u32::from(node_id).to_string(),
                    "--near-rpc".to_string(),
                    near_rpc,
                    "--mpc-contract-id".to_string(),
                    mpc_contract_id.to_string(),
                    "--account".to_string(),
                    account.to_string(),
                    "--account-sk".to_string(),
                    account_sk.to_string(),
                    "--web-port".to_string(),
                    web_port.to_string(),
                    "--cipher-pk".to_string(),
                    cipher_pk,
                    "--cipher-sk".to_string(),
                    cipher_sk,
                ];
                args.extend(indexer_options.into_str_args());
                args.extend(storage_options.into_str_args());
                args
            }
        }
    }
}

pub fn run(cmd: Cli) -> anyhow::Result<()> {
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

    match cmd {
        Cli::Start {
            node_id,
            near_rpc,
            web_port,
            mpc_contract_id,
            account,
            account_sk,
            cipher_pk,
            cipher_sk,
            indexer_options,
            storage_options,
        } => {
            let sign_queue = Arc::new(RwLock::new(SignQueue::new()));
            let a = indexer_options.clone();
            let b = mpc_contract_id.clone();
            let c = sign_queue.clone();
            let indexer_handler = thread::spawn(move || {
                indexer::run(a, b, c).unwrap();
            });
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (sender, receiver) = mpsc::channel(16384);
                    let key_storage = storage::init(&storage_options).await?;

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
                        sign_queue.clone(),
                        hpke::PublicKey::try_from_bytes(&hex::decode(cipher_pk)?).unwrap(),
                        key_storage,
                    );
                    tracing::debug!("protocol initialized");
                    let protocol_handle = tokio::spawn(async move {
                        protocol.run().await.unwrap();
                    });
                    tracing::debug!("protocol thread spawned");
                    let mpc_contract_id_cloned = mpc_contract_id.clone();
                    let cipher_sk =
                        hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?).unwrap();
                    let web_handle = tokio::spawn(async move {
                        web::run(
                            web_port,
                            mpc_contract_id_cloned,
                            rpc_client,
                            signer,
                            sender,
                            cipher_sk,
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
            indexer_handler.join().unwrap();
        }
    }

    Ok(())
}

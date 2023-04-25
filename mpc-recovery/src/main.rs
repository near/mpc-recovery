use clap::Parser;
use mpc_recovery::{
    gcp::GcpService,
    oauth::{PagodaFirebaseTokenVerifier, UniversalTokenVerifier},
    LeaderConfig,
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_primitives::types::AccountId;

#[derive(Parser, Debug)]
enum Cli {
    Generate {
        n: usize,
    },
    StartLeader {
        /// Environment to run in (`dev` or `prod`)
        #[arg(long, env("MPC_RECOVERY_ENV"), default_value("dev"))]
        env: String,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        /// The compute nodes to connect to
        #[arg(long, env("MPC_RECOVERY_SIGN_NODES"))]
        sign_nodes: Vec<String>,
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_RECOVERY_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// NEAR meta transaction relayer URL
        #[arg(
            long,
            env("MPC_RECOVERY_RELAYER_URL"),
            default_value("http://34.70.226.83:3030")
        )]
        relayer_url: String,
        /// NEAR root account that has linkdrop contract deployed on it
        #[arg(long, env("MPC_RECOVERY_NEAR_ROOT_ACCOUNT"), default_value("testnet"))]
        near_root_account: String,
        /// Account creator ID
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_ID"))]
        account_creator_id: AccountId,
        /// TEMPORARY - Account creator ed25519 secret key
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_CREATOR_SK"))]
        account_creator_sk: Option<String>,
        #[arg(
            long,
            env("MPC_RECOVERY_ACCOUNT_LOOKUP_URL"),
            default_value("https://api.kitwallet.app")
        )]
        account_lookup_url: String,
        #[arg(long, env("PAGODA_FIREBASE_AUDIENCE_ID"))]
        pagoda_firebase_audience_id: String,
        /// GCP project ID
        #[arg(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
        gcp_project_id: String,
        /// GCP datastore URL
        #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
        gcp_datastore_url: Option<String>,
        /// Whether to accept test tokens
        #[arg(long, env("MPC_RECOVERY_TEST"), default_value("false"))]
        test: bool,
    },
    StartSign {
        /// Environment to run in (`dev` or `prod`)
        #[arg(long, env("MPC_RECOVERY_ENV"), default_value("dev"))]
        env: String,
        /// Node ID
        #[arg(long, env("MPC_RECOVERY_NODE_ID"))]
        node_id: u64,
        /// Secret key share, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_SK_SHARE"))]
        sk_share: Option<String>,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        /// GCP project ID
        #[arg(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
        gcp_project_id: String,
        /// GCP datastore URL
        #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
        gcp_datastore_url: Option<String>,
        /// Whether to accept test tokens
        #[arg(long, env("MPC_RECOVERY_TEST"), default_value("false"))]
        test: bool,
    },
}

async fn load_sh_skare(
    gcp_service: &GcpService,
    env: &str,
    node_id: u64,
    sk_share_arg: Option<String>,
) -> anyhow::Result<String> {
    match sk_share_arg {
        Some(sk_share) => Ok(sk_share),
        None => {
            let name = format!(
                "projects/pagoda-discovery-platform-dev/secrets/mpc-recovery-secret-share-{node_id}-{env}/versions/latest"
            );
            Ok(std::str::from_utf8(&gcp_service.load_secret(name).await?)?.to_string())
        }
    }
}

async fn load_account_creator_sk(
    gcp_service: &GcpService,
    env: &str,
    account_creator_sk_arg: Option<String>,
) -> anyhow::Result<String> {
    match account_creator_sk_arg {
        Some(account_creator_sk) => Ok(account_creator_sk),
        None => {
            let name = format!(
                "projects/pagoda-discovery-platform-dev/secrets/mpc-recovery-account-creator-sk-{env}/versions/latest"
            );
            Ok(std::str::from_utf8(&gcp_service.load_secret(name).await?)?.to_string())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install global collector configured based on RUST_LOG env var.
    let mut subscriber = tracing_subscriber::fmt();
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() {
        // Disable colored logging as it messes up Google's log formatting
        subscriber = subscriber.with_ansi(false);
    }
    subscriber.init();
    let _span = tracing::trace_span!("cli").entered();

    match Cli::parse() {
        Cli::Generate { n } => {
            let (pk_set, sk_shares) = mpc_recovery::generate(n);
            println!("Public key set: {}", serde_json::to_string(&pk_set)?);
            for (i, sk_share) in sk_shares.iter().enumerate() {
                println!(
                    "Secret key share {}: {}",
                    i,
                    serde_json::to_string(sk_share)?
                );
            }
        }
        Cli::StartLeader {
            env,
            web_port,
            sign_nodes,
            near_rpc,
            relayer_url,
            near_root_account,
            account_creator_id,
            account_creator_sk,
            account_lookup_url,
            pagoda_firebase_audience_id,
            gcp_project_id,
            gcp_datastore_url,
            test,
        } => {
            let gcp_service =
                GcpService::new(env.clone(), gcp_project_id, gcp_datastore_url).await?;
            let account_creator_sk =
                load_account_creator_sk(&gcp_service, &env, account_creator_sk).await?;

            let account_creator_sk = account_creator_sk.parse()?;

            let config = LeaderConfig {
                env,
                port: web_port,
                sign_nodes,
                near_rpc,
                relayer_url,
                near_root_account,
                // TODO: Create such an account for testnet and mainnet in a secure way
                account_creator_id,
                account_creator_sk,
                account_lookup_url,
                pagoda_firebase_audience_id,
            };

            if test {
                mpc_recovery::run_leader_node::<UniversalTokenVerifier>(config).await;
            } else {
                mpc_recovery::run_leader_node::<PagodaFirebaseTokenVerifier>(config).await;
            }
        }
        Cli::StartSign {
            env,
            node_id,
            sk_share,
            web_port,
            gcp_project_id,
            gcp_datastore_url,
            test,
        } => {
            let gcp_service =
                GcpService::new(env.clone(), gcp_project_id, gcp_datastore_url).await?;
            let sk_share = load_sh_skare(&gcp_service, &env, node_id, sk_share).await?;

            // TODO Import just the private key and derive the rest
            let sk_share: ExpandedKeyPair = serde_json::from_str(&sk_share).unwrap();

            if test {
                mpc_recovery::run_sign_node::<UniversalTokenVerifier>(
                    gcp_service,
                    node_id,
                    sk_share,
                    web_port,
                )
                .await;
            } else {
                mpc_recovery::run_sign_node::<PagodaFirebaseTokenVerifier>(
                    gcp_service,
                    node_id,
                    sk_share,
                    web_port,
                )
                .await;
            }
        }
    }

    Ok(())
}

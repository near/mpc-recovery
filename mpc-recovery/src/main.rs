use aes_gcm::{
    aead::{consts::U32, generic_array::GenericArray, KeyInit},
    Aes256Gcm,
};
use clap::Parser;
use mpc_recovery::{
    gcp::GcpService,
    oauth::{PagodaFirebaseTokenVerifier, UniversalTokenVerifier},
    GenerateResult, LeaderConfig, SignerConfig,
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_primitives::types::AccountId;
use tracing_subscriber::EnvFilter;

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
        #[arg(long, value_parser, num_args = 1.., value_delimiter = ',', env("MPC_RECOVERY_SIGN_NODES"))]
        sign_nodes: Vec<String>,
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_RECOVERY_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// NEAR meta transaction relayer URL
        #[arg(long, env("MPC_RECOVERY_RELAYER_API_KEY"))]
        relayer_api_key: Option<String>,
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
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_CREATOR_ID"))]
        account_creator_id: AccountId,
        /// TEMPORARY - Account creator ed25519 secret key
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_CREATOR_SK"))]
        account_creator_sk: Option<String>,
        /// Firebase Audience ID
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
        /// Cipher key to encrypt stored user credentials, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_CIPHER_KEY"))]
        cipher_key: Option<String>,
        /// Secret key share, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_SK_SHARE"))]
        sk_share: Option<String>,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        /// Firebase Audience ID
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
    RotateSignNodeKey {
        /// Environment to run in (`dev` or `prod`)
        #[arg(long, env("MPC_RECOVERY_ENV"), default_value("dev"))]
        env: String,
        /// Node ID
        #[arg(long, env("MPC_RECOVERY_NODE_ID"))]
        node_id: u64,
        /// Old cipher key, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_OLD_CIPHER_KEY"))]
        old_cipher_key: Option<String>,
        /// The new cipher key to replace each encrypted record with.
        #[arg(long, env("MPC_RECOVERY_NEW_CIPHER_KEY"))]
        new_cipher_key: Option<String>,
        /// Old secret key share, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_OLD_SK_SHARE"))]
        old_sk_share: Option<String>,
        /// Newest secret key share.
        #[arg(long, env("MPC_RECOVERY_NEW_SK_SHARE"))]
        new_sk_share: String,
        /// GCP project ID
        #[arg(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
        gcp_project_id: String,
        /// GCP datastore URL
        #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
        gcp_datastore_url: Option<String>,
    },
    // RotateUserKeys {
    // }
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
            let name = format!("mpc-recovery-secret-share-{node_id}-{env}/versions/latest");
            Ok(std::str::from_utf8(&gcp_service.load_secret(name).await?)?.to_string())
        }
    }
}

async fn load_cipher_key(
    gcp_service: &GcpService,
    env: &str,
    node_id: u64,
    cipher_key_arg: Option<String>,
) -> anyhow::Result<String> {
    match cipher_key_arg {
        Some(cipher_key) => Ok(cipher_key),
        None => {
            let name = format!("mpc-recovery-encryption-cipher-{node_id}-{env}/versions/latest");
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
            let name = format!("mpc-recovery-account-creator-sk-{env}/versions/latest");
            Ok(std::str::from_utf8(&gcp_service.load_secret(name).await?)?.to_string())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install global collector configured based on RUST_LOG env var.
    let mut subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() {
        // Disable colored logging as it messes up Google's log formatting
        subscriber = subscriber.with_ansi(false);
    }
    subscriber.init();
    let _span = tracing::trace_span!("cli").entered();

    match Cli::parse() {
        Cli::Generate { n } => {
            let GenerateResult { pk_set, secrets } = mpc_recovery::generate(n);
            tracing::info!("Public key set: {}", serde_json::to_string(&pk_set)?);
            for (i, (sk_share, cipher_key)) in secrets.iter().enumerate() {
                tracing::info!(
                    "Secret key share {}: {}",
                    i,
                    serde_json::to_string(sk_share)?
                );
                tracing::info!("Cipher {}: {}", i, hex::encode(cipher_key));
            }
        }
        Cli::StartLeader {
            env,
            web_port,
            sign_nodes,
            near_rpc,
            relayer_api_key,
            relayer_url,
            near_root_account,
            account_creator_id,
            account_creator_sk,
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
                relayer_api_key,
                relayer_url,
                near_root_account,
                // TODO: Create such an account for testnet and mainnet in a secure way
                account_creator_id,
                account_creator_sk,
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
            cipher_key,
            web_port,
            pagoda_firebase_audience_id,
            gcp_project_id,
            gcp_datastore_url,
            test,
        } => {
            let gcp_service =
                GcpService::new(env.clone(), gcp_project_id, gcp_datastore_url).await?;
            let cipher_key = load_cipher_key(&gcp_service, &env, node_id, cipher_key).await?;
            let cipher_key = hex::decode(cipher_key)?;
            let cipher_key = GenericArray::<u8, U32>::clone_from_slice(&cipher_key);
            let cipher = Aes256Gcm::new(&cipher_key);

            let sk_share = load_sh_skare(&gcp_service, &env, node_id, sk_share).await?;

            // TODO Import just the private key and derive the rest
            let sk_share: ExpandedKeyPair = serde_json::from_str(&sk_share).unwrap();

            let config = SignerConfig {
                vault: mpc_recovery::sign_node::migration::Vault::Stable {
                    cipher: cipher.clone(),
                    node_key: sk_share.clone(),
                    node_id: node_id as usize,
                },
                gcp_service,
                our_index: node_id,
                node_key: sk_share,
                cipher,
                port: web_port,
                pagoda_firebase_audience_id,
            };
            if test {
                mpc_recovery::run_sign_node::<UniversalTokenVerifier>(config).await;
            } else {
                mpc_recovery::run_sign_node::<PagodaFirebaseTokenVerifier>(config).await;
            }
        }
        Cli::RotateSignNodeKey {
            env,
            node_id,
            old_cipher_key,
            new_cipher_key,
            old_sk_share,
            new_sk_share,
            gcp_project_id,
            gcp_datastore_url,
        } => {
            let gcp_service =
                GcpService::new(env.clone(), gcp_project_id, gcp_datastore_url).await?;

            let old_cipher_key = load_cipher_key(&gcp_service, &env, node_id, old_cipher_key).await?;
            let old_cipher_key = hex::decode(old_cipher_key)?;
            let old_cipher_key = GenericArray::<u8, U32>::clone_from_slice(&old_cipher_key);
            let old_cipher = Aes256Gcm::new(&old_cipher_key);
            let old_sk_share = load_sh_skare(&gcp_service, &env, node_id, old_sk_share).await?;
            let old_sk_share: ExpandedKeyPair = serde_json::from_str(&old_sk_share).unwrap();

            let new_cipher_key = load_cipher_key(&gcp_service, &env, node_id, new_cipher_key).await?;
            let new_cipher_key = hex::decode(new_cipher_key)?;
            let new_cipher_key = GenericArray::<u8, U32>::clone_from_slice(&new_cipher_key);
            let new_cipher = Aes256Gcm::new(&new_cipher_key);
            let new_sk_share: ExpandedKeyPair = serde_json::from_str(&new_sk_share).unwrap();

        }
    }

    Ok(())
}

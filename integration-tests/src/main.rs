use clap::Parser;
use mpc_recovery::GenerateResult;
use mpc_recovery_integration_tests::containers;
use near_primitives::utils::generate_random_string;
use tokio::io::{stdin, AsyncReadExt};
use tracing_subscriber::EnvFilter;

const NETWORK: &str = "mpc_recovery_dev_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-dev-gcp-project";
pub const FIREBASE_AUDIENCE_ID: &str = "test_audience";

#[derive(Parser, Debug)]
enum Cli {
    TestLeader { nodes: usize },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    subscriber.init();
    match Cli::parse() {
        Cli::TestLeader { nodes } => {
            tracing::info!("Setting up an environment with {} nodes", nodes);
            let docker_client = containers::DockerClient::default();

            let relayer_id = generate_random_string(7);
            let relayer_ctx_future = mpc_recovery_integration_tests::initialize_relayer(
                &docker_client,
                NETWORK,
                &relayer_id,
            );
            let datastore_future =
                containers::Datastore::run(&docker_client, NETWORK, GCP_PROJECT_ID);

            let oidc_provider_future = containers::OidcProvider::run(&docker_client, NETWORK);

            let (relayer_ctx, datastore, oidc_provider) =
                futures::future::join3(relayer_ctx_future, datastore_future, oidc_provider_future)
                    .await;

            let relayer_ctx = relayer_ctx?;
            let datastore = datastore?;
            let oidc_provider = oidc_provider?;

            tracing::info!("Generating secrets");
            let GenerateResult { secrets, .. } = mpc_recovery::generate(nodes);
            tracing::info!("Running signer nodes...");
            let mut signer_node_futures = Vec::new();
            for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
                let signer_node = containers::SignerNode::run_signing_node(
                    &docker_client,
                    NETWORK,
                    i as u64,
                    share,
                    cipher_key,
                    &datastore.address,
                    &datastore.local_address,
                    GCP_PROJECT_ID,
                    FIREBASE_AUDIENCE_ID,
                    &oidc_provider.jwt_pk_url,
                );
                signer_node_futures.push(signer_node);
            }
            let signer_nodes = futures::future::join_all(signer_node_futures)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;
            tracing::info!("Signer nodes initialized");
            let signer_urls: &Vec<_> = &signer_nodes.iter().map(|n| n.address.clone()).collect();

            let near_root_account = relayer_ctx.worker.root_account()?;
            tracing::info!("Root account_id: {}", near_root_account.id());

            let mut cmd = vec![
                "start-leader".to_string(),
                "--web-port".to_string(),
                "3000".to_string(),
                "--near-rpc".to_string(),
                format!(
                    "http://localhost:{}",
                    relayer_ctx
                        .sandbox
                        .container
                        .get_host_port_ipv4(containers::Sandbox::CONTAINER_RPC_PORT)
                ),
                "--near-root-account".to_string(),
                near_root_account.id().to_string(),
                "--account-creator-id".to_string(),
                relayer_ctx.creator_account.id().to_string(),
                "--account-creator-sk".to_string(),
                relayer_ctx.creator_account.secret_key().to_string(),
                "--gcp-project-id".to_string(),
                GCP_PROJECT_ID.to_string(),
                "--gcp-datastore-url".to_string(),
                format!(
                    "http://localhost:{}",
                    datastore
                        .container
                        .get_host_port_ipv4(containers::Datastore::CONTAINER_PORT)
                ),
                "--fast-auth-partners".to_string(),
                escape_json_string(&serde_json::json!([
                    {
                        "oidc_provider": {
                            "issuer": format!("https://securetoken.google.com/{}", FIREBASE_AUDIENCE_ID.to_string()),
                            "audience": FIREBASE_AUDIENCE_ID.to_string(),
                        },
                        "relayer": {
                            "url": format!(
                                "http://localhost:{}",
                                relayer_ctx
                                    .relayer
                                    .container
                                    .get_host_port_ipv4(containers::Relayer::CONTAINER_PORT)
                            ),
                            "api_key": serde_json::Value::Null,
                        },
                    },
                ]).to_string()),
                "--jwt-signature-pk-url".to_string(),
                oidc_provider.jwt_pk_url,

            ];
            for sign_node in signer_urls {
                cmd.push("--sign-nodes".to_string());
                cmd.push(sign_node.clone());
            }

            tracing::info!("Please run the command below to start a leader node:");
            tracing::info!(
                "RUST_BACKTRACE=1 RUST_LOG=mpc_recovery=debug cargo run --bin mpc-recovery -- {}",
                cmd.join(" ")
            );
            tracing::info!("====================================");
            tracing::info!("You can now interact with your local service manually. For example:");
            tracing::info!(
                r#"curl -X POST -H "Content-Type: application/json" -d '{{"oidc_token": <valid_token>, "near_account_id": "abc45436676.near", "create_account_options": {{"full_access_keys": ["ed25519:4fnCz9NTEMhkfwAHDhFDkPS1mD58QHdRyago5n4vtCS2"]}}}}' http://localhost:3000/new_account"#
            );

            tracing::info!("Press any button to exit and destroy all containers...");

            while stdin().read(&mut [0]).await? == 0 {}
        }
    };

    Ok(())
}

fn escape_json_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len() + 2);
    result.push('"');

    for c in input.chars() {
        match c {
            '"' => result.push_str(r"\\"),
            '\\' => result.push_str(r"\\"),
            '\n' => result.push_str(r"\n"),
            '\r' => result.push_str(r"\r"),
            '\t' => result.push_str(r"\t"),
            '\u{08}' => result.push_str(r"\b"), // Backspace
            '\u{0C}' => result.push_str(r"\f"), // Form feed
            _ => result.push(c),
        }
    }

    result.push('"');
    result
}

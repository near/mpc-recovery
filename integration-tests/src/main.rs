use clap::Parser;
use mpc_recovery::GenerateResult;
use mpc_recovery_integration_tests::containers;
use tokio::io::{stdin, AsyncReadExt};

const NETWORK: &str = "mpc_recovery_dev_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-dev-gcp-project";
// TODO: figure out how to instantiate an use a local firebase deployment
const FIREBASE_AUDIENCE_ID: &str = "not-actually-used-in-integration-tests";

#[derive(Parser, Debug)]
enum Cli {
    TestLeader { nodes: usize },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse() {
        Cli::TestLeader { nodes } => {
            println!("Setting up an environment with {} nodes", nodes);
            let docker_client = containers::DockerClient::default();

            let relayer_ctx_future =
                mpc_recovery_integration_tests::initialize_relayer(&docker_client, NETWORK);
            let datastore_future =
                containers::Datastore::run(&docker_client, NETWORK, GCP_PROJECT_ID);

            let (relayer_ctx, datastore) =
                futures::future::join(relayer_ctx_future, datastore_future).await;
            let relayer_ctx = relayer_ctx?;
            let datastore = datastore?;

            println!("Generating secrets");
            let GenerateResult { secrets, .. } = mpc_recovery::generate(nodes);
            println!("Running signer nodes...");
            let mut signer_node_futures = Vec::new();
            for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
                let signer_node = containers::SignerNode::run(
                    &docker_client,
                    NETWORK,
                    i as u64,
                    share,
                    cipher_key,
                    &datastore.address,
                    GCP_PROJECT_ID,
                    FIREBASE_AUDIENCE_ID,
                );
                signer_node_futures.push(signer_node);
            }
            let signer_nodes = futures::future::join_all(signer_node_futures)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;
            println!("Signer nodes initialized");
            let signer_urls: &Vec<_> = &signer_nodes.iter().map(|n| n.address.clone()).collect();

            let near_root_account = relayer_ctx.worker.root_account()?;
            println!("Root account_id: {}", near_root_account.id());

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
                "--relayer-url".to_string(),
                format!(
                    "http://localhost:{}",
                    relayer_ctx
                        .relayer
                        .container
                        .get_host_port_ipv4(containers::Relayer::CONTAINER_PORT)
                ),
                "--near-root-account".to_string(),
                near_root_account.id().to_string(),
                "--account-creator-id".to_string(),
                relayer_ctx.creator_account_id.to_string(),
                "--account-creator-sk".to_string(),
                relayer_ctx.creator_account_sk.to_string(),
                "--pagoda-firebase-audience-id".to_string(),
                FIREBASE_AUDIENCE_ID.to_string(),
                "--gcp-project-id".to_string(),
                GCP_PROJECT_ID.to_string(),
                "--gcp-datastore-url".to_string(),
                format!(
                    "http://localhost:{}",
                    datastore
                        .container
                        .get_host_port_ipv4(containers::Datastore::CONTAINER_PORT)
                ),
                "--test".to_string(),
            ];
            for sign_node in signer_urls {
                cmd.push("--sign-nodes".to_string());
                cmd.push(sign_node.clone());
            }

            println!("Please run the command below to start a leader node:");
            println!(
                "RUST_LOG=mpc_recovery=debug cargo run --bin mpc-recovery -- {}",
                cmd.join(" ")
            );
            println!("====================================");
            println!("You can now interact with your local service manually. For example:");
            println!(
                r#"curl -X POST -H "Content-Type: application/json" -d '{{"oidc_token": "validToken:1", "near_account_id": "abc45436676.near", "create_account_options": {{"full_access_keys": ["ed25519:4fnCz9NTEMhkfwAHDhFDkPS1mD58QHdRyago5n4vtCS2"]}}}}' http://localhost:3000/new_account"#
            );

            println!();
            println!("Press any button to exit and destroy all containers...");

            while stdin().read(&mut [0]).await? == 0 {}
        }
    };

    Ok(())
}

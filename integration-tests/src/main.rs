use clap::Parser;
// use mpc_recovery_integration_tests::env;
// use mpc_recovery_integration_tests::multichain::containers::DockerClient;
// use tokio::io::{stdin, AsyncReadExt};
// use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
enum Cli {
    SetupEnv { nodes: usize },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // let subscriber = tracing_subscriber::fmt()
    //     .with_thread_ids(true)
    //     .with_env_filter(EnvFilter::from_default_env());
    // subscriber.init();
    // match Cli::parse() {
    //     Cli::SetupEnv { nodes } => {
    //         println!("Setting up an environment with {} nodes...", nodes);
    //         let docker_client = DockerClient::default();
    //         let nodes = env::run(nodes, &docker_client).await?;
    //         let ctx = nodes.ctx();

    //         println!("\nEnvironment is ready:");
    //         println!("  docker-network: {}", ctx.docker_network);
    //         println!("  gcp-project-id: {}", ctx.gcp_project_id);
    //         println!("  audience-id:    {}", ctx.audience_id);
    //         println!("  issuer:         {}", ctx.issuer);
    //         println!("  release:        {}", ctx.release);
    //         println!("  env:            {}", ctx.env);

    //         println!("\nAccounts:");
    //         println!("  creator: {}", ctx.relayer_ctx.creator_account.id());
    //         println!("  root:    {}", ctx.relayer_ctx.worker.root_account()?.id());

    //         println!("\nExternal services:");
    //         println!("  oidc-provider: {}", ctx.oidc_provider.jwt_pk_local_url);
    //         println!("  datastore:     {}", nodes.datastore_addr());
    //         println!("  sandbox:       {}", ctx.relayer_ctx.sandbox.local_address);
    //         println!("  relayer:       {}", ctx.relayer_ctx.relayer.local_address);
    //         println!("  redis:         {}", ctx.relayer_ctx.redis.local_address);

    //         println!("\nNode services:");
    //         println!("  leader node:   {}", nodes.leader_api().address);
    //         println!("  signer nodes:");
    //         for node in nodes.signer_apis() {
    //             println!("    {}: {}", node.node_id, node.address);
    //         }

    //         println!("\nSigner public key set:");
    //         for pk in nodes.pk_set() {
    //             println!("  {pk:?}");
    //         }

    //         println!("\nPress any button to exit and destroy all containers...");
    //         while stdin().read(&mut [0]).await? == 0 {
    //             tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    //         }
    //     }
    // };

    Ok(())
}

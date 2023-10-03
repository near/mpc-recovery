use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use near_crypto::KeyFile;
use near_units::parse_near;
use workspaces::{
    network::{Sandbox, ValidatorKey},
    types::SecretKey,
    Account, Worker,
};

pub mod containers;
pub mod sandbox;
pub mod util;

async fn fetch_validator_keys(
    docker_client: &containers::DockerClient,
    sandbox: &containers::Sandbox<'_>,
) -> anyhow::Result<KeyFile> {
    tracing::info!("Fetching validator keys...");
    let create_result = docker_client
        .docker
        .create_exec(
            sandbox.container.id(),
            CreateExecOptions::<String> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec![
                    "cat".to_string(),
                    "/root/.near/validator_key.json".to_string(),
                ]),
                ..Default::default()
            },
        )
        .await?;

    let start_result = docker_client
        .docker
        .start_exec(&create_result.id, None)
        .await?;

    match start_result {
        StartExecResults::Attached { mut output, .. } => {
            let mut stream_contents = Vec::new();
            while let Some(chunk) = output.next().await {
                stream_contents.extend_from_slice(&chunk?.into_bytes());
            }

            tracing::info!("Validator keys fetched");
            Ok(serde_json::from_slice(&stream_contents)?)
        }
        StartExecResults::Detached => unreachable!("unexpected detached output"),
    }
}

pub struct RelayerCtx<'a> {
    pub sandbox: containers::Sandbox<'a>,
    pub redis: containers::Redis<'a>,
    pub relayer: containers::Relayer<'a>,
    pub worker: Worker<Sandbox>,
    pub creator_account: Account,
    pub creator_account_keys: Vec<SecretKey>,
}

pub async fn initialize_relayer<'a>(
    docker_client: &'a containers::DockerClient,
    network: &str,
) -> anyhow::Result<RelayerCtx<'a>> {
    tracing::info!("Initializing relayer...");
    let sandbox = containers::Sandbox::run(docker_client, network).await?;

    let validator_key = fetch_validator_keys(docker_client, &sandbox).await?;

    tracing::info!("Initializing sandbox worker...");
    let worker = workspaces::sandbox()
        .rpc_addr(&format!(
            "http://localhost:{}",
            sandbox
                .container
                .get_host_port_ipv4(crate::containers::Sandbox::CONTAINER_RPC_PORT)
        ))
        .validator_key(ValidatorKey::Known(
            validator_key.account_id.to_string().parse()?,
            validator_key.secret_key.to_string().parse()?,
        ))
        .await?;
    tracing::info!("Sandbox worker initialized");
    let social_db = sandbox::initialize_social_db(&worker).await?;
    sandbox::initialize_linkdrop(&worker).await?;
    tracing::info!("Initializing relayer accounts...");
    let relayer_account =
        sandbox::create_account(&worker, "relayer", parse_near!("1000 N")).await?;
    let relayer_account_keys = sandbox::gen_rotating_keys(&relayer_account, 5).await?;

    let creator_account = sandbox::create_account(&worker, "creator", parse_near!("200 N")).await?;
    let creator_account_keys = sandbox::gen_rotating_keys(&creator_account, 5).await?;

    let social_account = sandbox::create_account(&worker, "social", parse_near!("1000 N")).await?;
    tracing::info!(
        "Relayer accounts initialized. Relayer account: {}, Creator account: {}, Social account: {}",
        relayer_account.id(),
        creator_account.id(),
        social_account.id()
    );

    let redis = containers::Redis::run(docker_client, network).await?;
    let relayer = containers::Relayer::run(
        docker_client,
        network,
        &sandbox.address,
        &redis.address,
        relayer_account.id(),
        &relayer_account_keys,
        creator_account.id(),
        social_db.id(),
        social_account.id(),
        social_account.secret_key(),
    )
    .await?;

    Ok(RelayerCtx::<'a> {
        sandbox,
        redis,
        relayer,
        worker,
        creator_account,
        creator_account_keys,
    })
}

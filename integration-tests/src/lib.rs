use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use near_crypto::KeyFile;
use near_workspaces::{
    network::{Sandbox, ValidatorKey},
    types::SecretKey,
    Account, Worker,
};

use crate::multichain::containers::{self, LocalStack};
use near_workspaces::types::NearToken;
use testcontainers::{Container, GenericImage};

// pub mod env;
// pub mod mpc;
pub mod multichain;
pub mod sandbox;
pub mod util;

async fn fetch_from_validator(
    docker_client: &containers::DockerClient,
    container: &Container<'_, GenericImage>,
    path: &str,
) -> anyhow::Result<Vec<u8>> {
    tracing::info!(path, "fetching data from validator");
    let create_result = docker_client
        .docker
        .create_exec(
            container.id(),
            CreateExecOptions::<&str> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec!["cat", path]),
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

            tracing::info!("data fetched");
            Ok(stream_contents)
        }
        StartExecResults::Detached => unreachable!("unexpected detached output"),
    }
}

async fn fetch_validator_keys(
    docker_client: &containers::DockerClient,
    container: &Container<'_, GenericImage>,
) -> anyhow::Result<KeyFile> {
    let _span = tracing::info_span!("fetch_validator_keys");
    let key_data =
        fetch_from_validator(docker_client, container, "/root/.near/validator_key.json").await?;
    Ok(serde_json::from_slice(&key_data)?)
}

// pub struct SandboxCtx<'a> {
//     pub sandbox: containers::Sandbox<'a>,
//     pub worker: Worker<Sandbox>,
// }

// pub async fn initialize_sandbox<'a>(
//     docker_client: &'a containers::DockerClient,
//     network: &str,
// ) -> anyhow::Result<SandboxCtx<'a>> {
//     tracing::info!("initializing sandbox");
//     let sandbox = containers::Sandbox::run(docker_client, network).await?;

//     let validator_key = fetch_validator_keys(docker_client, &sandbox.container).await?;

//     tracing::info!("initializing sandbox worker");
//     let worker = near_workspaces::sandbox()
//         .rpc_addr(&sandbox.local_address)
//         .validator_key(ValidatorKey::Known(
//             validator_key.account_id.to_string().parse()?,
//             validator_key.secret_key.to_string().parse()?,
//         ))
//         .await?;

//     Ok(SandboxCtx { sandbox, worker })
// }

pub struct LakeIndexerCtx<'a> {
    pub localstack: containers::LocalStack<'a>,
    pub lake_indexer: containers::LakeIndexer<'a>,
    pub worker: Worker<Sandbox>,
}

pub async fn initialize_lake_indexer<'a>(
    docker_client: &'a containers::DockerClient,
    network: &str,
) -> anyhow::Result<LakeIndexerCtx<'a>> {
    let s3_bucket = "near-lake-custom".to_string();
    let s3_region = "us-east-1".to_string();
    let localstack =
        LocalStack::run(docker_client, network, s3_bucket.clone(), s3_region.clone()).await?;

    let lake_indexer = containers::LakeIndexer::run(
        docker_client,
        network,
        &localstack.s3_address,
        s3_bucket,
        s3_region,
    )
    .await?;

    let validator_key = fetch_validator_keys(docker_client, &lake_indexer.container).await?;

    tracing::info!("initializing sandbox worker");
    let worker = near_workspaces::sandbox()
        .rpc_addr(&lake_indexer.rpc_host_address)
        .validator_key(ValidatorKey::Known(
            validator_key.account_id.to_string().parse()?,
            validator_key.secret_key.to_string().parse()?,
        ))
        .await?;

    Ok(LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    })
}

// pub struct RelayerCtx<'a> {
//     pub sandbox: containers::Sandbox<'a>,
//     pub redis: containers::Redis<'a>,
//     pub relayer: containers::Relayer<'a>,
//     pub worker: Worker<Sandbox>,
//     pub creator_account: Account,
//     pub creator_account_keys: Vec<SecretKey>,
// }

// pub async fn initialize_relayer<'a>(
//     docker_client: &'a containers::DockerClient,
//     network: &str,
//     relayer_id: &str,
// ) -> anyhow::Result<RelayerCtx<'a>> {
//     let SandboxCtx {
//         sandbox, worker, ..
//     } = initialize_sandbox(docker_client, network).await?;

//     let social_db = sandbox::initialize_social_db(&worker).await?;
//     sandbox::initialize_linkdrop(&worker).await?;
//     tracing::info!("Initializing relayer accounts...");
//     let relayer_account =
//         sandbox::create_account(&worker, "relayer", NearToken::from_near(1000)).await?;
//     let relayer_account_keys = sandbox::gen_rotating_keys(&relayer_account, 5).await?;

//     let creator_account =
//         sandbox::create_account(&worker, "creator", NearToken::from_near(200)).await?;
//     let creator_account_keys = sandbox::gen_rotating_keys(&creator_account, 5).await?;

//     let social_account =
//         sandbox::create_account(&worker, "social", NearToken::from_near(1000)).await?;
//     tracing::info!(
//         "Relayer accounts initialized. Relayer account: {}, Creator account: {}, Social account: {}",
//         relayer_account.id(),
//         creator_account.id(),
//         social_account.id()
//     );

//     let redis = containers::Redis::run(docker_client, network).await?;
//     let relayer = containers::Relayer::run(
//         docker_client,
//         network,
//         &sandbox.address,
//         &redis.full_address,
//         relayer_account.id(),
//         &relayer_account_keys,
//         creator_account.id(),
//         social_db.id(),
//         social_account.id(),
//         social_account.secret_key(),
//         relayer_id,
//     )
//     .await?;

//     Ok(RelayerCtx::<'a> {
//         sandbox,
//         redis,
//         relayer,
//         worker,
//         creator_account,
//         creator_account_keys,
//     })
// }

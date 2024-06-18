pub mod containers;
pub mod execute;
pub mod local;
pub mod utils;

use std::collections::HashMap;

use self::local::NodeConfig;
use crate::containers::DockerClient;
use crate::containers::LocalStack;

use anyhow::Context as _;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use mpc_contract::primitives::CandidateInfo;
use mpc_recovery_node::gcp::GcpService;
use mpc_recovery_node::protocol::presignature::PresignatureConfig;
use mpc_recovery_node::protocol::triple::TripleConfig;
use mpc_recovery_node::storage;
use mpc_recovery_node::storage::triple_storage::TripleNodeStorageBox;
use near_crypto::KeyFile;
use near_workspaces::network::{Sandbox, ValidatorKey};
use near_workspaces::types::SecretKey;
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::json;
use testcontainers::{Container, GenericImage};

const NETWORK: &str = "mpc_it_network";

#[derive(Clone)]
pub struct MultichainConfig {
    pub nodes: usize,
    pub threshold: usize,
    pub triple_cfg: TripleConfig,
    pub presig_cfg: PresignatureConfig,
}

impl Default for MultichainConfig {
    fn default() -> Self {
        Self {
            nodes: 3,
            threshold: 2,
            triple_cfg: TripleConfig {
                min_triples: 8,
                max_triples: 80,
                max_concurrent_introduction: 8,
                max_concurrent_generation: 24,
            },
            presig_cfg: PresignatureConfig {
                min_presignatures: 2,
                max_presignatures: 20,
            },
        }
    }
}

pub enum Nodes<'a> {
    Local {
        ctx: Context<'a>,
        nodes: Vec<local::Node>,
    },
    Docker {
        ctx: Context<'a>,
        nodes: Vec<containers::Node<'a>>,
    },
}

impl Nodes<'_> {
    pub fn len(&self) -> usize {
        match self {
            Nodes::Local { nodes, .. } => nodes.len(),
            Nodes::Docker { nodes, .. } => nodes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn ctx(&self) -> &Context {
        match self {
            Nodes::Local { ctx, .. } => ctx,
            Nodes::Docker { ctx, .. } => ctx,
        }
    }

    pub fn url(&self, id: usize) -> &str {
        match self {
            Nodes::Local { nodes, .. } => &nodes[id].address,
            Nodes::Docker { nodes, .. } => &nodes[id].address,
        }
    }

    pub fn near_acc_sk(&self) -> HashMap<AccountId, SecretKey> {
        let mut account_to_sk = HashMap::new();
        match self {
            Nodes::Local { nodes, .. } => {
                for node in nodes {
                    account_to_sk.insert(node.account_id.clone(), node.account_sk.clone());
                }
            }
            Nodes::Docker { nodes, .. } => {
                for node in nodes {
                    account_to_sk.insert(node.account_id.clone(), node.account_sk.clone());
                }
            }
        };
        account_to_sk
    }

    pub fn near_accounts(&self) -> Vec<Account> {
        self.near_acc_sk()
            .iter()
            .map(|(account_id, account_sk)| {
                Account::from_secret_key(account_id.clone(), account_sk.clone(), &self.ctx().worker)
            })
            .collect()
    }

    pub async fn start_node(
        &mut self,
        new_node_account_id: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<()> {
        tracing::info!(%new_node_account_id, "adding one more node");
        match self {
            Nodes::Local { ctx, nodes } => {
                nodes.push(local::Node::run(ctx, new_node_account_id, account_sk, cfg).await?)
            }
            Nodes::Docker { ctx, nodes } => {
                nodes.push(containers::Node::run(ctx, new_node_account_id, account_sk, cfg).await?)
            }
        }

        Ok(())
    }

    pub async fn kill_node(&mut self, account_id: &AccountId) -> anyhow::Result<NodeConfig> {
        let killed_node_config = match self {
            Nodes::Local { nodes, .. } => {
                let (index, node) = nodes
                    .iter_mut()
                    .enumerate()
                    .find(|(_, node)| node.account_id == *account_id)
                    .unwrap();
                let node_killed = node.kill()?;
                nodes.remove(index);
                node_killed
            }
            Nodes::Docker { nodes, .. } => {
                let (index, node) = nodes
                    .iter_mut()
                    .enumerate()
                    .find(|(_, node)| node.account_id == *account_id)
                    .unwrap();
                let node_killed = node.kill();
                nodes.remove(index);
                node_killed
            }
        };

        // wait for the node to be removed from the network
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(killed_node_config)
    }

    pub async fn restart_node(&mut self, node_config: NodeConfig) -> anyhow::Result<()> {
        let account_id = node_config.account_id.clone();
        tracing::info!(%account_id, "restarting node");
        match self {
            Nodes::Local { ctx, nodes } => {
                nodes.push(local::Node::restart(ctx, node_config).await?)
            }
            Nodes::Docker { ctx, nodes } => {
                nodes.push(containers::Node::restart(ctx, node_config).await?)
            }
        }
        // wait for the node to be added to the network
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(())
    }

    pub async fn triple_storage(
        &self,
        account_id: &AccountId,
    ) -> anyhow::Result<TripleNodeStorageBox> {
        let gcp_service = GcpService::init(account_id, &self.ctx().storage_options).await?;
        Ok(storage::triple_storage::init(
            Some(&gcp_service),
            account_id,
        ))
    }

    pub async fn gcp_services(&self) -> anyhow::Result<Vec<GcpService>> {
        let mut gcp_services = Vec::new();
        match self {
            Nodes::Local { nodes, .. } => {
                for node in nodes {
                    gcp_services.push(
                        GcpService::init(&node.account_id, &self.ctx().storage_options).await?,
                    );
                }
            }
            Nodes::Docker { nodes, .. } => {
                for node in nodes {
                    gcp_services.push(
                        GcpService::init(&node.account_id, &self.ctx().storage_options).await?,
                    );
                }
            }
        }
        Ok(gcp_services)
    }
}

pub struct Context<'a> {
    pub docker_client: &'a DockerClient,
    pub docker_network: String,
    pub release: bool,

    pub localstack: crate::containers::LocalStack<'a>,
    pub lake_indexer: crate::containers::LakeIndexer<'a>,
    pub worker: Worker<Sandbox>,
    pub mpc_contract: Contract,
    pub datastore: crate::containers::Datastore<'a>,
    pub storage_options: storage::Options,
}

pub async fn setup(docker_client: &DockerClient) -> anyhow::Result<Context<'_>> {
    let release = true;
    let docker_network = NETWORK;
    docker_client.create_network(docker_network).await?;

    let LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    } = initialize_lake_indexer(docker_client, docker_network).await?;

    let mpc_contract = worker
        .dev_deploy(&std::fs::read(
            execute::target_dir()
                .context("could not find target dir")?
                .join("wasm32-unknown-unknown/release/mpc_contract.wasm"),
        )?)
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    let gcp_project_id = "multichain-integration";
    let datastore =
        crate::containers::Datastore::run(docker_client, docker_network, gcp_project_id).await?;

    let sk_share_local_path = "multichain-integration-secret-manager".to_string();
    let storage_options = mpc_recovery_node::storage::Options {
        env: "local-test".to_string(),
        gcp_project_id: "multichain-integration".to_string(),
        sk_share_secret_id: None,
        gcp_datastore_url: Some(datastore.local_address.clone()),
        sk_share_local_path: Some(sk_share_local_path),
    };
    Ok(Context {
        docker_client,
        docker_network: docker_network.to_string(),
        release,
        localstack,
        lake_indexer,
        worker,
        mpc_contract,
        datastore,
        storage_options,
    })
}

pub async fn docker(cfg: MultichainConfig, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let accounts =
        futures::future::join_all((0..cfg.nodes).map(|_| ctx.worker.dev_create_account()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
    let mut node_futures = Vec::new();
    for account in &accounts {
        let node = containers::Node::run(&ctx, account.id(), account.secret_key(), &cfg);
        node_futures.push(node);
    }
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let candidates: HashMap<AccountId, CandidateInfo> = accounts
        .iter()
        .cloned()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().to_string().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_pk.to_bytes(),
                    sign_pk: node.sign_pk.to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": candidates
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(Nodes::Docker { ctx, nodes })
}

pub async fn host(cfg: MultichainConfig, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let accounts =
        futures::future::join_all((0..cfg.nodes).map(|_| ctx.worker.dev_create_account()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
    let mut node_futures = Vec::with_capacity(cfg.nodes);
    for account in accounts.iter().take(cfg.nodes) {
        node_futures.push(local::Node::run(
            &ctx,
            account.id(),
            account.secret_key(),
            &cfg,
        ));
    }
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let candidates: HashMap<AccountId, CandidateInfo> = accounts
        .iter()
        .cloned()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().to_string().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_pk.to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": candidates
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(Nodes::Local { ctx, nodes })
}

pub async fn run(cfg: MultichainConfig, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    #[cfg(feature = "docker-test")]
    return docker(cfg, docker_client).await;

    #[cfg(not(feature = "docker-test"))]
    return host(cfg, docker_client).await;
}

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

pub struct LakeIndexerCtx<'a> {
    pub localstack: containers::LocalStack<'a>,
    pub lake_indexer: containers::LakeIndexer<'a>,
    pub worker: Worker<Sandbox>,
}

pub async fn initialize_lake_indexer<'a>(
    docker_client: &'a containers::DockerClient,
    network: &str,
) -> anyhow::Result<LakeIndexerCtx<'a>> {
    let s3_bucket = "near-lake-custom";
    let s3_region = "us-east-1";
    let localstack = LocalStack::run(docker_client, network, s3_bucket, s3_region).await?;

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

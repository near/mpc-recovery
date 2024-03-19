pub mod containers;
pub mod local;

use crate::env::containers::DockerClient;
use crate::mpc::TARGET_CONTRACT_DIR;
use crate::{initialize_lake_indexer, LakeIndexerCtx};
use mpc_contract::primitives::CandidateInfo;
use mpc_recovery_node::gcp::GcpService;
use mpc_recovery_node::protocol::triple::TripleConfig;
use mpc_recovery_node::storage;
use mpc_recovery_node::storage::triple_storage::TripleNodeStorageBox;
use near_workspaces::network::Sandbox;
use near_workspaces::{AccountId, Contract, Worker};
use serde_json::json;
use std::collections::HashMap;

const NETWORK: &str = "mpc_it_network";

#[derive(Clone)]
pub struct MultichainConfig {
    pub nodes: usize,
    pub triple_cfg: TripleConfig,
}

impl Default for MultichainConfig {
    fn default() -> Self {
        Self {
            nodes: 3,
            triple_cfg: TripleConfig {
                min_triples: 2,
                max_triples: 10,
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

    pub async fn add_node(
        &mut self,
        account: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<()> {
        tracing::info!(%account, "adding one more node");
        match self {
            Nodes::Local { ctx, nodes } => {
                nodes.push(local::Node::run(ctx, account, account_sk, cfg).await?)
            }
            Nodes::Docker { ctx, nodes } => {
                nodes.push(containers::Node::run(ctx, account, account_sk, cfg).await?)
            }
        }

        Ok(())
    }

    pub async fn kill_node(&mut self, index: usize) -> anyhow::Result<()> {
        match self {
            Nodes::Local { nodes, .. } => {
                nodes[index].kill()?;
                nodes.remove(index);
            }
            Nodes::Docker { nodes, .. } => {
                nodes[index].kill();
                nodes.remove(index);
            }
        }

        // wait for the node to be removed from the network
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(())
    }

    pub async fn triple_storage(&self, account_id: String) -> anyhow::Result<TripleNodeStorageBox> {
        let gcp_service = GcpService::init(&account_id, &self.ctx().storage_options).await?;
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

    pub localstack: crate::env::containers::LocalStack<'a>,
    pub lake_indexer: crate::env::containers::LakeIndexer<'a>,
    pub worker: Worker<Sandbox>,
    pub mpc_contract: Contract,
    pub datastore: crate::env::containers::Datastore<'a>,
    pub storage_options: storage::Options,
}

pub async fn setup(docker_client: &DockerClient) -> anyhow::Result<Context<'_>> {
    if !crate::mpc::build_multichain_contract().await?.success() {
        anyhow::bail!("failed to prebuild multichain contract");
    }

    let release = true;
    if !crate::mpc::build_multichain(release).await?.success() {
        anyhow::bail!("failed to prebuild multichain node service");
    }

    let docker_network = NETWORK;
    docker_client.create_network(docker_network).await?;

    let LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    } = initialize_lake_indexer(docker_client, docker_network).await?;

    let mpc_contract = worker
        .dev_deploy(&std::fs::read(format!(
            "{}/wasm32-unknown-unknown/release/mpc_contract.wasm",
            TARGET_CONTRACT_DIR
        ))?)
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    let gcp_project_id = "multichain-integration";
    let datastore =
        crate::env::containers::Datastore::run(docker_client, docker_network, gcp_project_id)
            .await?;

    let storage_options = mpc_recovery_node::storage::Options {
        env: "local-test".to_string(),
        gcp_project_id: "multichain-integration".to_string(),
        sk_share_secret_id: None,
        gcp_datastore_url: Some(datastore.local_address.clone()),
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
            "threshold": 2,
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
                    sign_pk: node.account_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": 2,
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

pub mod containers;
pub mod local;

use crate::env::containers::DockerClient;
use crate::{initialize_sandbox, SandboxCtx};
use mpc_contract::ParticipantInfo;
use near_workspaces::network::Sandbox;
use near_workspaces::{AccountId, Contract, Worker};
use serde_json::json;
use std::collections::HashMap;

const NETWORK: &str = "mpc_it_network";

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
        node_id: u32,
        account: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
    ) -> anyhow::Result<()> {
        tracing::info!(%account, "adding one more node");
        match self {
            Nodes::Local { ctx, nodes } => {
                nodes.push(local::Node::run(ctx, node_id, account, account_sk).await?)
            }
            Nodes::Docker { ctx, nodes } => {
                nodes.push(containers::Node::run(ctx, node_id, account, account_sk).await?)
            }
        }

        Ok(())
    }
}

pub struct Context<'a> {
    pub docker_client: &'a DockerClient,
    pub docker_network: String,
    pub release: bool,

    pub sandbox: crate::env::containers::Sandbox<'a>,
    pub worker: Worker<Sandbox>,
    pub mpc_contract: Contract,
}

pub async fn setup(docker_client: &DockerClient) -> anyhow::Result<Context<'_>> {
    let docker_network = NETWORK;
    docker_client.create_network(docker_network).await?;

    let SandboxCtx { sandbox, worker } = initialize_sandbox(docker_client, NETWORK).await?;

    let mpc_contract = worker
        .dev_deploy(include_bytes!(
            "../../../target/wasm32-unknown-unknown/release/mpc_contract.wasm"
        ))
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    Ok(Context {
        docker_client,
        docker_network: docker_network.to_string(),
        release: true,
        sandbox,
        worker,
        mpc_contract,
    })
}

pub async fn docker(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let accounts = futures::future::join_all((0..nodes).map(|_| ctx.worker.dev_create_account()))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut node_futures = Vec::new();
    for (i, account) in accounts.iter().enumerate() {
        let node = containers::Node::run(&ctx, i as u32, account.id(), account.secret_key());
        node_futures.push(node);
    }
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let participants: HashMap<AccountId, ParticipantInfo> = accounts
        .iter()
        .cloned()
        .enumerate()
        .zip(&nodes)
        .map(|((i, account), node)| {
            (
                account.id().clone(),
                ParticipantInfo {
                    id: i as u32,
                    account_id: account.id().to_string().parse().unwrap(),
                    url: node.address.clone(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": 2,
            "participants": participants
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(Nodes::Docker { ctx, nodes })
}

pub async fn host(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let accounts = futures::future::join_all((0..nodes).map(|_| ctx.worker.dev_create_account()))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut node_futures = Vec::with_capacity(nodes);
    for (i, account) in accounts.iter().enumerate().take(nodes) {
        node_futures.push(local::Node::run(
            &ctx,
            i as u32,
            account.id(),
            account.secret_key(),
        ));
    }
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let participants: HashMap<AccountId, ParticipantInfo> = accounts
        .iter()
        .cloned()
        .enumerate()
        .zip(&nodes)
        .map(|((i, account), node)| {
            (
                account.id().clone(),
                ParticipantInfo {
                    id: i as u32,
                    account_id: account.id().to_string().parse().unwrap(),
                    url: node.address.clone(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": 2,
            "participants": participants
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(Nodes::Local { ctx, nodes })
}

pub async fn run(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    #[cfg(feature = "docker-test")]
    return docker(nodes, docker_client).await;

    #[cfg(not(feature = "docker-test"))]
    return host(nodes, docker_client).await;
}

use crate::{mpc, util};
use async_process::Child;
use near_workspaces::AccountId;

#[allow(dead_code)]
pub struct Node {
    pub address: String,
    node_id: usize,
    account: AccountId,
    account_sk: near_workspaces::types::SecretKey,

    // process held so it's not dropped. Once dropped, process will be killed.
    #[allow(unused)]
    process: Child,
}

impl Node {
    pub async fn run(
        ctx: &super::Context<'_>,
        node_id: u32,
        account: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
    ) -> anyhow::Result<Self> {
        let web_port = util::pick_unused_port().await?;
        let cli = mpc_recovery_node::cli::Cli::Start {
            node_id: node_id.into(),
            near_rpc: ctx.lake_indexer.rpc_host_address.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account: account.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port,
            indexer_options: mpc_recovery_node::indexer::Options {
                s3_bucket: ctx.localstack.s3_host_address.clone(),
                s3_region: ctx.localstack.s3_region.clone(),
                start_block_height: 0,
            },
        };

        let mpc_node_id = format!("multichain/{node_id}");
        let process = mpc::spawn_multichain(ctx.release, &mpc_node_id, cli)?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {}", address);
        util::ping_until_ok(&address, 60).await?;
        tracing::info!("node started [node_id={node_id}, {address}]");

        Ok(Self {
            address,
            node_id: node_id as usize,
            account: account.clone(),
            account_sk: account_sk.clone(),
            process,
        })
    }
}

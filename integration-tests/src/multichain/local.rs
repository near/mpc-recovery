use crate::{mpc, util};
use async_process::Child;
use mpc_keys::hpke;
use near_workspaces::AccountId;

#[allow(dead_code)]
pub struct Node {
    pub address: String,
    node_id: usize,
    account: AccountId,
    pub account_sk: near_workspaces::types::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    cipher_sk: hpke::SecretKey,

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
        let (cipher_sk, cipher_pk) = hpke::generate();
        let cli = mpc_recovery_node::cli::Cli::Start {
            node_id: node_id.into(),
            near_rpc: ctx.lake_indexer.rpc_host_address.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account: account.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            indexer_options: mpc_recovery_node::indexer::Options {
                s3_bucket: ctx.localstack.s3_bucket.clone(),
                s3_region: ctx.localstack.s3_region.clone(),
                s3_url: Some(ctx.localstack.s3_host_address.clone()),
                start_block_height: 0,
            },
            my_address: None,
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
            cipher_pk,
            cipher_sk,
            process,
        })
    }
}

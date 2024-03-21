use crate::{mpc, util};
use async_process::Child;
use mpc_keys::hpke;
use mpc_recovery_node::storage;
use near_workspaces::AccountId;

use super::MultichainConfig;

#[allow(dead_code)]
pub struct Node {
    pub address: String,
    pub account_id: AccountId,
    pub account_sk: near_workspaces::types::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    cipher_sk: hpke::SecretKey,
    storage_options: storage::Options,

    // process held so it's not dropped. Once dropped, process will be killed.
    process: Child,
}

impl Node {
    pub async fn run(
        ctx: &super::Context<'_>,
        account_id: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<Self> {
        let web_port = util::pick_unused_port().await?;
        let (cipher_sk, cipher_pk) = hpke::generate();
        let storage_options = ctx.storage_options.clone();
        let cli = mpc_recovery_node::cli::Cli::Start {
            near_rpc: ctx.lake_indexer.rpc_host_address.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: account_id.clone(),
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
            storage_options: storage_options.clone(),
            min_triples: cfg.triple_cfg.min_triples,
            max_triples: cfg.triple_cfg.max_triples,
            max_concurrent_introduction: cfg.triple_cfg.max_concurrent_introduction,
            max_concurrent_generation: cfg.triple_cfg.max_concurrent_generation,
            min_presignatures: cfg.presig_cfg.min_presignatures,
            max_presignatures: cfg.presig_cfg.max_presignatures,
        };

        let mpc_node_id = format!("multichain/{account_id}", account_id = account_id);
        let process = mpc::spawn_multichain(ctx.release, &mpc_node_id, cli)?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {}", address);
        util::ping_until_ok(&address, 60).await?;
        tracing::info!("node started [node_account_id={account_id}, {address}]");

        Ok(Self {
            address,
            account_id: account_id.clone(),
            account_sk: account_sk.clone(),
            cipher_pk,
            cipher_sk,
            storage_options,
            process,
        })
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        self.process.kill()?;
        tracing::info!(?self.account_id, ?self.address, "node killed");
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill().unwrap();
    }
}

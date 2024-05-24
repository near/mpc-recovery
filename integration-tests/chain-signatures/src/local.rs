use crate::{execute, utils, MultichainConfig};

use async_process::Child;
use mpc_keys::hpke;
use near_workspaces::AccountId;

#[allow(dead_code)]
pub struct Node {
    pub address: String,
    pub account_id: AccountId,
    pub account_sk: near_workspaces::types::SecretKey,
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    cipher_sk: hpke::SecretKey,
    cfg: MultichainConfig,
    web_port: u16,

    // process held so it's not dropped. Once dropped, process will be killed.
    process: Child,
}

pub struct NodeConfig {
    pub web_port: u16,
    pub account_id: AccountId,
    pub account_sk: near_workspaces::types::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    pub cipher_sk: hpke::SecretKey,
    pub cfg: MultichainConfig,
}

impl Node {
    pub async fn run(
        ctx: &super::Context<'_>,
        account_id: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<Self> {
        let web_port = utils::pick_unused_port().await?;
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");

        let storage_options = ctx.storage_options.clone();
        let indexer_options = mpc_recovery_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
        };
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let cli = mpc_recovery_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            sign_sk: Some(sign_sk.clone()),
            indexer_options: indexer_options.clone(),
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
        let process = execute::spawn_multichain(ctx.release, &mpc_node_id, cli)?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {}", address);
        utils::ping_until_ok(&address, 60).await?;
        tracing::info!("node started [node_account_id={account_id}, {address}]");

        Ok(Self {
            address,
            account_id: account_id.clone(),
            account_sk: account_sk.clone(),
            sign_sk,
            cipher_pk,
            cipher_sk,
            cfg: cfg.clone(),
            web_port,
            process,
        })
    }

    pub async fn restart(ctx: &super::Context<'_>, config: NodeConfig) -> anyhow::Result<Self> {
        let web_port = config.web_port;
        let cipher_pk = config.cipher_pk;
        let cipher_sk = config.cipher_sk;
        let cfg = config.cfg;
        let account_id = config.account_id;
        let account_sk = config.account_sk;
        let storage_options = ctx.storage_options.clone();
        let indexer_options = mpc_recovery_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
        };
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let cli = mpc_recovery_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            sign_sk: Some(sign_sk.clone()),
            indexer_options: indexer_options.clone(),
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
        let process = execute::spawn_multichain(ctx.release, &mpc_node_id, cli)?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {}", address);
        utils::ping_until_ok(&address, 60).await?;
        tracing::info!("node started [node_account_id={account_id}, {address}]");

        Ok(Self {
            address,
            account_id,
            account_sk,
            sign_sk,
            cipher_pk,
            cipher_sk,
            cfg,
            web_port,
            process,
        })
    }

    pub fn kill(&mut self) -> std::io::Result<NodeConfig> {
        self.process.kill()?;
        tracing::info!(?self.account_id, ?self.address, "node killed");
        Ok(NodeConfig {
            web_port: self.web_port,
            account_id: self.account_id.clone(),
            account_sk: self.account_sk.clone(),
            cipher_pk: self.cipher_pk.clone(),
            cipher_sk: self.cipher_sk.clone(),
            cfg: self.cfg.clone(),
        })
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill().unwrap();
    }
}

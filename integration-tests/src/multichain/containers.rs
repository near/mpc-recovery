use ed25519_dalek::ed25519::signature::digest::{consts::U32, generic_array::GenericArray};
use mpc_keys::hpke;
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_workspaces::AccountId;
use testcontainers::{
    core::{ExecCommand, WaitFor},
    Container, GenericImage, RunnableImage,
};
use tracing;

use super::MultichainConfig;

pub struct Node<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub account_id: AccountId,
    pub local_address: String,
    pub cipher_pk: hpke::PublicKey,
    pub cipher_sk: hpke::SecretKey,
    pub sign_pk: near_workspaces::types::PublicKey,
}

pub struct NodeApi {
    pub address: String,
    pub node_id: usize,
    pub sk_share: ExpandedKeyPair,
    pub cipher_key: GenericArray<u8, U32>,
    pub gcp_project_id: String,
    pub gcp_datastore_local_url: String,
}

impl<'a> Node<'a> {
    // Container port used for the docker network, does not have to be unique
    const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        ctx: &super::Context<'a>,
        account_id: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<Node<'a>> {
        tracing::info!("running node container, account_id={}", account_id);
        let (cipher_sk, cipher_pk) = hpke::generate();
        let storage_options = ctx.storage_options.clone();
        let args = mpc_recovery_node::cli::Cli::Start {
            near_rpc: ctx.lake_indexer.rpc_host_address.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: Self::CONTAINER_PORT,
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
        }
        .into_str_args();
        let image: GenericImage = GenericImage::new("near/mpc-recovery-node", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery_node=DEBUG")
            .with_env_var("RUST_BACKTRACE", "1");
        let image: RunnableImage<GenericImage> = (image, args).into();
        let image = image.with_network(&ctx.docker_network);
        let container = ctx.docker_client.cli.run(image);
        let ip_address = ctx
            .docker_client
            .get_network_ip_address(&container, &ctx.docker_network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            full_address,
            "node container is running, account_id={}",
            account_id
        );
        Ok(Node {
            container,
            address: full_address,
            account_id: account_id.clone(),
            local_address: format!("http://localhost:{host_port}"),
            cipher_pk,
            cipher_sk,
            sign_pk: account_sk.public_key(),
        })
    }

    pub fn kill(&self) {
        self.container.stop();
    }
}

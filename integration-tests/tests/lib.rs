mod containers;
// mod docker;
mod mpc;
mod sandbox;

use containers::{LeaderNodeApi, SignerNodeApi};
use curv::elliptic::curves::{Ed25519, Point};
use futures::future::BoxFuture;
use mpc_recovery::GenerateResult;
use near_units::parse_near;
use std::time::Duration;
use workspaces::{network::Sandbox, Worker};

const NETWORK: &str = "mpc_recovery_integration_test_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-gcp-project";
// TODO: figure out how to instantiate an use a local firebase deployment
const FIREBASE_AUDIENCE_ID: &str = "not actually used in integration tests";
#[cfg(target_os = "linux")]
const HOST_MACHINE_FROM_DOCKER: &str = "172.17.0.1";
#[cfg(target_os = "macos")]
const HOST_MACHINE_FROM_DOCKER: &str = "docker.for.mac.localhost";

pub struct TestContext<'a> {
    leader_node: &'a LeaderNodeApi,
    _pk_set: &'a Vec<Point<Ed25519>>,
    worker: &'a Worker<Sandbox>,
    signer_nodes: &'a Vec<SignerNodeApi>,
}

async fn with_nodes<F>(nodes: usize, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(TestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let worker = workspaces::sandbox().await?;
    let social_db = sandbox::initialize_social_db(&worker).await?;
    sandbox::initialize_linkdrop(&worker).await?;
    let (relayer_account_id, relayer_account_sk) = sandbox::create_account(&worker).await?;
    let (creator_account_id, creator_account_sk) = sandbox::create_account(&worker).await?;
    let (social_account_id, social_account_sk) = sandbox::create_account(&worker).await?;
    sandbox::up_funds_for_account(&worker, &social_account_id, parse_near!("100 N")).await?;

    let docker_client = containers::DockerClient::default();
    let datastore = containers::Datastore::run(&docker_client, NETWORK, GCP_PROJECT_ID).await?;
    let redis = containers::Redis::run(&docker_client, NETWORK).await?;
    let near_rpc = format!("http://{HOST_MACHINE_FROM_DOCKER}:{}", worker.rpc_port());
    let relayer = containers::Relayer::run(
        &docker_client,
        NETWORK,
        &near_rpc,
        &redis.address,
        &relayer_account_id,
        &relayer_account_sk,
        &creator_account_id,
        &social_db.id(),
        &social_account_id,
        &social_account_sk,
    )
    .await?;

    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_nodes = Vec::new();
    for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
        let signer_node = containers::SignerNode::run(
            &docker_client,
            NETWORK,
            i as u64,
            share,
            cipher_key,
            &datastore.address,
            GCP_PROJECT_ID,
            FIREBASE_AUDIENCE_ID,
        )
        .await?;
        signer_nodes.push(signer_node);
    }
    let signer_urls: &Vec<_> = &signer_nodes.iter().map(|n| n.address.clone()).collect();

    let near_root_account = worker.root_account()?;
    let leader_node = containers::LeaderNode::run(
        &docker_client,
        NETWORK,
        signer_urls.clone(),
        &near_rpc,
        &relayer.address,
        &datastore.address,
        GCP_PROJECT_ID,
        near_root_account.id(),
        &creator_account_id,
        &creator_account_sk,
        FIREBASE_AUDIENCE_ID,
    )
    .await?;

    // Wait until all nodes initialize
    // TODO: proper wait condition
    tokio::time::sleep(Duration::from_millis(10000)).await;

    f(TestContext {
        leader_node: &leader_node.api(),
        _pk_set: &pk_set,
        signer_nodes: &signer_nodes.iter().map(|n| n.api()).collect(),
        worker: &worker,
    })
    .await
}

mod account {
    use rand::{distributions::Alphanumeric, Rng};
    use workspaces::{network::Sandbox, AccountId, Worker};

    pub fn random(worker: &Worker<Sandbox>) -> anyhow::Result<AccountId> {
        let account_id_rand: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        Ok(format!(
            "mpc-recovery-{}.{}",
            account_id_rand.to_lowercase(),
            worker.root_account()?.id()
        )
        .parse()?)
    }

    pub fn malformed() -> String {
        let random: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        format!("malformed-account-{}-!@#$%", random.to_lowercase())
    }
}

mod key {
    use rand::{distributions::Alphanumeric, Rng};

    pub fn random() -> String {
        near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519)
            .public_key()
            .to_string()
    }

    #[allow(dead_code)]
    pub fn malformed() -> String {
        let random: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        format!("malformed-key-{}-!@#$%", random.to_lowercase())
    }
}

mod token {
    use rand::{distributions::Alphanumeric, Rng};

    pub fn valid_random() -> String {
        let random: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        format!("validToken:{}", random)
    }

    pub fn invalid() -> String {
        "invalidToken".to_string()
    }
}

mod check {
    use crate::TestContext;
    use workspaces::AccountId;

    pub async fn access_key_exists(
        ctx: &TestContext<'_>,
        account_id: &AccountId,
        public_key: &str,
    ) -> anyhow::Result<()> {
        let access_keys = ctx.worker.view_access_keys(account_id).await?;

        if access_keys
            .iter()
            .any(|ak| ak.public_key.to_string() == public_key)
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "could not find access key {public_key} on account {account_id}"
            ))
        }
    }

    pub async fn no_account(ctx: &TestContext<'_>, account_id: &AccountId) -> anyhow::Result<()> {
        if ctx.worker.view_account(account_id).await.is_err() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "expected account {account_id} to not exist, but it does"
            ))
        }
    }
}

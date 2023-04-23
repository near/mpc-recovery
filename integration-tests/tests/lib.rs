mod docker;
mod mpc;

use crate::docker::{LeaderNode, SignNode};
use bollard::Docker;
use docker::{datastore::Datastore, redis::Redis, relayer::Relayer};
use futures::future::BoxFuture;
use std::time::Duration;
use threshold_crypto::PublicKeySet;
use workspaces::{network::Sandbox, AccountId, Worker};

const NETWORK: &str = "mpc_recovery_integration_test_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-gcp-project";
#[cfg(target_os = "linux")]
const HOST_MACHINE_FROM_DOCKER: &str = "172.17.0.1";
#[cfg(target_os = "macos")]
const HOST_MACHINE_FROM_DOCKER: &str = "docker.for.mac.localhost";

pub struct TestContext<'a> {
    leader_node: &'a LeaderNode,
    pk_set: &'a PublicKeySet,
    worker: &'a Worker<Sandbox>,
}

async fn create_account(
    worker: &Worker<Sandbox>,
) -> anyhow::Result<(AccountId, near_crypto::SecretKey)> {
    let (account_id, account_sk) = worker.dev_generate().await;
    worker
        .create_tla(account_id.clone(), account_sk.clone())
        .await?
        .into_result()?;

    let account_sk: near_crypto::SecretKey =
        serde_json::from_str(&serde_json::to_string(&account_sk)?)?;

    Ok((account_id, account_sk))
}

async fn with_nodes<F>(shares: usize, threshold: usize, nodes: usize, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(TestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker = Docker::connect_with_local_defaults()?;

    let (pk_set, sk_shares) = mpc_recovery::generate(shares, threshold)?;
    let worker = workspaces::sandbox().await?;
    let near_root_account = worker.root_account()?;
    near_root_account
        .deploy(include_bytes!("../linkdrop.wasm"))
        .await?
        .into_result()?;
    near_root_account
        .call(near_root_account.id(), "new")
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    let (relayer_account_id, relayer_account_sk) = create_account(&worker).await?;
    let (creator_account_id, creator_account_sk) = create_account(&worker).await?;

    let near_rpc = format!("http://{HOST_MACHINE_FROM_DOCKER}:{}", worker.rpc_port());
    let datastore = Datastore::start(&docker, NETWORK, GCP_PROJECT_ID).await?;
    let redis = Redis::start(&docker, NETWORK).await?;
    let relayer = Relayer::start(
        &docker,
        NETWORK,
        &near_rpc,
        &redis.hostname,
        &relayer_account_id,
        &relayer_account_sk,
        &creator_account_id,
    )
    .await?;

    let mut sign_nodes = Vec::new();
    for i in 2..=nodes {
        let addr = SignNode::start(&docker, NETWORK, i as u64, &pk_set, &sk_shares[i - 1]).await?;
        sign_nodes.push(addr);
    }
    let leader_node = LeaderNode::start(
        &docker,
        NETWORK,
        1,
        &pk_set,
        &sk_shares[0],
        sign_nodes.iter().map(|n| n.address.clone()).collect(),
        &near_rpc,
        &relayer.address,
        &datastore.address,
        GCP_PROJECT_ID,
        near_root_account.id(),
        &creator_account_id,
        &creator_account_sk,
    )
    .await?;

    // Wait until all nodes initialize
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let result = f(TestContext {
        leader_node: &leader_node,
        pk_set: &pk_set,
        worker: &worker,
    })
    .await;

    drop(datastore);
    drop(leader_node);
    drop(sign_nodes);
    drop(relayer);
    drop(redis);

    // Wait until all docker containers are destroyed.
    // See `Drop` impl for `LeaderNode` and `SignNode` for more info.
    tokio::time::sleep(Duration::from_millis(2000)).await;

    result
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
    pub fn valid() -> String {
        "validToken".to_string()
    }

    pub fn invalid() -> String {
        "invalidToken".to_string()
    }
}

mod check {
    use crate::TestContext;
    use workspaces::AccountId;

    pub async fn access_key_exists<'a>(
        ctx: &TestContext<'a>,
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

    pub async fn no_account<'a>(
        ctx: &TestContext<'a>,
        account_id: &AccountId,
    ) -> anyhow::Result<()> {
        if ctx.worker.view_account(account_id).await.is_err() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "expected account {account_id} to not exist, but it does"
            ))
        }
    }
}

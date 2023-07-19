mod mpc;

use curv::elliptic::curves::{Ed25519, Point};
use futures::future::BoxFuture;
use mpc_recovery::gcp::GcpService;
use mpc_recovery::GenerateResult;
use mpc_recovery::sign_node::user_credentials::EncryptedUserCredentials;
use mpc_recovery_integration_tests::containers;
use workspaces::{network::Sandbox, Worker};

const NETWORK: &str = "mpc_it_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-gcp-project";
// TODO: figure out how to instantiate an use a local firebase deployment
const FIREBASE_AUDIENCE_ID: &str = "not actually used in integration tests";

pub struct TestContext<'a> {
    leader_node: &'a containers::LeaderNodeApi,
    pk_set: &'a Vec<Point<Ed25519>>,
    worker: &'a Worker<Sandbox>,
    signer_nodes: &'a Vec<containers::SignerNodeApi>,
}

async fn with_nodes<F>(nodes: usize, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(TestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker_client = containers::DockerClient::default();

    let relayer_ctx_future =
        mpc_recovery_integration_tests::initialize_relayer(&docker_client, NETWORK);
    let datastore_future = containers::Datastore::run(&docker_client, NETWORK, GCP_PROJECT_ID);

    let (relayer_ctx, datastore) =
        futures::future::join(relayer_ctx_future, datastore_future).await;
    let relayer_ctx = relayer_ctx?;
    let datastore = datastore?;

    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_node_futures = Vec::new();
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
        );
        signer_node_futures.push(signer_node);
    }
    let signer_nodes = futures::future::join_all(signer_node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let signer_urls: &Vec<_> = &signer_nodes.iter().map(|n| n.address.clone()).collect();

    let near_root_account = relayer_ctx.worker.root_account()?;
    let leader_node = containers::LeaderNode::run(
        &docker_client,
        NETWORK,
        signer_urls.clone(),
        &relayer_ctx.sandbox.address,
        &relayer_ctx.relayer.address,
        &datastore.address,
        GCP_PROJECT_ID,
        near_root_account.id(),
        &relayer_ctx.creator_account_id,
        &relayer_ctx.creator_account_sk,
        FIREBASE_AUDIENCE_ID,
    )
    .await?;

    f(TestContext {
        leader_node: &leader_node.api(&relayer_ctx.sandbox.address, &relayer_ctx.relayer.address),
        pk_set: &pk_set,
        signer_nodes: &signer_nodes.iter().map(|n| n.api()).collect(),
        worker: &relayer_ctx.worker,
    })
    .await?;

    // let gcp_service =
    //     GcpService::new("dev".into(), GCP_PROJECT_ID.into(), Some(datastore.address)).await?;

    // gcp_service.fetch_entities::<EncryptedUserCredentials>().await?;


    // use google_datastore1::api::{KindExpression, Query, RunQueryRequest};

    // let kind: String = "EncryptedUserCredentials-dev".to_string();
    // let req = RunQueryRequest {
    //     database_id: Some("".to_string()),
    //     partition_id: Default::default(),
    //     read_options: Default::default(),
    //     query: Some(Query {
    //         projection: None,
    //         kind: Some(vec![KindExpression { name: Some(kind) }]),
    //         filter: None,
    //         order: None,
    //         distinct_on: Some(vec![]),
    //         start_cursor: None,
    //         end_cursor: None,
    //         offset: None,
    //         limit: None,
    //     }),
    //     gql_query: None,
    // };

    // let query = datastore.projects().run_query(req, GCP_PROJECT_ID);

    Ok(())
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

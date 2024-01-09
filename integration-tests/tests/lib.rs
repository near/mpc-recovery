mod mpc;
mod multichain;

use curv::elliptic::curves::{Ed25519, Point};
use futures::future::BoxFuture;
use hyper::StatusCode;
use mpc_recovery::{
    gcp::GcpService,
    msg::{
        ClaimOidcResponse, MpcPkResponse, NewAccountResponse, SignResponse, UserCredentialsResponse,
    },
};
use mpc_recovery_integration_tests::env::containers::DockerClient;
use mpc_recovery_integration_tests::indexer::FullSignature;
use mpc_recovery_integration_tests::{env, indexer};
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::hash::CryptoHash;
use near_workspaces::{network::Sandbox, Worker};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use tokio::sync::RwLock;

pub struct TestContext {
    env: String,
    leader_node: env::LeaderNodeApi,
    pk_set: Vec<Point<Ed25519>>,
    worker: Worker<Sandbox>,
    signer_nodes: Vec<env::SignerNodeApi>,
    gcp_project_id: String,
    gcp_datastore_url: String,
}

impl TestContext {
    pub async fn gcp_service(&self) -> anyhow::Result<GcpService> {
        GcpService::new(
            self.env.clone(),
            self.gcp_project_id.clone(),
            Some(self.gcp_datastore_url.clone()),
        )
        .await
    }
}

async fn with_nodes<Task, Fut, Val>(nodes: usize, f: Task) -> anyhow::Result<()>
where
    Task: FnOnce(TestContext) -> Fut,
    Fut: core::future::Future<Output = anyhow::Result<Val>>,
{
    let docker_client = DockerClient::default();
    let nodes = env::run(nodes, &docker_client).await?;

    f(TestContext {
        env: nodes.ctx().env.clone(),
        pk_set: nodes.pk_set(),
        leader_node: nodes.leader_api(),
        signer_nodes: nodes.signer_apis(),
        worker: nodes.ctx().relayer_ctx.worker.clone(),
        gcp_project_id: nodes.ctx().gcp_project_id.clone(),
        gcp_datastore_url: nodes.datastore_addr(),
    })
    .await?;

    nodes.ctx().relayer_ctx.relayer.clean_tmp_files()?;

    Ok(())
}

pub struct MultichainTestContext<'a> {
    nodes: mpc_recovery_integration_tests::multichain::Nodes<'a>,
    rpc_client: near_fetch::Client,
    jsonrpc_client: JsonRpcClient,
    http_client: reqwest::Client,
    responses: Arc<RwLock<HashMap<CryptoHash, FullSignature>>>,
}

async fn with_multichain_nodes<F>(nodes: usize, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(MultichainTestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker_client = DockerClient::default();
    let nodes = mpc_recovery_integration_tests::multichain::run(nodes, &docker_client).await?;

    let s3_bucket = nodes.ctx().localstack.s3_bucket.clone();
    let s3_region = nodes.ctx().localstack.s3_region.clone();
    let s3_url = nodes.ctx().localstack.s3_host_address.clone();
    let mpc_contract_id = nodes.ctx().mpc_contract.id().clone();
    let responses = Arc::new(RwLock::new(HashMap::new()));
    let responses_clone = responses.clone();
    thread::spawn(move || {
        indexer::run(
            &s3_bucket,
            &s3_region,
            0,
            &s3_url,
            mpc_contract_id,
            responses_clone,
        )
        .unwrap();
    });

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());
    f(MultichainTestContext {
        nodes,
        rpc_client,
        jsonrpc_client,
        http_client: reqwest::Client::default(),
        responses,
    })
    .await?;

    Ok(())
}

mod account {
    use near_workspaces::{network::Sandbox, AccountId, Worker};
    use rand::{distributions::Alphanumeric, Rng};

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
    use near_crypto::{PublicKey, SecretKey};
    use rand::{distributions::Alphanumeric, Rng};

    pub fn random() -> (SecretKey, PublicKey) {
        let sk = random_sk();
        let pk = sk.public_key();
        (sk, pk)
    }

    pub fn random_sk() -> SecretKey {
        near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519)
    }

    pub fn random_pk() -> PublicKey {
        near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519).public_key()
    }

    #[allow(dead_code)]
    pub fn malformed_pk() -> String {
        let random: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        format!("malformed-key-{}-!@#$%", random.to_lowercase())
    }
}

mod check {
    use crate::TestContext;
    use near_crypto::PublicKey;
    use near_workspaces::AccountId;

    pub async fn access_key_exists(
        ctx: &TestContext,
        account_id: &AccountId,
        public_key: &PublicKey,
    ) -> anyhow::Result<()> {
        let access_keys = ctx.worker.view_access_keys(account_id).await?;

        if access_keys
            .iter()
            .any(|ak| ak.public_key.key_data() == public_key.key_data())
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "could not find access key {public_key} on account {account_id}"
            ))
        }
    }

    pub async fn access_key_does_not_exists(
        ctx: &TestContext,
        account_id: &AccountId,
        public_key: &str,
    ) -> anyhow::Result<()> {
        let access_keys = ctx.worker.view_access_keys(account_id).await?;

        if access_keys
            .iter()
            .any(|ak| ak.public_key.to_string() == public_key)
        {
            Err(anyhow::anyhow!(
                "Access key {public_key} still added to the account {account_id}"
            ))
        } else {
            Ok(())
        }
    }
}

mod wait_for {
    use crate::MultichainTestContext;
    use anyhow::Context;
    use backon::ExponentialBuilder;
    use backon::Retryable;
    use mpc_contract::ProtocolContractState;
    use mpc_contract::RunningContractState;
    use mpc_recovery_integration_tests::indexer::FullSignature;
    use mpc_recovery_node::web::StateView;
    use near_primitives::hash::CryptoHash;

    pub async fn running_mpc<'a>(
        ctx: &MultichainTestContext<'a>,
        epoch: u64,
    ) -> anyhow::Result<RunningContractState> {
        let is_running = || async {
            let state: ProtocolContractState = ctx
                .rpc_client
                .view(ctx.nodes.ctx().mpc_contract.id(), "state", ())
                .await?;

            match state {
                ProtocolContractState::Running(running) if running.epoch >= epoch => Ok(running),
                ProtocolContractState::Running(running) => {
                    anyhow::bail!("running with an older epoch: {}", running.epoch)
                }
                _ => anyhow::bail!("not running"),
            }
        };
        is_running
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc nodes did not reach epoch '{epoch}' before deadline"))
    }

    pub async fn has_at_least_triples<'a>(
        ctx: &MultichainTestContext<'a>,
        id: usize,
        expected_triple_count: usize,
    ) -> anyhow::Result<StateView> {
        let is_enough_triples = || async {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running { triple_count, .. }
                    if triple_count >= expected_triple_count =>
                {
                    Ok(state_view)
                }
                StateView::Running { .. } => anyhow::bail!("node does not have enough triples yet"),
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        };
        is_enough_triples
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_triple_count}' triples before deadline"))
    }

    pub async fn has_at_least_presignatures<'a>(
        ctx: &MultichainTestContext<'a>,
        id: usize,
        expected_presignature_count: usize,
    ) -> anyhow::Result<StateView> {
        let is_enough_presignatures = || async {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running {
                    presignature_count, ..
                } if presignature_count >= expected_presignature_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough presignatures yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        };
        is_enough_presignatures
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_presignature_count}' presignatures before deadline"))
    }

    pub async fn has_response<'a>(
        ctx: &MultichainTestContext<'a>,
        receipt_id: CryptoHash,
    ) -> anyhow::Result<FullSignature> {
        let is_enough_presignatures = || async {
            let mut responses = ctx.responses.write().await;
            if let Some(signature) = responses.remove(&receipt_id) {
                return Ok(signature);
            }
            drop(responses);
            anyhow::bail!("mpc has not responded yet")
        };
        is_enough_presignatures
            .retry(&ExponentialBuilder::default().with_max_times(8))
            .await
            .with_context(|| {
                format!("mpc failed to respond to receipt id '{receipt_id}' before deadline")
            })
    }
}

trait MpcCheck {
    type Response;

    fn assert_ok(self) -> anyhow::Result<Self::Response>;
    fn assert_bad_request_contains(self, expected: &str) -> anyhow::Result<Self::Response>;
    fn assert_unauthorized_contains(self, expected: &str) -> anyhow::Result<Self::Response>;
    fn assert_internal_error_contains(self, expected: &str) -> anyhow::Result<Self::Response>;
    fn assert_dependency_error_contains(self, expected: &str) -> anyhow::Result<Self::Response>;

    fn assert_bad_request(self) -> anyhow::Result<Self::Response>
    where
        Self: Sized,
    {
        self.assert_bad_request_contains("")
    }
    fn assert_unauthorized(self) -> anyhow::Result<Self::Response>
    where
        Self: Sized,
    {
        self.assert_unauthorized_contains("")
    }
    fn assert_internal_error(self) -> anyhow::Result<Self::Response>
    where
        Self: Sized,
    {
        self.assert_internal_error_contains("")
    }
}

// Presumes that $response::Err has a `msg: String` field.
#[macro_export]
macro_rules! impl_mpc_check {
    ( $response:ident ) => {
        impl MpcCheck for (StatusCode, $response) {
            type Response = $response;

            fn assert_ok(self) -> anyhow::Result<Self::Response> {
                let status_code = self.0;
                let response = self.1;

                if status_code == StatusCode::OK {
                    let $response::Ok { .. } = response else {
                        anyhow::bail!("failed to get a signature from mpc-recovery");
                    };

                    Ok(response)
                } else {
                    let $response::Err { .. } = response else {
                        anyhow::bail!("unexpected Ok with a non-200 http code ({status_code})");
                    };
                    anyhow::bail!(
                        "expected 200, but got {status_code} with response: {response:?}"
                    );
                }
            }

            fn assert_bad_request_contains(self, expected: &str) -> anyhow::Result<Self::Response> {
                let status_code = self.0;
                let response = self.1;

                if status_code == StatusCode::BAD_REQUEST {
                    let $response::Err { ref msg, .. } = response else {
                        anyhow::bail!("unexpected Ok with a 400 http code");
                    };
                    assert!(msg.contains(expected), "{expected:?} not in {msg:?}");

                    Ok(response)
                } else {
                    anyhow::bail!(
                        "expected 400, but got {status_code} with response: {response:?}"
                    );
                }
            }

            fn assert_unauthorized_contains(
                self,
                expected: &str,
            ) -> anyhow::Result<Self::Response> {
                let status_code = self.0;
                let response = self.1;

                if status_code == StatusCode::UNAUTHORIZED {
                    let $response::Err { ref msg, .. } = response else {
                        anyhow::bail!("unexpected Ok with a 401 http code");
                    };
                    assert!(msg.contains(expected), "{expected:?} not in {msg:?}");

                    Ok(response)
                } else {
                    anyhow::bail!(
                        "expected 401, but got {status_code} with response: {response:?}"
                    );
                }
            }
            // ideally we should not have situations where we can get INTERNAL_SERVER_ERROR
            fn assert_internal_error_contains(
                self,
                expected: &str,
            ) -> anyhow::Result<Self::Response> {
                let status_code = self.0;
                let response = self.1;

                if status_code == StatusCode::INTERNAL_SERVER_ERROR {
                    let $response::Err { ref msg, .. } = response else {
                        anyhow::bail!("unexpected error with a 401 http code");
                    };
                    assert!(msg.contains(expected));

                    Ok(response)
                } else {
                    anyhow::bail!(
                        "expected 401, but got {status_code} with response: {response:?}"
                    );
                }
            }
            fn assert_dependency_error_contains(
                self,
                expected: &str,
            ) -> anyhow::Result<Self::Response> {
                let status_code = self.0;
                let response = self.1;

                if status_code == StatusCode::FAILED_DEPENDENCY {
                    let $response::Err { ref msg, .. } = response else {
                        anyhow::bail!("unexpected error with a 424 http code");
                    };
                    assert!(msg.contains(expected));

                    Ok(response)
                } else {
                    anyhow::bail!(
                        "expected 424, but got {status_code} with response: {response:?}"
                    );
                }
            }
        }
    };
}

impl_mpc_check!(SignResponse);
impl_mpc_check!(NewAccountResponse);
impl_mpc_check!(MpcPkResponse);
impl_mpc_check!(ClaimOidcResponse);
impl_mpc_check!(UserCredentialsResponse);

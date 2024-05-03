mod mpc;
mod multichain;

use anyhow::anyhow;
use std::str::FromStr;

use curv::elliptic::curves::{Ed25519, Point};
use futures::future::BoxFuture;
use hyper::StatusCode;
use mpc_recovery::{
    gcp::GcpService,
    msg::{
        ClaimOidcResponse, MpcPkResponse, NewAccountResponse, SignResponse, UserCredentialsResponse,
    },
};
use mpc_recovery_integration_tests::{
    env,
    multichain::utils::{vote_join, vote_leave},
};
use mpc_recovery_integration_tests::{env::containers::DockerClient, multichain::MultichainConfig};
use near_jsonrpc_client::JsonRpcClient;
use near_workspaces::{network::Sandbox, Account, AccountId, Worker};

use crate::multichain::actions::wait_for;

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
    cfg: MultichainConfig,
}

impl MultichainTestContext<'_> {
    pub async fn participant_accounts(&self) -> anyhow::Result<Vec<Account>> {
        let node_accounts: Vec<Account> = self.nodes.near_accounts();
        let state = wait_for::running_mpc(self, None).await?;
        let participant_ids = state.participants.keys().collect::<Vec<_>>();
        let participant_accounts: Vec<Account> = participant_ids
            .iter()
            .map(|id| near_workspaces::types::AccountId::from_str(id.as_ref()).unwrap())
            .map(|id| {
                node_accounts
                    .iter()
                    .find(|a| a.id() == &id)
                    .unwrap()
                    .clone()
            })
            .collect();
        Ok(participant_accounts)
    }

    pub async fn add_participant(&mut self) -> anyhow::Result<()> {
        let state = wait_for::running_mpc(self, None).await?;

        let new_node_account = self.nodes.ctx().worker.dev_create_account().await?;
        tracing::info!("Adding a new participant: {}", new_node_account.id());
        self.nodes
            .start_node(
                new_node_account.id(),
                new_node_account.secret_key(),
                &self.cfg,
            )
            .await?;

        // Wait for new node to add itself as a candidate
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // T number of participants should vote
        let participants = self.participant_accounts().await?;
        let voting_participants = participants
            .iter()
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();
        assert!(vote_join(
            voting_participants,
            self.nodes.ctx().mpc_contract.id(),
            new_node_account.id()
        )
        .await
        .is_ok());

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        assert_eq!(new_state.participants.len(), state.participants.len() + 1);
        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(())
    }

    pub async fn remove_participant(
        &mut self,
        leaving_account_id: Option<&AccountId>,
    ) -> anyhow::Result<()> {
        let state = wait_for::running_mpc(self, None).await?;
        let participant_accounts = self.participant_accounts().await?;
        let leaving_account_id =
            leaving_account_id.unwrap_or_else(|| participant_accounts.last().unwrap().id());
        tracing::info!("Removing participant: {}", leaving_account_id);

        let voting_accounts = participant_accounts
            .iter()
            .filter(|account| account.id() != leaving_account_id)
            .take(state.threshold)
            .cloned()
            .collect::<Vec<Account>>();

        let results = vote_leave(
            voting_accounts,
            self.nodes.ctx().mpc_contract.id(),
            leaving_account_id,
        )
        .await;

        // Check if any result has failures, and return early with an error if so
        if results
            .iter()
            .any(|result| !result.as_ref().unwrap().failures().is_empty())
        {
            return Err(anyhow!("Failed to vote_leave"));
        }

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        assert_eq!(state.participants.len(), new_state.participants.len() + 1);

        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        self.nodes.kill_node(leaving_account_id).await.unwrap();
        Ok(())
    }
}

async fn with_multichain_nodes<F>(cfg: MultichainConfig, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(MultichainTestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker_client = DockerClient::default();
    let nodes =
        mpc_recovery_integration_tests::multichain::run(cfg.clone(), &docker_client).await?;

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());
    f(MultichainTestContext {
        nodes,
        rpc_client,
        jsonrpc_client,
        http_client: reqwest::Client::default(),
        cfg,
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

// Kept the dead code around because it will be useful in testing and it's implemented everywhere
trait MpcCheck {
    type Response;

    fn assert_ok(self) -> anyhow::Result<Self::Response>;
    fn assert_bad_request_contains(self, expected: &str) -> anyhow::Result<Self::Response>;
    fn assert_unauthorized_contains(self, expected: &str) -> anyhow::Result<Self::Response>;
    #[allow(dead_code)]
    fn assert_internal_error_contains(self, expected: &str) -> anyhow::Result<Self::Response>;
    fn assert_dependency_error_contains(self, expected: &str) -> anyhow::Result<Self::Response>;

    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

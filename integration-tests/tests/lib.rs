mod mpc;

use curv::elliptic::curves::{Ed25519, Point};
use futures::future::BoxFuture;
use hyper::StatusCode;
use mpc_recovery::{
    firewall::allowed::DelegateActionRelayer,
    gcp::GcpService,
    msg::{
        ClaimOidcResponse, MpcPkResponse, NewAccountResponse, SignResponse, UserCredentialsResponse,
    },
    GenerateResult,
};
use mpc_recovery_integration_tests::containers;
use near_primitives::utils::generate_random_string;
use workspaces::{network::Sandbox, Worker};

const NETWORK: &str = "mpc_it_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-gcp-project";
// TODO: figure out how to instantiate and use a local firebase deployment
pub const FIREBASE_AUDIENCE_ID: &str = "test_audience";

pub struct TestContext {
    leader_node: containers::LeaderNodeApi,
    pk_set: Vec<Point<Ed25519>>,
    worker: Worker<Sandbox>,
    signer_nodes: Vec<containers::SignerNodeApi>,
    gcp_datastore_url: String,
}

impl TestContext {
    pub async fn gcp_service(&self) -> anyhow::Result<GcpService> {
        GcpService::new(
            "dev".into(),
            GCP_PROJECT_ID.into(),
            Some(self.gcp_datastore_url.clone()),
        )
        .await
    }
}

async fn with_nodes<F>(nodes: usize, f: F) -> anyhow::Result<()>
where
    F: FnOnce(TestContext) -> BoxFuture<'static, anyhow::Result<()>>,
{
    let docker_client = containers::DockerClient::default();
    docker_client.create_network(NETWORK).await?;

    let relayer_id = generate_random_string(7); // used to distinguish relayer tmp files in multiple tests
    let relayer_ctx_future =
        mpc_recovery_integration_tests::initialize_relayer(&docker_client, NETWORK, &relayer_id);
    let datastore_future = containers::Datastore::run(&docker_client, NETWORK, GCP_PROJECT_ID);

    let (relayer_ctx, datastore) =
        futures::future::join(relayer_ctx_future, datastore_future).await;
    let relayer_ctx = relayer_ctx?;
    let datastore = datastore?;

    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_node_futures = Vec::new();
    for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
        let signer_node = containers::SignerNode::run_signing_node(
            &docker_client,
            NETWORK,
            i as u64,
            share,
            cipher_key,
            &datastore.address,
            &datastore.local_address,
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
        relayer_ctx.creator_account.id(),
        relayer_ctx.creator_account.secret_key(),
        FIREBASE_AUDIENCE_ID,
    )
    .await?;

    f(TestContext {
        leader_node: leader_node.api(
            &relayer_ctx.sandbox.local_address,
            &DelegateActionRelayer {
                url: relayer_ctx.relayer.local_address.clone(),
                api_key: None,
            },
        ),
        pk_set,
        signer_nodes: signer_nodes.iter().map(|n| n.api()).collect(),
        worker: relayer_ctx.worker,
        gcp_datastore_url: datastore.local_address,
    })
    .await?;

    relayer_ctx.relayer.clean_tmp_files()?;

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
    use workspaces::AccountId;

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

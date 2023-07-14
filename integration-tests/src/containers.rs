#![allow(clippy::too_many_arguments)]

use anyhow::anyhow;
use bollard::Docker;
use ed25519_dalek::ed25519::signature::digest::{consts::U32, generic_array::GenericArray};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use mpc_recovery::msg::{
    AcceptNodePublicKeysRequest, AddKeyRequest, AddKeyResponse, ClaimOidcRequest,
    ClaimOidcResponse, NewAccountRequest, NewAccountResponse,
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_crypto::SecretKey;
use serde::{Deserialize, Serialize};
use testcontainers::{
    clients::Cli,
    core::{ExecCommand, WaitFor},
    images::generic::GenericImage,
    Container, Image, RunnableImage,
};
use tracing;
use workspaces::AccountId;

pub struct DockerClient {
    pub docker: Docker,
    pub cli: Cli,
}

impl DockerClient {
    pub async fn get_network_ip_address<I: Image>(
        &self,
        container: &Container<'_, I>,
        network: &str,
    ) -> anyhow::Result<String> {
        let network_settings = self
            .docker
            .inspect_container(container.id(), None)
            .await?
            .network_settings
            .ok_or_else(|| anyhow!("missing NetworkSettings on container '{}'", container.id()))?;
        let ip_address = network_settings
            .networks
            .ok_or_else(|| {
                anyhow!(
                    "missing NetworkSettings.Networks on container '{}'",
                    container.id()
                )
            })?
            .get(network)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' is not a part of network '{}'",
                    container.id(),
                    network
                )
            })?
            .ip_address
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' belongs to network '{}', but is not assigned an IP address",
                    container.id(),
                    network
                )
            })?;

        Ok(ip_address)
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        Self {
            docker: Docker::connect_with_local_defaults().unwrap(),
            cli: Default::default(),
        }
    }
}

pub struct Redis<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

impl<'a> Redis<'a> {
    pub async fn run(docker_client: &'a DockerClient, network: &str) -> anyhow::Result<Redis<'a>> {
        tracing::info!("Running Redis container...");
        let image = GenericImage::new("redis", "latest")
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"));
        let image: RunnableImage<GenericImage> = image.into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        tracing::info!("Redis container is running at {}", address);
        Ok(Redis { container, address })
    }
}

pub struct Sandbox<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

impl<'a> Sandbox<'a> {
    pub const CONTAINER_RPC_PORT: u16 = 3000;
    pub const CONTAINER_NETWORK_PORT: u16 = 3001;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
    ) -> anyhow::Result<Sandbox<'a>> {
        tracing::info!("Running sandbox container...");
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let image = GenericImage::new("ghcr.io/near/sandbox", "latest-aarch64")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_RPC_PORT);
        #[cfg(target_arch = "x86_64")]
        let image = GenericImage::new("ghcr.io/near/sandbox", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_RPC_PORT);
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "--rpc-addr".to_string(),
                format!("0.0.0.0:{}", Self::CONTAINER_RPC_PORT),
                "--network-addr".to_string(),
                format!("0.0.0.0:{}", Self::CONTAINER_NETWORK_PORT),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_RPC_PORT),
            ready_conditions: vec![]
        });

        let full_address = format!("http://{}:{}", address, Self::CONTAINER_RPC_PORT);
        tracing::info!("Sandbox container is running at {}", full_address);
        Ok(Sandbox {
            container,
            address: full_address,
        })
    }
}

pub struct Relayer<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

impl<'a> Relayer<'a> {
    pub const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        near_rpc: &str,
        redis_hostname: &str,
        relayer_account_id: &AccountId,
        relayer_account_sk: &SecretKey,
        creator_account_id: &AccountId,
        social_db_id: &AccountId,
        social_account_id: &AccountId,
        social_account_sk: &SecretKey,
    ) -> anyhow::Result<Relayer<'a>> {
        tracing::info!("Running relayer container...");
        let image = GenericImage::new("ghcr.io/near/pagoda-relayer-rs-fastauth", "latest")
            .with_wait_for(WaitFor::message_on_stdout("listening on"))
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "DEBUG")
            .with_env_var("NETWORK", "custom")
            .with_env_var("SERVER_PORT", Self::CONTAINER_PORT.to_string())
            .with_env_var("RELAYER_RPC_URL", near_rpc)
            .with_env_var("RELAYER_ACCOUNT_ID", relayer_account_id.to_string())
            .with_env_var("REDIS_HOST", redis_hostname)
            .with_env_var("PUBLIC_KEY", relayer_account_sk.public_key().to_string())
            .with_env_var("PRIVATE_KEY", relayer_account_sk.to_string())
            .with_env_var(
                "RELAYER_WHITELISTED_CONTRACT",
                creator_account_id.to_string(),
            )
            .with_env_var("CUSTOM_SOCIAL_DB_ID", social_db_id.to_string())
            .with_env_var("STORAGE_ACCOUNT_ID", social_account_id.to_string())
            .with_env_var(
                "STORAGE_PUBLIC_KEY",
                social_account_sk.public_key().to_string(),
            )
            .with_env_var("STORAGE_PRIVATE_KEY", social_account_sk.to_string());
        let image: RunnableImage<GenericImage> = image.into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        let full_address = format!("http://{}:{}", ip_address, Self::CONTAINER_PORT);
        tracing::info!("Relayer container is running at {}", full_address);
        Ok(Relayer {
            container,
            address: full_address,
        })
    }
}

pub struct Datastore<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

impl<'a> Datastore<'a> {
    pub const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        project_id: &str,
    ) -> anyhow::Result<Datastore<'a>> {
        tracing::info!("Running datastore container...");
        let image = GenericImage::new(
            "gcr.io/google.com/cloudsdktool/google-cloud-cli",
            "436.0.0-emulators",
        )
        .with_wait_for(WaitFor::message_on_stderr("Dev App Server is now running."))
        .with_exposed_port(Self::CONTAINER_PORT)
        .with_entrypoint("gcloud")
        .with_env_var(
            "DATASTORE_EMULATOR_HOST",
            format!("0.0.0.0:{}", Self::CONTAINER_PORT),
        )
        .with_env_var("DATASTORE_PROJECT_ID", project_id);
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "beta".to_string(),
                "emulators".to_string(),
                "datastore".to_string(),
                "start".to_string(),
                format!("--project={project_id}"),
                "--host-port".to_string(),
                format!("0.0.0.0:{}", Self::CONTAINER_PORT),
                "--no-store-on-disk".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        let full_address = format!("http://{}:{}/", ip_address, Self::CONTAINER_PORT);
        tracing::info!("Datastore container is running at {}", full_address);
        Ok(Datastore {
            container,
            address: full_address,
        })
    }
}

pub struct SignerNode<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub local_address: String,
}

pub struct SignerNodeApi {
    pub address: String,
}

impl<'a> SignerNode<'a> {
    // Container port used for the docker network, does not have to be unique
    const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        node_id: u64,
        sk_share: &ExpandedKeyPair,
        cipher_key: &GenericArray<u8, U32>,
        datastore_url: &str,
        gcp_project_id: &str,
        firebase_audience_id: &str,
    ) -> anyhow::Result<SignerNode<'a>> {
        tracing::info!("Running signer node container {}...", node_id);
        let image: GenericImage = GenericImage::new("near/mpc-recovery", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery=DEBUG");
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "start-sign".to_string(),
                "--node-id".to_string(),
                node_id.to_string(),
                "--sk-share".to_string(),
                serde_json::to_string(&sk_share)?,
                "--cipher-key".to_string(),
                hex::encode(cipher_key),
                "--web-port".to_string(),
                Self::CONTAINER_PORT.to_string(),
                "--pagoda-firebase-audience-id".to_string(),
                firebase_audience_id.to_string(),
                "--gcp-project-id".to_string(),
                gcp_project_id.to_string(),
                "--gcp-datastore-url".to_string(),
                datastore_url.to_string(),
                "--test".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            "Signer node container {} is running at {}",
            node_id,
            full_address
        );
        Ok(SignerNode {
            container,
            address: full_address,
            local_address: format!("http://localhost:{host_port}"),
        })
    }

    pub fn api(&self) -> SignerNodeApi {
        SignerNodeApi {
            address: self.local_address.clone(),
        }
    }
}

impl SignerNodeApi {
    pub async fn accept_pk_set(
        &self,
        request: AcceptNodePublicKeysRequest,
    ) -> anyhow::Result<(StatusCode, Result<String, String>)> {
        post(format!("{}/accept_pk_set", self.address), request).await
    }
}

pub struct LeaderNode<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    local_address: String,
}

pub struct LeaderNodeApi {
    address: String,
}

impl<'a> LeaderNode<'a> {
    // Container port used for the docker network, does not have to be unique
    const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        sign_nodes: Vec<String>,
        near_rpc: &str,
        relayer_url: &str,
        datastore_url: &str,
        gcp_project_id: &str,
        near_root_account: &AccountId,
        account_creator_id: &AccountId,
        account_creator_sk: &SecretKey,
        firebase_audience_id: &str,
    ) -> anyhow::Result<LeaderNode<'a>> {
        tracing::info!("Running leader node container...");

        let image = GenericImage::new("near/mpc-recovery", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery=DEBUG");
        let mut cmd = vec![
            "start-leader".to_string(),
            "--web-port".to_string(),
            Self::CONTAINER_PORT.to_string(),
            "--near-rpc".to_string(),
            near_rpc.to_string(),
            "--relayer-url".to_string(),
            relayer_url.to_string(),
            "--near-root-account".to_string(),
            near_root_account.to_string(),
            "--account-creator-id".to_string(),
            account_creator_id.to_string(),
            "--account-creator-sk".to_string(),
            account_creator_sk.to_string(),
            "--pagoda-firebase-audience-id".to_string(),
            firebase_audience_id.to_string(),
            "--gcp-project-id".to_string(),
            gcp_project_id.to_string(),
            "--gcp-datastore-url".to_string(),
            datastore_url.to_string(),
            "--test".to_string(),
        ];
        for sign_node in sign_nodes {
            cmd.push("--sign-nodes".to_string());
            cmd.push(sign_node);
        }
        let image: RunnableImage<GenericImage> = (image, cmd).into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!("Leader node container is running at {}", full_address);
        Ok(LeaderNode {
            container,
            address: full_address,
            local_address: format!("http://localhost:{host_port}"),
        })
    }

    pub fn api(&self) -> LeaderNodeApi {
        LeaderNodeApi {
            address: self.local_address.clone(),
        }
    }
}

impl LeaderNodeApi {
    pub async fn claim_oidc(
        &self,
        request: ClaimOidcRequest,
    ) -> anyhow::Result<(StatusCode, ClaimOidcResponse)> {
        post(format!("{}/claim_oidc", self.address), request).await
    }

    pub async fn new_account(
        &self,
        request: NewAccountRequest,
    ) -> anyhow::Result<(StatusCode, NewAccountResponse)> {
        post(format!("{}/new_account", self.address), request).await
    }

    pub async fn add_key(
        &self,
        request: AddKeyRequest,
    ) -> anyhow::Result<(StatusCode, AddKeyResponse)> {
        post(format!("{}/add_key", self.address), request).await
    }
}

async fn post<U, Req: Serialize, Resp>(uri: U, request: Req) -> anyhow::Result<(StatusCode, Resp)>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
    for<'de> Resp: Deserialize<'de>,
{
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request)?))?;

    let client = Client::new();
    let response = client.request(req).await?;
    let status = response.status();

    let data = hyper::body::to_bytes(response).await?;
    let response: Resp = serde_json::from_slice(&data)?;

    Ok((status, response))
}

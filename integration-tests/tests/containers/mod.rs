use anyhow::anyhow;
use bollard::Docker;
use ed25519_dalek::ed25519::signature::digest::{consts::U32, generic_array::GenericArray};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use mpc_recovery::msg::{AddKeyRequest, AddKeyResponse, NewAccountRequest, NewAccountResponse};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_crypto::SecretKey;
use serde::{Deserialize, Serialize};
use testcontainers::{
    clients::Cli, core::WaitFor, images::generic::GenericImage, Container, Image, RunnableImage,
};
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
        let image = GenericImage::new("redis", "latest")
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"));
        let image: RunnableImage<GenericImage> = image.into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        Ok(Redis { container, address })
    }
}

pub struct Relayer<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

impl<'a> Relayer<'a> {
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
        let port = portpicker::pick_unused_port().expect("no free ports");

        let image = GenericImage::new("pagoda-relayer-rs-fastauth", "latest")
            .with_wait_for(WaitFor::message_on_stdout("listening on"))
            .with_exposed_port(port)
            .with_env_var("RUST_LOG", "DEBUG")
            .with_env_var("NETWORK", "custom")
            .with_env_var("SERVER_PORT", port.to_string())
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

        Ok(Relayer {
            container,
            address: format!("http://{ip_address}:{port}"),
        })
    }
}

pub struct Datastore<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

impl<'a> Datastore<'a> {
    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        project_id: &str,
    ) -> anyhow::Result<Datastore<'a>> {
        let port = portpicker::pick_unused_port().expect("no free ports");

        let image = GenericImage::new("google/cloud-sdk", "latest")
            .with_wait_for(WaitFor::message_on_stderr("Dev App Server is now running."))
            .with_exposed_port(port)
            .with_entrypoint("gcloud")
            .with_env_var("DATASTORE_EMULATOR_HOST", &format!("0.0.0.0:{port}"))
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
                format!("0.0.0.0:{port}"),
                "--no-store-on-disk".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        Ok(Datastore {
            container,
            address: format!("http://{ip_address}:{port}/"),
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
        let image: GenericImage = GenericImage::new("near/mpc-recovery", "latest")
            .with_wait_for(WaitFor::message_on_stdout("running a sign node"))
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

        Ok(SignerNode {
            container,
            address: format!("http://{ip_address}:{}", Self::CONTAINER_PORT),
            local_address: format!("http://localhost:{host_port}"),
        })
    }

    pub fn api(&self) -> SignerNodeApi {
        SignerNodeApi {
            address: self.local_address.clone(),
        }
    }
}

pub struct LeaderNode<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
}

pub struct LeaderNodeApi {
    address: String,
}

impl<'a> LeaderNode<'a> {
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
        let port = portpicker::pick_unused_port().expect("no free ports");

        let image = GenericImage::new("near/mpc-recovery", "latest")
            .with_wait_for(WaitFor::message_on_stdout("running a leader node"))
            .with_exposed_port(port)
            .with_env_var("RUST_LOG", "mpc_recovery=DEBUG");
        let mut cmd = vec![
            "start-leader".to_string(),
            "--web-port".to_string(),
            port.to_string(),
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

        Ok(LeaderNode {
            container,
            address: format!("http://{ip_address}:{port}"),
        })
    }

    pub fn api(&self) -> LeaderNodeApi {
        LeaderNodeApi {
            address: self.address.clone(),
        }
    }
}

impl LeaderNodeApi {
    async fn post<U, Req: Serialize, Resp>(
        &self,
        uri: U,
        request: Req,
    ) -> anyhow::Result<(StatusCode, Resp)>
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

    pub async fn new_account(
        &self,
        request: NewAccountRequest,
    ) -> anyhow::Result<(StatusCode, NewAccountResponse)> {
        self.post(format!("{}/new_account", self.address), request)
            .await
    }

    pub async fn add_key(
        &self,
        request: AddKeyRequest,
    ) -> anyhow::Result<(StatusCode, AddKeyResponse)> {
        self.post(format!("{}/add_key", self.address), request)
            .await
    }
}

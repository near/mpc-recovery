use bollard::{
    container::{AttachContainerOptions, AttachContainerResults, Config, RemoveContainerOptions},
    network::CreateNetworkOptions,
    service::{HostConfig, Ipam, PortBinding},
    Docker,
};
use futures::StreamExt;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use mpc_recovery::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse,
};
use near_crypto::SecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare};
use tokio::io::AsyncWriteExt;
use workspaces::AccountId;

// pub mod redis;
// pub mod relayer;

async fn continuously_print_docker_output(docker: &Docker, id: &str) -> anyhow::Result<()> {
    let AttachContainerResults { mut output, .. } = docker
        .attach_container(
            id,
            Some(AttachContainerOptions::<String> {
                stdout: Some(true),
                stderr: Some(true),
                stream: Some(true),
                ..Default::default()
            }),
        )
        .await?;

    // Asynchronous process that pipes docker attach output into stdout.
    // Will die automatically once Docker container output is closed.
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();

        while let Some(Ok(output)) = output.next().await {
            stdout
                .write_all(output.into_bytes().as_ref())
                .await
                .unwrap();
            stdout.flush().await.unwrap();
        }
    });

    Ok(())
}

async fn start_mpc_node(
    docker: &Docker,
    network: &str,
    cmd: Vec<String>,
    web_port: u16,
    expose_web_port: bool,
) -> anyhow::Result<(String, String)> {
    let mut exposed_ports = HashMap::new();
    let mut port_bindings = HashMap::new();
    if expose_web_port {
        let empty = HashMap::<(), ()>::new();
        exposed_ports.insert(format!("{web_port}/tcp"), empty);
        port_bindings.insert(
            format!("{web_port}/tcp"),
            Some(vec![PortBinding {
                host_ip: None,
                host_port: Some(web_port.to_string()),
            }]),
        );
    }

    let mpc_recovery_config = Config {
        image: Some("near/mpc-recovery:latest".to_string()),
        tty: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        exposed_ports: Some(exposed_ports),
        cmd: Some(cmd),
        host_config: Some(HostConfig {
            network_mode: Some(network.to_string()),
            port_bindings: Some(port_bindings),
            ..Default::default()
        }),
        env: Some(vec!["RUST_LOG=mpc_recovery=DEBUG".to_string()]),
        ..Default::default()
    };

    let id = docker
        .create_container::<&str, String>(None, mpc_recovery_config)
        .await?
        .id;

    continuously_print_docker_output(docker, &id).await?;
    docker.start_container::<String>(&id, None).await?;

    let network_settings = docker
        .inspect_container(&id, None)
        .await?
        .network_settings
        .unwrap();
    let ip_address = network_settings
        .networks
        .unwrap()
        .get(network)
        .cloned()
        .unwrap()
        .ip_address
        .unwrap();

    Ok((id, ip_address))
}

async fn create_network(docker: &Docker, network: &str) -> anyhow::Result<()> {
    let list = docker.list_networks::<&str>(None).await?;
    if list.iter().any(|n| n.name == Some(network.to_string())) {
        return Ok(());
    }

    let create_network_options = CreateNetworkOptions {
        name: network,
        check_duplicate: true,
        driver: if cfg!(windows) {
            "transparent"
        } else {
            "bridge"
        },
        ipam: Ipam {
            config: None,
            ..Default::default()
        },
        ..Default::default()
    };
    let _response = &docker.create_network(create_network_options).await?;

    Ok(())
}

pub struct LeaderNode {
    docker: Docker,
    container_id: String,
    pub address: String,
}

impl LeaderNode {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        docker: &Docker,
        network: &str,
        node_id: u64,
        pk_set: &PublicKeySet,
        sk_share: &SecretKeyShare,
        sign_nodes: Vec<String>,
        near_rpc: &str,
        relayer_url: &str,
        account_creator_id: &AccountId,
        account_creator_sk: &SecretKey,
    ) -> anyhow::Result<LeaderNode> {
        create_network(docker, network).await?;
        let web_port = portpicker::pick_unused_port().expect("no free ports");

        let mut cmd = vec![
            "start-leader".to_string(),
            "--node-id".to_string(),
            node_id.to_string(),
            "--pk-set".to_string(),
            serde_json::to_string(&pk_set)?,
            "--sk-share".to_string(),
            serde_json::to_string(&SerdeSecret(sk_share))?,
            "--web-port".to_string(),
            web_port.to_string(),
            "--near-rpc".to_string(),
            near_rpc.to_string(),
            "--relayer-url".to_string(),
            relayer_url.to_string(),
            "--account-creator-id".to_string(),
            account_creator_id.to_string(),
            "--account-creator-sk".to_string(),
            account_creator_sk.to_string(),
        ];
        for sign_node in sign_nodes {
            cmd.push("--sign-nodes".to_string());
            cmd.push(sign_node);
        }

        let (container_id, _) = start_mpc_node(docker, network, cmd, web_port, true).await?;
        Ok(LeaderNode {
            docker: docker.clone(),
            container_id,
            address: format!("http://localhost:{web_port}"),
        })
    }

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

    pub async fn submit(
        &self,
        request: LeaderRequest,
    ) -> anyhow::Result<(StatusCode, LeaderResponse)> {
        self.post(format!("{}/submit", self.address), request).await
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

// Removing container is an asynchronous operation and hence has to be scheduled to execute
// outside of `drop`'s scope. This leads to problems when the drop happens right before the
// execution ends. The invoker needs to be aware of this behavior and give `drop` some time
// to finalize.
impl Drop for LeaderNode {
    fn drop(&mut self) {
        let container_id = self.container_id.clone();
        let docker = self.docker.clone();
        tokio::spawn(async move {
            docker
                .remove_container(
                    &container_id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
        });
    }
}

pub struct SignNode {
    docker: Docker,
    container_id: String,
    pub address: String,
}

impl SignNode {
    pub async fn start(
        docker: &Docker,
        network: &str,
        node_id: u64,
        pk_set: &PublicKeySet,
        sk_share: &SecretKeyShare,
    ) -> anyhow::Result<SignNode> {
        create_network(docker, network).await?;
        let web_port = portpicker::pick_unused_port().expect("no free ports");

        let cmd = vec![
            "start-sign".to_string(),
            "--node-id".to_string(),
            node_id.to_string(),
            "--pk-set".to_string(),
            serde_json::to_string(&pk_set)?,
            "--sk-share".to_string(),
            serde_json::to_string(&SerdeSecret(sk_share))?,
            "--web-port".to_string(),
            web_port.to_string(),
        ];

        let (container_id, ip_address) =
            start_mpc_node(docker, network, cmd, web_port, false).await?;

        Ok(SignNode {
            docker: docker.clone(),
            container_id,
            address: format!("http://{ip_address}:{web_port}"),
        })
    }
}

// Removing container is an asynchronous operation and hence has to be scheduled to execute
// outside of `drop`'s scope. This leads to problems when the drop happens right before the
// execution ends. The invoker needs to be aware of this behavior and give `drop` some time
// to finalize.
impl Drop for SignNode {
    fn drop(&mut self) {
        let container_id = self.container_id.clone();
        let docker = self.docker.clone();
        tokio::spawn(async move {
            docker
                .remove_container(
                    &container_id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
        });
    }
}
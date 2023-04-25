use crate::drop_container;
use bollard::{
    container::{Config, RemoveContainerOptions},
    service::{HostConfig, PortBinding},
    Docker,
};
use near_crypto::SecretKey;
use std::collections::HashMap;
use workspaces::AccountId;

pub struct Relayer {
    docker: Docker,
    container_id: String,
    pub address: String,
}

impl Relayer {
    pub async fn start(
        docker: &Docker,
        network: &str,
        near_rpc: &str,
        redis_hostname: &str,
        relayer_account_id: &AccountId,
        relayer_account_sk: &SecretKey,
        creator_account_id: &AccountId,
        social_db_id: &AccountId,
        social_account_id: &AccountId,
        social_account_sk: &SecretKey,
    ) -> anyhow::Result<Self> {
        super::create_network(docker, network).await?;
        let web_port = portpicker::pick_unused_port().expect("no free ports");

        let mut exposed_ports = HashMap::new();
        let mut port_bindings = HashMap::new();
        let empty = HashMap::<(), ()>::new();
        exposed_ports.insert(format!("{web_port}/tcp"), empty);
        port_bindings.insert(
            format!("{web_port}/tcp"),
            Some(vec![PortBinding {
                host_ip: None,
                host_port: Some(web_port.to_string()),
            }]),
        );

        let relayer_config = Config {
            image: Some("pagoda-relayer-rs-fastauth:latest".to_string()),
            tty: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            exposed_ports: Some(exposed_ports),
            cmd: None,
            host_config: Some(HostConfig {
                network_mode: Some(network.to_string()),
                port_bindings: Some(port_bindings),
                ..Default::default()
            }),
            env: Some(vec![
                "RUST_LOG=mpc_recovery=DEBUG".to_string(),
                "NETWORK=custom".to_string(),
                format!("SERVER_PORT={}", web_port),
                format!("RELAYER_RPC_URL={}", near_rpc),
                format!("RELAYER_ACCOUNT_ID={}", relayer_account_id),
                format!("REDIS_HOST={}", redis_hostname),
                format!("PUBLIC_KEY={}", relayer_account_sk.public_key()),
                format!("PRIVATE_KEY={}", relayer_account_sk),
                format!("RELAYER_WHITELISTED_CONTRACT={}", creator_account_id),
                format!("CUSTOM_SOCIAL_DB_ID={}", social_db_id),
                format!("STORAGE_ACCOUNT_ID={}", social_account_id),
                format!("STORAGE_PUBLIC_KEY={}", social_account_sk.public_key()),
                format!("STORAGE_PRIVATE_KEY={}", social_account_sk),
            ]),
            ..Default::default()
        };

        let container_id = docker
            .create_container::<&str, String>(None, relayer_config)
            .await?
            .id;

        super::continuously_print_docker_output(docker, &container_id).await?;
        docker
            .start_container::<String>(&container_id, None)
            .await?;

        let network_settings = docker
            .inspect_container(&container_id, None)
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

        Ok(Self {
            docker: docker.clone(),
            container_id,
            address: format!("http://{ip_address}:{web_port}"),
        })
    }
}

drop_container!(Relayer);

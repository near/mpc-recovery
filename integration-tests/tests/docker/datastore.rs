use std::collections::HashMap;

use crate::drop_container;
use bollard::{
    container::{Config, RemoveContainerOptions},
    image::CreateImageOptions,
    service::{HostConfig, PortBinding},
    Docker,
};
use futures::TryStreamExt;

pub struct Datastore {
    docker: Docker,
    container_id: String,
    pub address: String,
}

impl Datastore {
    pub async fn start(docker: &Docker, network: &str, project_id: &str) -> anyhow::Result<Self> {
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

        docker
            .create_image(
                Some(CreateImageOptions {
                    from_image: "google/cloud-sdk:latest",
                    ..Default::default()
                }),
                None,
                None,
            )
            .try_collect::<Vec<_>>()
            .await?;

        let config = Config {
            image: Some("google/cloud-sdk:latest".to_string()),
            tty: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            exposed_ports: Some(exposed_ports),
            cmd: Some(vec![
                "gcloud".to_string(),
                "beta".to_string(),
                "emulators".to_string(),
                "datastore".to_string(),
                "start".to_string(),
                format!("--project={project_id}"),
                "--host-port".to_string(),
                format!("0.0.0.0:{web_port}"),
                "--no-store-on-disk".to_string(),
            ]),
            env: Some(vec![
                format!("DATASTORE_EMULATOR_HOST=0.0.0.0:{web_port}"),
                format!("DATASTORE_PROJECT_ID={project_id}"),
            ]),
            host_config: Some(HostConfig {
                network_mode: Some(network.to_string()),
                port_bindings: Some(port_bindings),
                ..Default::default()
            }),
            ..Default::default()
        };

        let container_id = docker
            .create_container::<&str, String>(None, config)
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
            address: format!("http://{ip_address}:{web_port}/"),
        })
    }
}

drop_container!(Datastore);

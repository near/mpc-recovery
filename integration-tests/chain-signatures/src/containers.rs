use std::path::Path;

use super::{local::NodeConfig, MultichainConfig};
use anyhow::anyhow;
use bollard::exec::CreateExecOptions;
use bollard::{container::LogsOptions, network::CreateNetworkOptions, service::Ipam, Docker};
use futures::{lock::Mutex, StreamExt};
use mpc_keys::hpke;
use near_workspaces::AccountId;
use once_cell::sync::Lazy;
use testcontainers::clients::Cli;
use testcontainers::Image;
use testcontainers::{
    core::{ExecCommand, WaitFor},
    Container, GenericImage, RunnableImage,
};
use tokio::io::AsyncWriteExt;
use tracing;

static NETWORK_MUTEX: Lazy<Mutex<i32>> = Lazy::new(|| Mutex::new(0));

pub struct Node<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub account_id: AccountId,
    pub account_sk: near_workspaces::types::SecretKey,
    pub local_address: String,
    pub cipher_pk: hpke::PublicKey,
    pub cipher_sk: hpke::SecretKey,
    pub sign_pk: near_workspaces::types::PublicKey,
    cfg: MultichainConfig,
}

impl<'a> Node<'a> {
    // Container port used for the docker network, does not have to be unique
    const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        ctx: &super::Context<'a>,
        account_id: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<Node<'a>> {
        tracing::info!("running node container, account_id={}", account_id);
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let sign_pk = sign_sk.public_key();
        let indexer_options = mpc_recovery_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
        };
        let args = mpc_recovery_node::cli::Cli::Start {
            near_rpc: ctx.lake_indexer.rpc_host_address.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: Self::CONTAINER_PORT,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            sign_sk: Some(sign_sk),
            indexer_options: indexer_options.clone(),
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            min_triples: cfg.triple_cfg.min_triples,
            max_triples: cfg.triple_cfg.max_triples,
            max_concurrent_introduction: cfg.triple_cfg.max_concurrent_introduction,
            max_concurrent_generation: cfg.triple_cfg.max_concurrent_generation,
            min_presignatures: cfg.presig_cfg.min_presignatures,
            max_presignatures: cfg.presig_cfg.max_presignatures,
        }
        .into_str_args();
        let image: GenericImage = GenericImage::new("near/mpc-recovery-node", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery_node=DEBUG")
            .with_env_var("RUST_BACKTRACE", "1");
        let image: RunnableImage<GenericImage> = (image, args).into();
        let image = image.with_network(&ctx.docker_network);
        let container = ctx.docker_client.cli.run(image);
        let ip_address = ctx
            .docker_client
            .get_network_ip_address(&container, &ctx.docker_network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            full_address,
            "node container is running, account_id={}",
            account_id
        );
        Ok(Node {
            container,
            address: full_address,
            account_id: account_id.clone(),
            account_sk: account_sk.clone(),
            local_address: format!("http://localhost:{host_port}"),
            cipher_pk,
            cipher_sk,
            sign_pk: sign_pk.to_string().parse()?,
            cfg: cfg.clone(),
        })
    }

    pub fn kill(&self) -> NodeConfig {
        self.container.stop();
        NodeConfig {
            web_port: Self::CONTAINER_PORT,
            account_id: self.account_id.clone(),
            account_sk: self.account_sk.clone(),
            cipher_pk: self.cipher_pk.clone(),
            cipher_sk: self.cipher_sk.clone(),
            cfg: self.cfg.clone(),
        }
    }

    pub async fn restart(ctx: &super::Context<'a>, config: NodeConfig) -> anyhow::Result<Self> {
        let cipher_pk = config.cipher_pk;
        let cipher_sk = config.cipher_sk;
        let cfg = config.cfg;
        let account_id = config.account_id;
        let account_sk = config.account_sk;
        let storage_options = ctx.storage_options.clone();
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let indexer_options = mpc_recovery_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
        };
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let args = mpc_recovery_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: Self::CONTAINER_PORT,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            indexer_options: indexer_options.clone(),
            my_address: None,
            storage_options: storage_options.clone(),
            min_triples: cfg.triple_cfg.min_triples,
            max_triples: cfg.triple_cfg.max_triples,
            max_concurrent_introduction: cfg.triple_cfg.max_concurrent_introduction,
            max_concurrent_generation: cfg.triple_cfg.max_concurrent_generation,
            min_presignatures: cfg.presig_cfg.min_presignatures,
            max_presignatures: cfg.presig_cfg.max_presignatures,
            sign_sk: Some(sign_sk),
        }
        .into_str_args();
        let image: GenericImage = GenericImage::new("near/mpc-recovery-node", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery_node=DEBUG")
            .with_env_var("RUST_BACKTRACE", "1");
        let image: RunnableImage<GenericImage> = (image, args).into();
        let image = image.with_network(&ctx.docker_network);
        let container = ctx.docker_client.cli.run(image);
        let ip_address = ctx
            .docker_client
            .get_network_ip_address(&container, &ctx.docker_network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            full_address,
            "node container is running, account_id={}",
            account_id
        );
        Ok(Node {
            container,
            address: full_address,
            account_id: account_id.clone(),
            account_sk: account_sk.clone(),
            local_address: format!("http://localhost:{host_port}"),
            cipher_pk,
            cipher_sk,
            sign_pk: account_sk.public_key(),
            cfg: cfg.clone(),
        })
    }
}

pub struct LocalStack<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub s3_address: String,
    pub s3_host_address: String,
    pub s3_bucket: String,
    pub s3_region: String,
}

impl<'a> LocalStack<'a> {
    const S3_CONTAINER_PORT: u16 = 4566;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        s3_bucket: &str,
        s3_region: &str,
    ) -> anyhow::Result<LocalStack<'a>> {
        tracing::info!("running LocalStack container...");
        let image = GenericImage::new("localstack/localstack", "3.5.0")
            .with_wait_for(WaitFor::message_on_stdout("Ready."));
        let image: RunnableImage<GenericImage> = image.into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        // Create the bucket
        let create_result = docker_client
            .docker
            .create_exec(
                container.id(),
                CreateExecOptions::<&str> {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(vec![
                        "awslocal",
                        "s3api",
                        "create-bucket",
                        "--bucket",
                        s3_bucket,
                        "--region",
                        s3_region,
                    ]),
                    ..Default::default()
                },
            )
            .await?;
        let result = docker_client
            .docker
            .start_exec(&create_result.id, None)
            .await?;
        tracing::info!(?result, s3_bucket, s3_region, "localstack created bucket");

        let s3_address = format!("http://{}:{}", address, Self::S3_CONTAINER_PORT);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let s3_host_address = {
            let s3_host_port = container.get_host_port_ipv4(Self::S3_CONTAINER_PORT);
            format!("http://127.0.0.1:{s3_host_port}")
        };
        #[cfg(target_arch = "x86_64")]
        let s3_host_address = {
            let s3_host_port = container.get_host_port_ipv6(Self::S3_CONTAINER_PORT);
            format!("http://[::1]:{s3_host_port}")
        };

        tracing::info!(
            s3_address,
            s3_host_address,
            "LocalStack container is running"
        );
        Ok(LocalStack {
            container,
            address,
            s3_address,
            s3_host_address,
            s3_bucket: s3_bucket.to_string(),
            s3_region: s3_region.to_string(),
        })
    }
}

pub struct LakeIndexer<'a> {
    pub container: Container<'a, GenericImage>,
    pub bucket_name: String,
    pub region: String,
    pub rpc_address: String,
    pub rpc_host_address: String,
}

impl<'a> LakeIndexer<'a> {
    pub const CONTAINER_RPC_PORT: u16 = 3030;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        s3_address: &str,
        bucket_name: &str,
        region: &str,
    ) -> anyhow::Result<LakeIndexer<'a>> {
        tracing::info!(
            network,
            s3_address,
            bucket_name,
            region,
            "running NEAR Lake Indexer container..."
        );

        let image = GenericImage::new(
            "ghcr.io/near/near-lake-indexer",
            "node-1.40-rc.1-localstack",
        )
        .with_env_var("AWS_ACCESS_KEY_ID", "FAKE_LOCALSTACK_KEY_ID")
        .with_env_var("AWS_SECRET_ACCESS_KEY", "FAKE_LOCALSTACK_ACCESS_KEY")
        .with_wait_for(WaitFor::message_on_stderr("Starting Streamer"))
        .with_exposed_port(Self::CONTAINER_RPC_PORT);
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "--endpoint".to_string(),
                s3_address.to_string(),
                "--bucket".to_string(),
                bucket_name.to_string(),
                "--region".to_string(),
                region.to_string(),
                "--stream-while-syncing".to_string(),
                "sync-from-latest".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;
        let rpc_address = format!("http://{}:{}", address, Self::CONTAINER_RPC_PORT);
        let rpc_host_port = container.get_host_port_ipv4(Self::CONTAINER_RPC_PORT);
        let rpc_host_address = format!("http://127.0.0.1:{rpc_host_port}");

        tracing::info!(
            bucket_name,
            region,
            rpc_address,
            rpc_host_address,
            "NEAR Lake Indexer container is running"
        );
        Ok(LakeIndexer {
            container,
            bucket_name: bucket_name.to_string(),
            region: region.to_string(),
            rpc_address,
            rpc_host_address,
        })
    }
}

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

    pub async fn create_network(&self, network: &str) -> anyhow::Result<()> {
        let _lock = &NETWORK_MUTEX.lock().await;
        let list = self.docker.list_networks::<&str>(None).await?;
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
        let _response = &self.docker.create_network(create_network_options).await?;

        Ok(())
    }

    pub async fn continuously_print_logs(&self, id: &str) -> anyhow::Result<()> {
        let mut output = self.docker.logs::<String>(
            id,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

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

    pub async fn output_logs(&self, id: &str, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let mut output = self.docker.logs::<String>(
            id,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        let mut out = std::fs::File::create(path)?;
        tokio::spawn(async move {
            while let Some(Ok(output)) = output.next().await {
                std::io::Write::write_all(&mut out, output.into_bytes().as_ref()).unwrap();
            }
        });

        Ok(())
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        Self {
            docker: Docker::connect_with_local(
                "unix:///var/run/docker.sock",
                // 10 minutes timeout for all requests in case a lot of tests are being ran in parallel.
                600,
                bollard::API_DEFAULT_VERSION,
            )
            .unwrap(),
            cli: Default::default(),
        }
    }
}

pub struct Datastore<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub local_address: String,
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
            "464.0.0-emulators",
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
                "--consistency=1.0".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        let full_address = format!("http://{}:{}/", ip_address, Self::CONTAINER_PORT);
        let local_address = format!("http://127.0.0.1:{}/", host_port);
        tracing::info!("Datastore container is running at {}", full_address);
        Ok(Datastore {
            container,
            local_address,
            address: full_address,
        })
    }
}

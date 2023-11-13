pub mod containers;
pub mod local;

use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use curv::elliptic::curves::{Ed25519, Point};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_primitives::utils::generate_random_string;

use mpc_recovery::firewall::allowed::DelegateActionRelayer;
use mpc_recovery::relayer::NearRpcAndRelayerClient;
use mpc_recovery::GenerateResult;

use crate::env::containers::DockerClient;
use crate::{initialize_relayer, RelayerCtx};

const ENV: &str = "dev";
const NETWORK: &str = "mpc_it_network";
const GCP_PROJECT_ID: &str = "mpc-recovery-gcp-project";
// TODO: figure out how to instantiate and use a local firebase deployment
const FIREBASE_AUDIENCE_ID: &str = "test_audience";
const ISSUER: &str = "https://securetoken.google.com/test_audience";

pub struct SignerNodeApi {
    pub env: String,
    pub address: String,
    pub node_id: usize,
    pub sk_share: ExpandedKeyPair,
    pub cipher_key: GenericArray<u8, U32>,
    pub gcp_project_id: String,
    pub gcp_datastore_local_url: String,
}

pub struct LeaderNodeApi {
    pub address: String,
    pub relayer: DelegateActionRelayer,
    pub client: NearRpcAndRelayerClient,
}

pub enum Nodes<'a> {
    Local {
        ctx: Context<'a>,
        pk_set: Vec<Point<Ed25519>>,
        leader_node: local::LeaderNode,
        signer_nodes: Vec<local::SignerNode>,
    },
    Docker {
        ctx: Context<'a>,
        pk_set: Vec<Point<Ed25519>>,
        leader_node: containers::LeaderNode<'a>,
        signer_nodes: Vec<containers::SignerNode<'a>>,
    },
}

impl Nodes<'_> {
    pub fn ctx(&self) -> &Context {
        match self {
            Nodes::Local { ctx, .. } => ctx,
            Nodes::Docker { ctx, .. } => ctx,
        }
    }

    pub fn pk_set(&self) -> Vec<Point<Ed25519>> {
        match self {
            Nodes::Local { pk_set, .. } => pk_set.clone(),
            Nodes::Docker { pk_set, .. } => pk_set.clone(),
        }
    }

    pub fn leader_api(&self) -> LeaderNodeApi {
        match self {
            Nodes::Local { leader_node, .. } => leader_node.api(),
            Nodes::Docker { leader_node, .. } => leader_node.api(),
        }
    }

    pub fn signer_apis(&self) -> Vec<SignerNodeApi> {
        match self {
            Nodes::Local { signer_nodes, .. } => signer_nodes.iter().map(|n| n.api()).collect(),
            Nodes::Docker { signer_nodes, .. } => signer_nodes.iter().map(|n| n.api()).collect(),
        }
    }

    pub fn datastore_addr(&self) -> String {
        self.ctx().datastore.local_address.clone()
    }
}

pub struct Context<'a> {
    pub env: String,
    pub docker_client: &'a DockerClient,
    pub docker_network: String,
    pub gcp_project_id: String,
    pub audience_id: String,
    pub issuer: String,
    pub release: bool,

    pub relayer_ctx: RelayerCtx<'a>,
    pub datastore: containers::Datastore<'a>,
    pub oidc_provider: containers::OidcProvider<'a>,
}

pub async fn setup(docker_client: &DockerClient) -> anyhow::Result<Context<'_>> {
    let release = true;
    #[cfg(not(feature = "flamegraph"))]
    if !crate::mpc::build(release).await?.success() {
        anyhow::bail!("failed to prebuild MPC service");
    }

    let gcp_project_id = GCP_PROJECT_ID;
    let docker_network = NETWORK;
    docker_client.create_network(docker_network).await?;

    let relayer_id = generate_random_string(7); // used to distinguish relayer tmp files in multiple tests
    let relayer_ctx_future = initialize_relayer(docker_client, docker_network, &relayer_id);
    let datastore_future =
        containers::Datastore::run(docker_client, docker_network, gcp_project_id);
    let oidc_provider_future = containers::OidcProvider::run(docker_client, docker_network);

    let (relayer_ctx, datastore, oidc_provider) =
        futures::future::join3(relayer_ctx_future, datastore_future, oidc_provider_future).await;
    let relayer_ctx = relayer_ctx?;
    let datastore = datastore?;
    let oidc_provider = oidc_provider?;

    Ok(Context {
        env: ENV.to_string(),
        docker_client,
        docker_network: docker_network.to_string(),
        gcp_project_id: gcp_project_id.to_string(),
        audience_id: FIREBASE_AUDIENCE_ID.to_string(),
        issuer: ISSUER.to_string(),
        release,
        relayer_ctx,
        datastore,
        oidc_provider,
    })
}

pub async fn docker(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_node_futures = Vec::with_capacity(nodes);
    for (node_id, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
        signer_node_futures.push(containers::SignerNode::run(
            &ctx, node_id, share, cipher_key,
        ));
    }
    let signer_nodes = futures::future::join_all(signer_node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let sign_nodes = signer_nodes.iter().map(|n| n.address.clone()).collect();
    let leader_node = containers::LeaderNode::run(&ctx, sign_nodes).await?;

    Ok(Nodes::Docker {
        ctx,
        pk_set,
        leader_node,
        signer_nodes,
    })
}

pub async fn host(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;
    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_node_futures = Vec::with_capacity(nodes);
    for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
        signer_node_futures.push(local::SignerNode::run(&ctx, i as u64, share, cipher_key));
    }
    let signer_nodes = futures::future::join_all(signer_node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let sign_nodes = signer_nodes.iter().map(|n| n.address.clone()).collect();
    let leader_node = local::LeaderNode::run(&ctx, sign_nodes).await?;

    Ok(Nodes::Local {
        ctx,
        pk_set,
        leader_node,
        signer_nodes,
    })
}

pub async fn run(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    #[cfg(feature = "docker-test")]
    return docker(nodes, docker_client).await;

    #[cfg(not(feature = "docker-test"))]
    return host(nodes, docker_client).await;
}

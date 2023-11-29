use crate::protocol::state::PersistentNodeData;
use async_trait::async_trait;
use google_secretmanager1::{
    api::{AddSecretVersionRequest, SecretPayload},
    hyper::{self, client::HttpConnector},
    hyper_rustls::{self, HttpsConnector},
    oauth2::{
        authenticator::ApplicationDefaultCredentialsTypes,
        ApplicationDefaultCredentialsAuthenticator, ApplicationDefaultCredentialsFlowOpts,
    },
    SecretManager,
};

#[derive(thiserror::Error, Debug)]
pub enum SecretStorageError {
    #[error("GCP error: {0}")]
    GcpError(#[from] google_secretmanager1::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, SecretStorageError>;

#[async_trait]
pub trait SecretNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<()>;
    async fn load(&self) -> Result<Option<PersistentNodeData>>;
}

#[derive(Default)]
struct MemoryNodeStorage {
    node_data: Option<PersistentNodeData>,
}

#[async_trait]
impl SecretNodeStorage for MemoryNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<()> {
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> Result<Option<PersistentNodeData>> {
        Ok(self.node_data.clone())
    }
}

struct SecretManagerNodeStorage {
    secret_manager: SecretManager<HttpsConnector<HttpConnector>>,
    gcp_project_id: String,
    sk_share_secret_id: String,
}

impl SecretManagerNodeStorage {
    async fn new(gcp_project_id: String, sk_share_secret_id: String) -> Result<Self> {
        let client = hyper::Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        );
        let opts = ApplicationDefaultCredentialsFlowOpts::default();
        let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts).await {
            ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
            ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
        };
        let secret_manager = SecretManager::new(client.clone(), authenticator.clone());
        Ok(Self {
            secret_manager,
            gcp_project_id,
            sk_share_secret_id,
        })
    }
}

#[async_trait]
impl SecretNodeStorage for SecretManagerNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<()> {
        self.secret_manager
            .projects()
            .secrets_add_version(
                AddSecretVersionRequest {
                    payload: Some(SecretPayload {
                        data: Some(serde_json::to_vec(data)?),
                        ..Default::default()
                    }),
                },
                &format!("projects/{}", self.gcp_project_id,),
            )
            .doit()
            .await?;
        Ok(())
    }

    async fn load(&self) -> Result<Option<PersistentNodeData>> {
        let (_, response) = self
            .secret_manager
            .projects()
            .secrets_versions_access(&format!(
                "projects/{}/secrets/{}/versions/latest",
                self.gcp_project_id, self.sk_share_secret_id
            ))
            .doit()
            .await?;
        match response.payload {
            Some(SecretPayload {
                data: Some(data), ..
            }) if !data.is_empty() => Ok(Some(serde_json::from_slice(&data)?)),
            _ => {
                tracing::info!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }
}

/// Configures storage.
#[derive(Debug, Clone, clap::Parser)]
pub struct Options {
    /// GCP project ID.
    #[clap(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
    pub gcp_project_id: Option<String>,
    /// GCP Secret Manager ID that will be used to load/store the node's secret key share.
    #[clap(long, env("MPC_RECOVERY_SK_SHARE_SECRET_ID"), requires_all=["gcp_project_id"])]
    pub sk_share_secret_id: Option<String>,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = Vec::new();

        if let Some(gcp_project_id) = self.gcp_project_id {
            opts.extend(vec!["--gcp-project-id".to_string(), gcp_project_id]);
        }
        if let Some(sk_share_secret_id) = self.sk_share_secret_id {
            opts.extend(vec!["--sk-share-secret-id".to_string(), sk_share_secret_id]);
        }

        opts
    }
}

pub type SecretNodeStorageBox = Box<dyn SecretNodeStorage + Send + Sync>;

pub async fn init(opts: &Options) -> Result<SecretNodeStorageBox> {
    match &opts.sk_share_secret_id {
        Some(sk_share_secret_id) => Ok(Box::new(
            SecretManagerNodeStorage::new(
                opts.gcp_project_id.clone().unwrap(), // Guaranteed to be present
                sk_share_secret_id.clone(),
            )
            .await?,
        ) as SecretNodeStorageBox),
        None => Ok(Box::<MemoryNodeStorage>::default() as SecretNodeStorageBox),
    }
}

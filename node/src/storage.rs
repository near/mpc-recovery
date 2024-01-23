use crate::{
    protocol::state::PersistentNodeData,
    value::{FromValue, IntoValue},
};
use async_trait::async_trait;
use google_datastore1::{
    api::{CommitRequest, Entity, Mutation},
    oauth2::AccessTokenAuthenticator,
    Datastore,
};
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
                &format!(
                    "projects/{}/secrets/{}",
                    self.gcp_project_id, self.sk_share_secret_id
                ),
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
            // GCP does not allow to upload empty secrets, so we reserve 1-byte values as a
            // placeholder for empty secrets.
            Some(SecretPayload {
                data: Some(data), ..
            }) if data.len() > 1 => Ok(Some(serde_json::from_slice(&data)?)),
            _ => {
                tracing::info!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }
}

/// Configures storage.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "storage_options")]
pub struct Options {
    /// Environment name, e.g. `dev` or `prod`
    pub env: String,
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

pub struct GcsDatastore {
    env: String,
    project_id: String,
    datastore: Datastore<HttpsConnector<HttpConnector>>,
}

impl GcsDatastore {
    pub async fn new(
        env: String,
        project_id: String,
        gcp_datastore_url: Option<String>,
    ) -> anyhow::Result<Self> {
        let client = hyper::Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        );

        let datastore = if let Some(gcp_datastore_url) = gcp_datastore_url {
            // Assuming custom GCP URL points to an emulator, so the token does not matter
            let authenticator = AccessTokenAuthenticator::builder("TOKEN".to_string())
                .build()
                .await?;
            let mut datastore = Datastore::new(client, authenticator);
            datastore.base_url(gcp_datastore_url.clone());
            datastore.root_url(gcp_datastore_url);
            datastore
        } else {
            let opts = ApplicationDefaultCredentialsFlowOpts::default();
            let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts)
                .await
            {
                ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
                ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
            };
            Datastore::new(client, authenticator)
        };
        Ok(Self {
            env,
            project_id,
            datastore,
        })
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn upsert<T: IntoValue + KeyKind>(&self, value: T) -> anyhow::Result<()> {
        let mut entity = Entity::from_value(value.into_value())?;
        let path_element = entity
            .key
            .as_mut()
            .and_then(|k| k.path.as_mut())
            .and_then(|p| p.first_mut());
        if let Some(path_element) = path_element {
            // We can't create multiple datastore databases in GCP, so we have to suffix
            // type kinds with env (`dev`, `prod`).
            path_element.kind = Some(format!("{}-{}", T::kind(), self.env))
        }

        let request = CommitRequest {
            database_id: Some("".to_string()),
            mode: Some(String::from("NON_TRANSACTIONAL")),
            mutations: Some(vec![Mutation {
                insert: None,
                delete: None,
                update: None,
                base_version: None,
                upsert: Some(entity),
                update_time: None,
            }]),
            single_use_transaction: None,
            transaction: None,
        };

        tracing::debug!(?request);
        let (_, response) = self
            .datastore
            .projects()
            .commit(request, &self.project_id)
            .doit()
            .await?;
        tracing::debug!(?response, "received response");

        Ok(())
    }
}

pub trait KeyKind {
    fn kind() -> String;
}

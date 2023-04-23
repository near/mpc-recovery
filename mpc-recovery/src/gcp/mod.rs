pub mod error;
pub mod value;

use self::value::{FromValue, IntoValue};
use google_datastore1::api::{CommitRequest, Entity, Key, LookupRequest, Mutation, PathElement};
use google_datastore1::oauth2::AccessTokenAuthenticator;
use google_datastore1::Datastore;
use google_secretmanager1::oauth2::authenticator::ApplicationDefaultCredentialsTypes;
use google_secretmanager1::oauth2::{
    ApplicationDefaultCredentialsAuthenticator, ApplicationDefaultCredentialsFlowOpts,
};
use google_secretmanager1::SecretManager;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;

#[derive(Clone)]
pub struct GcpService {
    project_id: String,
    datastore: Datastore<HttpsConnector<HttpConnector>>,
    secret_manager: SecretManager<HttpsConnector<HttpConnector>>,
}

pub trait KeyKind {
    fn kind() -> String;
}

impl GcpService {
    pub async fn new(
        project_id: String,
        gcp_datastore_url: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut datastore;
        let secret_manager;
        let client = hyper::Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        );
        if let Some(gcp_datastore_url) = gcp_datastore_url {
            // Assuming custom GCP URL points to an emulator, so the token does not matter
            let authenticator = AccessTokenAuthenticator::builder("TOKEN".to_string())
                .build()
                .await?;
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
            datastore = Datastore::new(client, authenticator);
            datastore.base_url(gcp_datastore_url.clone());
            datastore.root_url(gcp_datastore_url);
        } else {
            let opts = ApplicationDefaultCredentialsFlowOpts::default();
            let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts)
                .await
            {
                ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
                ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
            };
            secret_manager = SecretManager::new(client.clone(), authenticator.clone());
            datastore = Datastore::new(client, authenticator);
        }

        Ok(Self {
            project_id,
            datastore,
            secret_manager,
        })
    }

    #[tracing::instrument(level = "debug", skip_all, fields(name = name.as_ref()))]
    pub async fn load_secret<T: AsRef<str>>(&self, name: T) -> anyhow::Result<Vec<u8>> {
        let (_, response) = self
            .secret_manager
            .projects()
            .secrets_versions_access(name.as_ref())
            .doit()
            .await?;
        let secret_payload = response
            .payload
            .ok_or_else(|| anyhow::anyhow!("secret value is missing payload"))?;
        let data = secret_payload
            .data
            .ok_or_else(|| anyhow::anyhow!("secret value payload is missing data"))?;
        tracing::debug!("loaded secret successfully");

        Ok(data)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(key = name_key.to_string()))]
    pub async fn get<K: ToString, T: FromValue + KeyKind>(&self, name_key: K) -> anyhow::Result<T> {
        let request = LookupRequest {
            keys: Some(vec![Key {
                path: Some(vec![PathElement {
                    kind: Some(T::kind()),
                    name: Some(name_key.to_string()),
                    id: None,
                }]),
                partition_id: None,
            }]),
            read_options: None,
            database_id: Some("".to_string()),
        };
        let (_, response) = self
            .datastore
            .projects()
            .lookup(request, &self.project_id)
            .doit()
            .await?;
        tracing::debug!(?response, "received response");
        let found_entity = response
            .found
            .and_then(|mut results| results.pop())
            .and_then(|result| result.entity)
            .ok_or_else(|| anyhow::anyhow!("not found"))?;
        Ok(T::from_value(found_entity.into_value())?)
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn insert<T: IntoValue>(&self, value: T) -> anyhow::Result<()> {
        let entity = Entity::from_value(value.into_value())?;

        let request = CommitRequest {
            database_id: Some("".to_string()),
            mode: Some(String::from("NON_TRANSACTIONAL")),
            mutations: Some(vec![Mutation {
                insert: Some(entity),
                delete: None,
                update: None,
                base_version: None,
                upsert: None,
                update_time: None,
            }]),
            single_use_transaction: None,
            transaction: None,
        };
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

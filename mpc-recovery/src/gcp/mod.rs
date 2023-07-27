pub mod error;
pub mod value;

use self::value::{FromValue, IntoValue};
use google_datastore1::api::{
    CommitRequest, Entity, EntityResult, Key, KindExpression, LookupRequest, Mutation, PathElement,
    Query, RunQueryRequest,
};
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
    env: String,
    project_id: String,
    datastore: Datastore<HttpsConnector<HttpConnector>>,
    secret_manager: SecretManager<HttpsConnector<HttpConnector>>,
}

pub trait KeyKind {
    fn kind() -> String;
}

impl GcpService {
    pub async fn new(
        env: String,
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
            env,
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
            .secrets_versions_access(&format!(
                "projects/{}/secrets/{}",
                self.project_id,
                name.as_ref()
            ))
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
    pub async fn get<K: ToString, T: FromValue + KeyKind>(
        &self,
        name_key: K,
    ) -> anyhow::Result<Option<T>> {
        let request = LookupRequest {
            keys: Some(vec![Key {
                path: Some(vec![PathElement {
                    // We can't create multiple datastore databases in GCP, so we have to suffix
                    // type kinds with env (`dev`, `prod`).
                    kind: Some(format!("{}-{}", T::kind(), self.env)),
                    name: Some(name_key.to_string()),
                    id: None,
                }]),
                partition_id: None,
            }]),
            read_options: None,
            database_id: Some("".to_string()),
        };
        tracing::debug!(?request);
        let (_, response) = self
            .datastore
            .projects()
            .lookup(request, &self.project_id)
            .doit()
            .await?;
        tracing::debug!(?response, "received response");
        match response
            .found
            .and_then(|mut results| results.pop())
            .and_then(|result| result.entity)
        {
            Some(found_entity) => Ok(Some(T::from_value(found_entity.into_value())?)),
            None => Ok(None),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn insert<T: IntoValue + KeyKind>(&self, value: T) -> anyhow::Result<()> {
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

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn update<T: IntoValue + KeyKind>(&self, value: T) -> anyhow::Result<()> {
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
                update: Some(entity),
                base_version: None,
                upsert: None,
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

    pub async fn fetch_entities<T: KeyKind>(&self) -> anyhow::Result<Vec<EntityResult>> {
        let kind: String = format!("{}-{}", T::kind(), self.env);
        let req = RunQueryRequest {
            database_id: Some("".to_string()),
            partition_id: Default::default(),
            read_options: Default::default(),
            query: Some(Query {
                projection: None,
                kind: Some(vec![KindExpression { name: Some(kind) }]),
                filter: None,
                order: None,
                distinct_on: Some(vec![]),
                start_cursor: None,
                end_cursor: None,
                offset: None,
                limit: None,
            }),
            gql_query: None,
        };

        let (_hyper_resp, query_resp) = self
            .datastore
            .projects()
            .run_query(req, &self.project_id)
            .doit()
            .await?;
        let batch = query_resp
            .batch
            .ok_or_else(|| anyhow::anyhow!("Could not retrieve batch while fetching entities"))?;

        batch.entity_results.ok_or_else(|| {
            anyhow::anyhow!("Could not retrieve entity results while fetching entities")
        })
    }
}

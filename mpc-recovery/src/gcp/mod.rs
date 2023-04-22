use google_datastore1::api::{
    ArrayValue, CommitRequest, Entity, Key, LookupRequest, Mutation, PathElement, Value,
};
use google_datastore1::Datastore;
use google_secretmanager1::oauth2::authenticator::ApplicationDefaultCredentialsTypes;
use google_secretmanager1::oauth2::{
    ApplicationDefaultCredentialsAuthenticator, ApplicationDefaultCredentialsFlowOpts,
};
use google_secretmanager1::SecretManager;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;

pub trait DatastoreEntity {
    fn kind() -> String;
    fn name(&self) -> String;
}

pub fn to_datastore_value<T: Serialize>(x: T) -> anyhow::Result<Value> {
    match serde_json::to_value(x)? {
        serde_json::Value::Null => Ok(Value {
            null_value: Some(String::from("NULL_VALUE")),
            ..Value::default()
        }),
        serde_json::Value::Bool(x) => Ok(Value {
            boolean_value: Some(x),
            ..Value::default()
        }),
        serde_json::Value::Number(x) => {
            if x.is_f64() {
                Ok(Value {
                    double_value: Some(
                        x.as_f64()
                            .ok_or_else(|| anyhow::anyhow!("non-serializable f64"))?,
                    ),
                    ..Value::default()
                })
            } else if x.is_i64() {
                Ok(Value {
                    integer_value: Some(
                        x.as_i64()
                            .ok_or_else(|| anyhow::anyhow!("non-serializable i64"))?,
                    ),
                    ..Value::default()
                })
            } else if x.is_u64() {
                Ok(Value {
                    integer_value: Some(
                        x.as_i64()
                            .ok_or_else(|| anyhow::anyhow!("non-serializable u64"))?,
                    ),
                    ..Value::default()
                })
            } else {
                anyhow::bail!("unsupported type");
            }
        }
        serde_json::Value::String(x) => Ok(Value {
            string_value: Some(x),
            ..Value::default()
        }),
        serde_json::Value::Array(xs) => {
            let mut any_error = None;
            let xs = xs
                .into_iter()
                .filter_map(|x| {
                    let result = to_datastore_value(x);
                    match result {
                        Ok(result) => Some(result),
                        Err(e) => {
                            any_error = Some(e);
                            None
                        }
                    }
                })
                .collect::<Vec<_>>();
            if let Some(e) = any_error {
                Err(e)
            } else {
                Ok(Value {
                    array_value: Some(ArrayValue { values: Some(xs) }),
                    ..Value::default()
                })
            }
        }
        serde_json::Value::Object(xs) => {
            let mut any_error = None;
            let xs = xs
                .into_iter()
                .filter_map(|(k, v)| {
                    let v = to_datastore_value(v);
                    match v {
                        Ok(v) => Some((k, v)),
                        Err(e) => {
                            any_error = Some(e);
                            None
                        }
                    }
                })
                .collect::<HashMap<_, _>>();
            if let Some(e) = any_error {
                Err(e)
            } else {
                Ok(Value {
                    entity_value: Some(Entity {
                        properties: Some(xs),
                        key: None,
                    }),
                    ..Value::default()
                })
            }
        }
    }
}

fn from_datastore_value<T: serde::de::DeserializeOwned>(value: Value) -> anyhow::Result<T> {
    let serde_value: serde_json::Value;
    if let Some(xs) = value.entity_value {
        let mut any_error = None;
        let xs = xs
            .properties
            .unwrap_or(HashMap::default())
            .into_iter()
            .filter_map(|(k, v)| {
                let result = from_datastore_value(v);
                match result {
                    Ok(v) => Some((k, v)),
                    Err(e) => {
                        any_error = Some(e);
                        None
                    }
                }
            })
            .collect::<serde_json::Map<_, _>>();
        if let Some(e) = any_error {
            return Err(e);
        } else {
            serde_value = serde_json::Value::Object(xs);
        }
    } else if let Some(xs) = value.timestamp_value {
        serde_value = serde_json::Value::String(xs.to_string());
    } else if let Some(_) = value.geo_point_value {
        anyhow::bail!("unimplemented");
    } else if let Some(_) = value.blob_value {
        anyhow::bail!("unimplemented");
    } else if let Some(xs) = value.double_value {
        serde_value = serde_json::Value::Number(
            serde_json::Number::from_f64(xs)
                .ok_or_else(|| anyhow::anyhow!("invalid f64 values: {xs}"))?,
        );
    } else if let Some(_) = value.meaning {
        anyhow::bail!("unimplemented");
    } else if let Some(_) = value.exclude_from_indexes {
        anyhow::bail!("unimplemented");
    } else if let Some(xs) = value.string_value {
        serde_value = serde_json::Value::String(xs);
    } else if let Some(_) = value.key_value {
        anyhow::bail!("unimplemented");
    } else if let Some(xs) = value.boolean_value {
        serde_value = serde_json::Value::Bool(xs);
    } else if let Some(xs) = value.array_value {
        let mut any_error = None;
        let xs = xs
            .values
            .unwrap_or(Vec::default())
            .into_iter()
            .filter_map(|x| {
                let result = from_datastore_value(x);
                match result {
                    Ok(result) => Some(result),
                    Err(e) => {
                        any_error = Some(e);
                        None
                    }
                }
            })
            .collect::<Vec<_>>();
        if let Some(e) = any_error {
            return Err(e);
        } else {
            serde_value = serde_json::Value::Array(xs);
        }
    } else if let Some(xs) = value.integer_value {
        serde_value = serde_json::Value::Number(serde_json::Number::from(xs));
    } else if let Some(_) = value.null_value {
        serde_value = serde_json::Value::Null;
    } else {
        anyhow::bail!("unimplemented");
    }

    Ok(serde_json::from_value(serde_value)?)
}

fn from_datastore_entity<T: serde::de::DeserializeOwned>(value: Entity) -> anyhow::Result<T> {
    let value = Value {
        entity_value: Some(value),
        ..Default::default()
    };
    from_datastore_value(value)
}

#[derive(Clone)]
pub struct GcpService {
    project_id: String,
    datastore: Datastore<HttpsConnector<HttpConnector>>,
    secret_manager: SecretManager<HttpsConnector<HttpConnector>>,
}

impl GcpService {
    pub async fn new(project_id: String) -> anyhow::Result<Self> {
        let opts = ApplicationDefaultCredentialsFlowOpts::default();
        let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts).await {
            ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
            ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
        };
        let client = hyper::Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        );
        let secret_manager = SecretManager::new(client.clone(), authenticator.clone());
        let datastore = Datastore::new(client, authenticator);

        Ok(Self {
            project_id,
            datastore,
            secret_manager,
        })
    }

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

        Ok(secret_payload
            .data
            .ok_or_else(|| anyhow::anyhow!("secret value payload is missing data"))?)
    }

    pub async fn get<K: ToString, T: DeserializeOwned + DatastoreEntity>(
        &self,
        name_key: K,
    ) -> anyhow::Result<T> {
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
        let found_entity = response
            .found
            .and_then(|mut results| results.pop())
            .and_then(|result| result.entity)
            .ok_or_else(|| anyhow::anyhow!("not found"))?;
        from_datastore_entity(found_entity)
    }

    pub async fn insert<T: Serialize + DatastoreEntity>(&self, value: T) -> anyhow::Result<()> {
        let name = value.name();
        let mut entity = to_datastore_value(value)?
            .entity_value
            .ok_or_else(|| anyhow::anyhow!("failed to convert value to Datastore entity"))?;
        entity.key = Some(Key {
            partition_id: None,
            path: Some(vec![PathElement {
                id: None,
                kind: Some(T::kind()),
                name: Some(name),
            }]),
        });

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
        self.datastore
            .projects()
            .commit(request, &self.project_id)
            .doit()
            .await?;

        Ok(())
    }
}

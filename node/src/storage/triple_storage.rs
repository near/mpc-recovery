use crate::gcp::error;
use crate::gcp::{
    error::ConvertError,
    value::{FromValue, IntoValue, Value},
    KeyKind,
};
use crate::gcp::{DatastoreService, GcpService};
use crate::protocol::triple::{Triple, TripleId};
use async_trait::async_trait;
use google_datastore1::api::{
    Filter, Key, PathElement, PropertyFilter, PropertyReference, Value as DatastoreValue,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct TripleData {
    pub account_id: String,
    pub triple: Triple,
}

impl KeyKind for TripleData {
    fn kind() -> String {
        "triples".to_string()
    }
}

impl IntoValue for TripleData {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "account_id".to_string(),
            Value::StringValue(self.account_id.clone()),
        );
        properties.insert(
            "triple_id".to_string(),
            Value::IntegerValue(self.triple.id as i64),
        );
        properties.insert(
            "triple_share".to_string(),
            Value::StringValue(serde_json::to_string(&self.triple.share).unwrap()),
        );
        properties.insert(
            "triple_public".to_string(),
            Value::StringValue(serde_json::to_string(&self.triple.public).unwrap()),
        );
        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(TripleData::kind()),
                    name: Some(format!("{}/{}", self.account_id, &self.triple.id)),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for TripleData {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, triple_id) = properties
                    .remove_entry("triple_id")
                    .ok_or_else(|| ConvertError::MissingProperty("triple_id".to_string()))?;

                let triple_id = i64::from_value(triple_id)?;
                let (_, account_id) = properties
                    .remove_entry("account_id")
                    .ok_or_else(|| ConvertError::MissingProperty("account_id".to_string()))?;
                let account_id = String::from_value(account_id)?;

                let (_, triple_share) = properties
                    .remove_entry("triple_share")
                    .ok_or_else(|| ConvertError::MissingProperty("triple_share".to_string()))?;
                let triple_share = String::from_value(triple_share)?;
                let triple_share = serde_json::from_str(&triple_share)
                    .map_err(|_| ConvertError::MalformedProperty("triple_share".to_string()))?;

                let (_, triple_public) = properties
                    .remove_entry("triple_public")
                    .ok_or_else(|| ConvertError::MissingProperty("triple_public".to_string()))?;
                let triple_public = String::from_value(triple_public)?;
                let triple_public = serde_json::from_str(&triple_public)
                    .map_err(|_| ConvertError::MalformedProperty("triple_public".to_string()))?;

                Ok(Self {
                    account_id,
                    triple: Triple {
                        id: triple_id as u64,
                        share: triple_share,
                        public: triple_public,
                    },
                })
            }
            value => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }
}

type TripleResult<T> = std::result::Result<T, error::DatastoreStorageError>;

#[async_trait]
pub trait TripleNodeStorage {
    async fn insert(&mut self, data: TripleData) -> TripleResult<()>;
    async fn delete(&mut self, data: TripleData) -> TripleResult<()>;
    async fn load(&self) -> TripleResult<Vec<TripleData>>;
    fn account_id(&self) -> String;
}

#[derive(Default, Clone)]
struct MemoryTripleNodeStorage {
    triples: HashMap<TripleId, Triple>,
    account_id: String,
}

#[async_trait]
impl TripleNodeStorage for MemoryTripleNodeStorage {
    async fn insert(&mut self, data: TripleData) -> TripleResult<()> {
        self.triples.insert(data.triple.id, data.triple);
        Ok(())
    }

    async fn delete(&mut self, data: TripleData) -> TripleResult<()> {
        self.triples.remove(&data.triple.id);
        Ok(())
    }

    async fn load(&self) -> TripleResult<Vec<TripleData>> {
        let mut res: Vec<TripleData> = vec![];
        for (_, triple) in self.triples.clone() {
            res.push(TripleData {
                account_id: self.account_id(),
                triple,
            });
        }
        Ok(res)
    }

    fn account_id(&self) -> String {
        self.account_id.clone()
    }
}

#[derive(Clone)]
struct DataStoreTripleNodeStorage {
    datastore: DatastoreService,
    account_id: String,
}

impl DataStoreTripleNodeStorage {
    fn new(datastore: DatastoreService, account_id: String) -> Self {
        Self {
            datastore,
            account_id,
        }
    }
}

#[async_trait]
impl TripleNodeStorage for DataStoreTripleNodeStorage {
    async fn insert(&mut self, data: TripleData) -> TripleResult<()> {
        tracing::info!("inserting triples using datastore");
        self.datastore.upsert(data).await?;
        Ok(())
    }

    async fn delete(&mut self, data: TripleData) -> TripleResult<()> {
        tracing::info!("deleting triples using datastore");
        self.datastore.delete(data).await?;
        Ok(())
    }

    async fn load(&self) -> TripleResult<Vec<TripleData>> {
        tracing::info!("loading triples using datastore");
        let account_id_val = DatastoreValue::from_value(self.account_id().into_value())?;
        let filter = Filter {
            composite_filter: None,
            property_filter: Some(PropertyFilter {
                op: Some("Equal".to_string()),
                property: Some(PropertyReference {
                    name: Some("account_id".to_string()),
                }),
                value: Some(account_id_val),
            }),
        };
        let response = self
            .datastore
            .fetch_entities::<TripleData>(Some(filter))
            .await?;
        let mut res: Vec<TripleData> = vec![];
        for entity_result in response {
            let entity = entity_result.entity.unwrap();
            let entity_value = entity.into_value();
            let triple_data = TripleData::from_value(entity_value).unwrap();
            res.push(triple_data);
        }
        Ok(res)
    }

    fn account_id(&self) -> String {
        self.account_id.clone()
    }
}

pub type TripleNodeStorageBox = Box<dyn TripleNodeStorage + Send + Sync>;

pub struct TripleStorage {
    pub storage: TripleNodeStorageBox,
}

pub type LockTripleNodeStorageBox = Arc<RwLock<TripleNodeStorageBox>>;

pub fn init(gcp_service: &Option<GcpService>, account_id: String) -> TripleNodeStorageBox {
    match gcp_service {
        Some(gcp) if gcp.datastore.is_some() => Box::new(DataStoreTripleNodeStorage::new(
            gcp.datastore.clone().unwrap(),
            account_id,
        )) as TripleNodeStorageBox,
        _ => Box::new(MemoryTripleNodeStorage {
            triples: HashMap::new(),
            account_id,
        }) as TripleNodeStorageBox,
    }
}

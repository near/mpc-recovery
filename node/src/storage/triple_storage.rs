use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::gcp::{error, Keyable};
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
use tokio::sync::RwLock;

use near_account_id::AccountId;

pub struct TripleKey<'a> {
    pub account_id: &'a str,
    pub triple_id: TripleId,
}

impl KeyKind for TripleKey<'_> {
    fn kind() -> String {
        "triples".to_string()
    }
}

impl Keyable for TripleKey<'_> {
    fn key(&self) -> Key {
        Key {
            path: Some(vec![PathElement {
                kind: None,
                name: Some(format!("{}/{}", self.account_id, self.triple_id)),
                id: None,
            }]),
            partition_id: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TripleData {
    pub account_id: AccountId,
    pub triple: Triple,
    pub mine: bool,
}

impl KeyKind for TripleData {
    fn kind() -> String {
        "triples".to_string()
    }
}

impl IntoValue for TripleData {
    fn into_value(self) -> Value {
        let triple_key = TripleKey {
            account_id: self.account_id.as_str(),
            triple_id: self.triple.id,
        };
        let mut properties = HashMap::new();
        properties.insert(
            "account_id".to_string(),
            Value::StringValue(self.account_id.to_string()),
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
        properties.insert("mine".to_string(), Value::BooleanValue(self.mine));
        Value::EntityValue {
            key: triple_key.key(),
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
                let account_id = String::from_value(account_id)?.parse().map_err(|err| {
                    ConvertError::MalformedProperty(format!(
                        "TripleData failed to parse account_id: {err:?}"
                    ))
                })?;

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

                let (_, mine) = properties
                    .remove_entry("mine")
                    .ok_or_else(|| ConvertError::MissingProperty("mine".to_string()))?;
                let mine = bool::from_value(mine)?;

                Ok(Self {
                    account_id,
                    triple: Triple {
                        id: triple_id as u64,
                        share: triple_share,
                        public: triple_public,
                    },
                    mine,
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
    async fn insert(&mut self, triple: Triple, mine: bool) -> TripleResult<()>;
    async fn delete(&mut self, id: TripleId) -> TripleResult<()>;
    async fn load(&self) -> TripleResult<Vec<TripleData>>;
    fn account_id(&self) -> &AccountId;
}

#[derive(Clone)]
struct MemoryTripleNodeStorage {
    triples: HashMap<TripleId, Triple>,
    mine: HashSet<TripleId>,
    account_id: AccountId,
}

#[async_trait]
impl TripleNodeStorage for MemoryTripleNodeStorage {
    async fn insert(&mut self, triple: Triple, mine: bool) -> TripleResult<()> {
        if mine {
            self.mine.insert(triple.id);
        }
        self.triples.insert(triple.id, triple);
        Ok(())
    }

    async fn delete(&mut self, id: TripleId) -> TripleResult<()> {
        self.triples.remove(&id);
        self.mine.remove(&id);
        Ok(())
    }

    async fn load(&self) -> TripleResult<Vec<TripleData>> {
        let mut res: Vec<TripleData> = vec![];
        for (triple_id, triple) in self.triples.clone() {
            let mine = self.mine.contains(&triple_id);
            res.push(TripleData {
                account_id: self.account_id().clone(),
                triple,
                mine,
            });
        }
        Ok(res)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[derive(Clone)]
struct DataStoreTripleNodeStorage {
    datastore: DatastoreService,
    account_id: AccountId,
}

impl DataStoreTripleNodeStorage {
    fn new(datastore: DatastoreService, account_id: &AccountId) -> Self {
        Self {
            datastore,
            account_id: account_id.clone(),
        }
    }
}

#[async_trait]
impl TripleNodeStorage for DataStoreTripleNodeStorage {
    async fn insert(&mut self, triple: Triple, mine: bool) -> TripleResult<()> {
        tracing::debug!(id = triple.id, "inserting triples using datastore");
        self.datastore
            .upsert(TripleData {
                account_id: self.account_id().clone(),
                triple,
                mine,
            })
            .await?;
        Ok(())
    }

    async fn delete(&mut self, id: TripleId) -> TripleResult<()> {
        tracing::debug!(id, "deleting triples using datastore");
        self.datastore
            .delete(TripleKey {
                account_id: self.account_id.as_str(),
                triple_id: id,
            })
            .await?;
        Ok(())
    }

    async fn load(&self) -> TripleResult<Vec<TripleData>> {
        tracing::debug!("loading triples using datastore");
        let filter = if self.datastore.is_emulator() {
            None
        } else {
            Some(Filter {
                composite_filter: None,
                property_filter: Some(PropertyFilter {
                    op: Some("Equal".to_string()),
                    property: Some(PropertyReference {
                        name: Some("account_id".to_string()),
                    }),
                    value: Some(DatastoreValue::from_value(self.account_id().into_value())?),
                }),
            })
        };
        let response = self.datastore.fetch_entities::<TripleData>(filter).await?;
        let mut res: Vec<TripleData> = vec![];
        for entity_result in response {
            let entity = entity_result.entity.ok_or_else(|| {
                error::DatastoreStorageError::FetchEntitiesError(
                    "entity was not able to unwrapped".to_string(),
                )
            })?;
            let triple_data = TripleData::from_value(entity.into_value())?;
            if &triple_data.account_id == self.account_id() {
                res.push(triple_data);
            }
        }
        tracing::debug!(count = res.len(), "loading triples success");
        Ok(res)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

pub type TripleNodeStorageBox = Box<dyn TripleNodeStorage + Send + Sync>;

pub struct TripleStorage {
    pub storage: TripleNodeStorageBox,
}

pub type LockTripleNodeStorageBox = Arc<RwLock<TripleNodeStorageBox>>;

pub fn init(gcp_service: Option<&GcpService>, account_id: &AccountId) -> TripleNodeStorageBox {
    match gcp_service {
        Some(gcp) => Box::new(DataStoreTripleNodeStorage::new(
            gcp.datastore.clone(),
            account_id,
        )) as TripleNodeStorageBox,
        _ => Box::new(MemoryTripleNodeStorage {
            triples: HashMap::new(),
            mine: HashSet::new(),
            account_id: account_id.clone(),
        }) as TripleNodeStorageBox,
    }
}

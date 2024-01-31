use async_trait::async_trait;
use crate::gcp::{GcpService, DatastoreService};
use crate::protocol::triple::{TripleId, Triple};
use std::collections::HashMap;
use crate::gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    };
use google_datastore1::api::{Key, PathElement};
use crate::gcp::error;
use crate::storage::Options;
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
            Value::StringValue(
                serde_json::to_string(&self.triple.share).unwrap(),
            ),
        );
        properties.insert(
            "triple_public".to_string(),
            Value::StringValue(
                serde_json::to_string(&self.triple.public).unwrap(),
            ),
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
                // let triple_id = String::from_value(triple_id)?.parse().ok_or_else(|| {
                //     ConvertError::ParseInt("Could not parse triple_id to u64".to_string())
                // });
                let triple_id = i64::from_value(triple_id)?;
                let (_, account_id) = properties
                    .remove_entry("account_id")
                    .ok_or_else(|| {
                        ConvertError::MissingProperty("account_id".to_string())
                    })?;
                let account_id = String::from_value(account_id)?;

                let (_, triple_share) = properties
                    .remove_entry("triple_share")
                    .ok_or_else(|| ConvertError::MissingProperty("triple_share".to_string()))?;
                let triple_share = String::from_value(triple_share)?;
                let triple_share = serde_json::from_str(&triple_share)
                    .map_err(|_| ConvertError::MalformedProperty("triple_share".to_string()))?;

                let (_, triple_public) = properties
                    .remove_entry("triple_public")
                    .ok_or_else(|| {
                        ConvertError::MissingProperty("triple_public".to_string())
                    })?;
                let triple_public = String::from_value(triple_public)?;
                let triple_public = serde_json::from_str(&triple_public)
                    .map_err(|_| ConvertError::MalformedProperty("triple_public".to_string()))?;

                Ok(Self {
                    account_id,
                    triple: Triple {
                        id: triple_id as u64,
                        share: triple_share,
                        public: triple_public
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
        let mut res: Vec<TripleData> = vec!();
        for (_, triple) in self.triples.clone() {
            res.push(TripleData {account_id: self.account_id(), triple: triple});
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
    kind: String,
    account_id: String,
}

impl DataStoreTripleNodeStorage {
    fn new(gcp_service: &GcpService, account_id: String) -> Self {
        Self {
            datastore: gcp_service.datastore.clone(),
            kind: "triples".to_string(),
            account_id
        }
    }
}

#[async_trait]
impl TripleNodeStorage for DataStoreTripleNodeStorage {
    async fn insert(&mut self, data: TripleData) -> TripleResult<()> {
        println!("using datastore");
        self.datastore
            .upsert(data)
            .await?;
        Ok(())
    }

    async fn delete(&mut self, data: TripleData) -> TripleResult<()> {
        self.datastore
            .delete(data)
            .await?;
        Ok(())
    }

    async fn load(&self) -> TripleResult<Vec<TripleData>> {
        let response = self.datastore.fetch_entities::<TripleData>()
            .await?;
        // TODO:convert the response to hashmap
        let mut res: Vec<TripleData> = vec!();
        for entity_result in response {
            let entity = entity_result.entity.unwrap();
            let entity_value = entity.into_value();
            let triple_data = TripleData::from_value(entity_value).unwrap();
            //let res = gcp_service.datastore.delete(triple_data).await.unwrap();
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
        Some(gcp) => Box::new(
            DataStoreTripleNodeStorage::new(
                &gcp, 
                account_id
            )) as TripleNodeStorageBox ,
        _ => Box::new(MemoryTripleNodeStorage {triples: HashMap::new(), account_id}) as TripleNodeStorageBox,
    }
}

mod test {
    use crate::storage;
    use crate::gcp::GcpService;
    use crate::storage::triple_storage;

    // TODO: This test currently takes 22 seconds on my machine, which is much slower than it should be
    // Improve this before we make more similar tests
    #[test]
    fn test_triple_load_and_delete() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let project_id = Some("pagoda-discovery-platform-dev".to_string());
            let env = "xiangyi-dev".to_string();
            let storage_options = storage::Options{gcp_project_id: project_id.clone(), sk_share_secret_id:Some("multichain-sk-share-dev-0".to_string()), gcp_datastore_url:None, env: Some(env)};
            let gcp_service = GcpService::init(&storage_options).await.unwrap();
            let mut triple_storage = triple_storage::init(&gcp_service,  "4".to_string());
            
            let load_res = triple_storage.load().await;
            println!("res: {:?}", load_res);
            
            for triple_data in load_res.unwrap() {
                let res = triple_storage.delete(triple_data).await;
                println!("res: {:?}", res);
            }
        })
    }
}

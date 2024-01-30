use crate::{protocol::state::PersistentNodeData, gcp::SecretManagerService};
use async_trait::async_trait;
use crate::gcp::{GcpService, SecretResult};
use crate::storage::Options;

#[async_trait]
pub trait SecretNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()>;
    async fn load(&self) -> SecretResult<Option<PersistentNodeData>>;
}

#[derive(Default)]
struct MemoryNodeStorage {
    node_data: Option<PersistentNodeData>,
}

#[async_trait]
impl SecretNodeStorage for MemoryNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        Ok(self.node_data.clone())
    }
}

struct SecretManagerNodeStorage {
    secret_manager: SecretManagerService,
    sk_share_secret_id: String,
}

impl SecretManagerNodeStorage {
    fn new(secret_manager: &SecretManagerService, sk_share_secret_id: String) -> Self {
        Self {
            secret_manager: secret_manager.clone(),
            sk_share_secret_id,
        }
    }
}

#[async_trait]
impl SecretNodeStorage for SecretManagerNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        self.secret_manager.store_secret(&serde_json::to_vec(data)?, &self.sk_share_secret_id).await?;
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        let raw_data = self.secret_manager.load_secret(&self.sk_share_secret_id).await?;
        match raw_data {
            Some(data) if data.len() > 1 => Ok(Some(serde_json::from_slice(&data)?)),
            _ => Ok(None),
        }
    }
}

pub type SecretNodeStorageBox = Box<dyn SecretNodeStorage + Send + Sync>;

pub fn init(gcp_service: &Option<GcpService>, opts: &Options) -> SecretNodeStorageBox {
    match gcp_service {
        Some(gcp) if opts.sk_share_secret_id.is_some() => Box::new(
            SecretManagerNodeStorage::new(
                &gcp.secret_manager, 
                opts.clone().sk_share_secret_id.unwrap().clone(),
            )) as SecretNodeStorageBox,
        _ => Box::<MemoryNodeStorage>::default() as SecretNodeStorageBox,
    }
}
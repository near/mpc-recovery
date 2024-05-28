use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gcp::{GcpService, SecretResult};
use crate::storage::Options;
use crate::{gcp::SecretManagerService, protocol::state::PersistentNodeData};
use async_trait::async_trait;

use near_account_id::AccountId;

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
        tracing::info!("storing PersistentNodeData using memory");
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::info!("loading PersistentNodeData using memory");
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
        tracing::debug!("storing PersistentNodeData using SecretNodeStorage");
        self.secret_manager
            .store_secret(&serde_json::to_vec(data)?, &self.sk_share_secret_id)
            .await?;
        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        tracing::debug!("loading PersistentNodeData using SecretNodeStorage");
        let raw_data = self
            .secret_manager
            .load_secret(&self.sk_share_secret_id)
            .await?;
        match raw_data {
            Some(data) if data.len() > 1 => Ok(Some(serde_json::from_slice(&data)?)),
            _ => {
                tracing::info!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }
}

struct DiskNodeStorage {
    path: PathBuf,
}

impl DiskNodeStorage {
    pub fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }
}

#[async_trait]
impl SecretNodeStorage for DiskNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> SecretResult<()> {
        tracing::debug!("storing PersistentNodeData using DiskNodeStorage");
        let mut file = File::create(self.path.as_os_str()).await?;
        // Serialize the person object to JSON and convert directly to bytes
        let json_bytes = serde_json::to_vec(data)?;
        // Write the serialized JSON bytes to the file
        file.write_all(&json_bytes).await?;

        Ok(())
    }

    async fn load(&self) -> SecretResult<Option<PersistentNodeData>> {
        println!("loading PersistentNodeData using DiskNodeStorage");
        // Open the file asynchronously
        let file_res = File::open(self.path.as_os_str()).await;

        match file_res {
            Ok(mut file) => {
                let mut contents = Vec::new();
                // Read the contents of the file into the vector
                println!("loading PersistentNodeData using DiskNodeStorage: reading");
                file.read_to_end(&mut contents).await?;

                println!("loading PersistentNodeData using DiskNodeStorage: read done");
                // Deserialize the JSON content to a PersistentNodeData object
                let data: PersistentNodeData = serde_json::from_slice(&contents)?;

                Ok(Some(data))
            }
            _ => Ok(None),
        }
    }
}

pub type SecretNodeStorageBox = Box<dyn SecretNodeStorage + Send + Sync>;

pub fn init(
    gcp_service: Option<&GcpService>,
    opts: &Options,
    account_id: &AccountId,
) -> SecretNodeStorageBox {
    match gcp_service {
        Some(gcp) if opts.sk_share_secret_id.is_some() => Box::new(SecretManagerNodeStorage::new(
            &gcp.secret_manager.clone(),
            opts.clone().sk_share_secret_id.unwrap().clone(),
        )) as SecretNodeStorageBox,
        _ => {
            if let Some(sk_share_local_path) = &opts.sk_share_local_path {
                let path = format!("{sk_share_local_path}-{account_id}");
                Box::new(DiskNodeStorage::new(&path)) as SecretNodeStorageBox
            } else {
                Box::<MemoryNodeStorage>::default() as SecretNodeStorageBox
            }
        }
    }
}

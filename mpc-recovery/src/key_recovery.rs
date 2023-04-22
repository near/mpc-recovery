use crate::{gcp::DatastoreEntity, primitives::InternalAccountId};
use near_crypto::{KeyType, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct UserSecretKey {
    pub internal_account_id: InternalAccountId,
    pub secret_key: SecretKey,
}

impl DatastoreEntity for UserSecretKey {
    fn kind() -> String {
        "UserSecretKey".to_string()
    }

    fn name(&self) -> String {
        self.internal_account_id.clone()
    }
}

impl UserSecretKey {
    pub fn random(internal_account_id: InternalAccountId) -> Self {
        Self {
            internal_account_id,
            secret_key: SecretKey::from_random(KeyType::ED25519),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }
}

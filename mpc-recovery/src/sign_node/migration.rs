//! Module that defines all the migrating logic for the sign node
//! when we want to rotate the key if our sign node gets compromised.

// Store both old and new ciphers in GCP. If old cipher exists,
// then we are in a state of migration.

use aes_gcm::Aes256Gcm;
use multi_party_eddsa::protocols::ExpandedKeyPair;

use crate::gcp::GcpService;

use super::user_credentials::EncryptedUserCredentials;

#[derive(Clone)]
pub enum Vault {
    Stable {
        node_key: ExpandedKeyPair,
        cipher: Aes256Gcm,
    },
    Migrating {
        node_key: ExpandedKeyPair,
        old_cipher: Aes256Gcm,
        new_cipher: Aes256Gcm,
    },
}

impl Vault {
    pub fn generate_user_creds(
        &self,
        node_id: usize,
        id: crate::primitives::InternalAccountId,
    ) -> anyhow::Result<EncryptedUserCredentials> {
        let cipher = match self {
            Vault::Stable { cipher, .. } => cipher,
            Vault::Migrating { new_cipher, .. } => new_cipher,
        };

        EncryptedUserCredentials::random(node_id, id, cipher)
    }

    pub fn rotate_cipher(&mut self, new_cipher: Aes256Gcm, gcp_service: GcpService) {
        // let new_cipher = Aes256Gcm::generate_key(&mut OsRng);
        // self.migrate(new_cipher);

    }

    fn migrate(&mut self, new_cipher: Aes256Gcm) {
        match self {
            Vault::Stable { cipher, node_key } => {
                *self = Vault::Migrating {
                    old_cipher: cipher.clone(),
                    new_cipher,
                    node_key: node_key.clone(),
                };
            }
            Vault::Migrating {
                old_cipher,
                new_cipher,
                node_key,
            } => {
                *old_cipher = new_cipher.clone();
            }
        }
    }
}

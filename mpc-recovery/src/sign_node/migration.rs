//! Module that defines all the migrating logic for the sign node
//! when we want to rotate the key if our sign node gets compromised.

// Store both old and new ciphers in GCP. If old cipher exists,
// then we are in a state of migration.

use aes_gcm::Aes256Gcm;
use multi_party_eddsa::protocols::ExpandedKeyPair;

use crate::gcp::value::{FromValue, IntoValue};
use crate::gcp::GcpService;

use super::user_credentials::EncryptedUserCredentials;

#[derive(Clone)]
pub enum Vault {
    Stable {
        node_id: usize,
        node_key: ExpandedKeyPair,
        cipher: Aes256Gcm,
    },
    Migrating {
        node_id: usize,
        node_key: ExpandedKeyPair,
        old_cipher: Aes256Gcm,
        new_cipher: Aes256Gcm,
    },
}

impl Vault {
    pub fn cipher(&self) -> &Aes256Gcm {
        match self {
            Vault::Stable { cipher, .. } => cipher,
            Vault::Migrating { new_cipher, .. } => new_cipher,
        }
    }

    pub fn generate_user_creds(
        &self,
        node_id: usize,
        id: crate::primitives::InternalAccountId,
    ) -> anyhow::Result<EncryptedUserCredentials> {
        EncryptedUserCredentials::random(node_id, id, self.cipher())
    }

    pub async fn rotate_cipher(
        &mut self,
        new_cipher: Aes256Gcm,
        gcp_service: &GcpService,
    ) -> anyhow::Result<()> {
        let Self::Stable {
            node_id, node_key: _, cipher: old_cipher
        } = self else {
            anyhow::bail!("Invalid state to be in while rotating key");
        };

        // TODO: replace with less memory intensive method such that we don't run out of memory
        let entities = gcp_service
            .fetch_entities::<EncryptedUserCredentials>()
            .await?;

        for entity in entities {
            let old_entity = entity.entity.unwrap();
            if !old_entity.key.as_ref().unwrap().path.as_ref().unwrap()[0]
                .name
                .as_ref()
                .unwrap()
                .starts_with(&node_id.to_string())
            {
                println!("Skipping: {:#?}", old_entity.key);
                continue;
            }

            let old_cred = EncryptedUserCredentials::from_value(old_entity.into_value())?;
            let key_pair = old_cred
                .decrypt_key_pair(old_cipher)
                .map_err(|e| anyhow::anyhow!(e))?;

            let new_cred = EncryptedUserCredentials::new(
                old_cred.node_id,
                old_cred.internal_account_id,
                &new_cipher,
                key_pair,
            )?;

            // TODO: send all updates at once?
            gcp_service.update(new_cred).await?;
        }

        Ok(())
    }

    fn _migrate(&mut self, new_cipher: Aes256Gcm) {
        match self {
            Vault::Stable {
                node_id,
                cipher,
                node_key,
            } => {
                *self = Vault::Migrating {
                    old_cipher: cipher.clone(),
                    new_cipher,
                    node_key: node_key.clone(),
                    node_id: *node_id,
                };
            }
            Vault::Migrating {
                old_cipher,
                new_cipher,
                node_key: _,
                node_id: _,
            } => {
                *old_cipher = new_cipher.clone();
            }
        }
    }
}

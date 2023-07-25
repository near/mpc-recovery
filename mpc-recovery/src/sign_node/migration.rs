//! Module that defines all the migrating logic for the sign node
//! when we want to rotate the key if our sign node gets compromised.

// Store both old and new ciphers in GCP. If old cipher exists,
// then we are in a state of migration.

use aes_gcm::Aes256Gcm;
use anyhow::Context;

use crate::gcp::value::{FromValue, IntoValue};
use crate::gcp::GcpService;

use super::user_credentials::EncryptedUserCredentials;

pub async fn rotate_cipher(
    node_id: usize,
    old_cipher: &Aes256Gcm,
    new_cipher: &Aes256Gcm,
    src_gcp_service: &GcpService,
    dest_gcp_service: &GcpService,
) -> anyhow::Result<()> {
    // TODO: replace with less memory intensive method such that we don't run out of memory
    let entities = src_gcp_service
        .fetch_entities::<EncryptedUserCredentials>()
        .await?;

    for entity in entities {
        let old_entity = entity.entity.context("`entity` attr cannot be found")?;
        let entity_path = old_entity
            .key
            .as_ref()
            .context("`key` attr cannot be found")?
            .path
            .as_ref()
            .context("`path` attr cannot be found")?[0]
            .name
            .as_ref()
            .context("`name` attr cannot be found")?;
        let entity_node_id = entity_path
            .split('/')
            .next()
            .context("cannot retrieve entity node_id")?
            .parse::<usize>()?;

        // Check if this entity belongs to this node. This check is needed for integration tests as all
        // entities are stored in the same datastore instead of separate ones during test-time.
        if node_id != entity_node_id {
            continue;
        }

        let old_cred = EncryptedUserCredentials::from_value(old_entity.into_value())?;
        let key_pair = old_cred
            .decrypt_key_pair(old_cipher)
            .map_err(|e| anyhow::anyhow!(e))?;

        let new_cred = EncryptedUserCredentials::new(
            old_cred.node_id,
            old_cred.internal_account_id,
            new_cipher,
            key_pair,
        )?;

        // TODO: send all updates at once?
        dest_gcp_service.upsert(new_cred).await?;
    }

    Ok(())
}

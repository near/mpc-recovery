use crate::{
    primitives::InternalAccountId,
    transaction::{call, to_dalek_public_key},
};
use multi_party_eddsa::protocols::aggsig::KeyAgg;
use near_crypto::{ED25519PublicKey, PublicKey, SecretKey};

pub async fn get_user_recovery_pk(
    client: &reqwest::Client,
    sign_nodes: &[String],
    id: InternalAccountId,
) -> anyhow::Result<PublicKey> {
    let res = call(client, sign_nodes, "public_key", id).await?;

    let pk = KeyAgg::key_aggregation_n(&res, 0).apk;
    to_dalek_public_key(&pk).map(|k| PublicKey::ED25519(ED25519PublicKey(*k.as_bytes())))
}

pub fn _get_user_recovery_sk(_id: InternalAccountId) -> SecretKey {
    // TODO: use key derivation or other techniques to generate a key
    "ed25519:5pFJN3czPAHFWHZYjD4oTtnJE7PshLMeTkSU7CmWkvLaQWchCLgXGF1wwcJmh2AQChGH85EwcL5VW7tUavcAZDSG".parse().unwrap()
}

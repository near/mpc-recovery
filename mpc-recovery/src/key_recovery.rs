use crate::{
    msg::PublicKeyNodeRequest,
    transaction::{call_all_nodes, to_dalek_public_key, NodeCallError},
};
use ed25519_dalek::Signature;
use multi_party_eddsa::protocols::aggsig::KeyAgg;
use near_crypto::{ED25519PublicKey, PublicKey};

#[derive(thiserror::Error, Debug)]
#[allow(dead_code)]
pub enum NodeRecoveryError {
    #[error("call error: {0}")]
    CallError(#[from] NodeCallError),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub async fn get_user_recovery_pk(
    client: &reqwest::Client,
    sign_nodes: &[String],
    oidc_token: &str,
    frp_signature: Signature,
    frp_public_key: &PublicKey,
) -> Result<PublicKey, NodeRecoveryError> {
    let request = PublicKeyNodeRequest {
        oidc_token: oidc_token.to_string(),
        frp_signature,
        frp_public_key: frp_public_key.clone(),
    };
    let res = call_all_nodes(client, sign_nodes, "public_key", request).await?;

    let pk = KeyAgg::key_aggregation_n(&res, 0).apk;
    Ok(to_dalek_public_key(&pk).map(|k| PublicKey::ED25519(ED25519PublicKey(*k.as_bytes())))?)
}

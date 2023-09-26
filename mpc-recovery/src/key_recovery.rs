use crate::{
    error::LeaderNodeError,
    msg::PublicKeyNodeRequest,
    sign_node::oidc::OidcToken,
    transaction::{call_all_nodes, to_dalek_public_key},
};
use ed25519_dalek::Signature;
use multi_party_eddsa::protocols::aggsig::KeyAgg;
use near_crypto::{ED25519PublicKey, PublicKey};

pub async fn get_user_recovery_pk(
    client: &reqwest::Client,
    sign_nodes: &[String],
    oidc_token: &OidcToken,
    frp_signature: &Signature,
    frp_public_key: &PublicKey,
) -> Result<PublicKey, LeaderNodeError> {
    let request = PublicKeyNodeRequest {
        oidc_token: oidc_token.clone(),
        frp_signature: frp_signature.clone(),
        frp_public_key: frp_public_key.clone(),
    };
    let res = call_all_nodes(client, sign_nodes, "public_key", request).await?;

    let pk = KeyAgg::key_aggregation_n(&res, 0).apk;
    to_dalek_public_key(&pk)
        .map(|k| PublicKey::ED25519(ED25519PublicKey(*k.as_bytes())))
        .map_err(LeaderNodeError::AggregateSigningFailed)
}

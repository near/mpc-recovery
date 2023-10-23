use mpc_recovery::sign_node::oidc::OidcToken;
use near_crypto::{PublicKey, SecretKey};
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
}

pub struct UserSession {
    pub jwt_token: OidcToken,
    pub near_account_id: AccountId,
    pub fa_sk: SecretKey,
    pub la_sk: SecretKey,
    pub recovery_pk: Option<PublicKey>,
}

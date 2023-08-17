use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::Signature;
use near_primitives::delegate_action::DelegateAction;
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};

use crate::sign_node::oidc::{OidcHash, OidcToken};
use crate::transaction::CreateAccountOptions;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MpcPkRequest {}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum MpcPkResponse {
    Ok { mpc_pk: ed25519_dalek::PublicKey },
    Err { msg: String },
}

impl TryInto<ed25519_dalek::PublicKey> for MpcPkResponse {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<ed25519_dalek::PublicKey, Self::Error> {
        match self {
            MpcPkResponse::Ok { mpc_pk } => Ok(mpc_pk),
            MpcPkResponse::Err { msg } => anyhow::bail!("error response: {}", msg),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimOidcRequest {
    #[serde(with = "hex::serde")]
    pub oidc_token_hash: OidcHash,
    pub frp_public_key: near_crypto::PublicKey,
    #[serde(with = "hex_signature")]
    pub frp_signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum ClaimOidcResponse {
    Ok {
        #[serde(with = "hex_signature")]
        mpc_signature: Signature,
    },
    Err {
        msg: String,
    },
}

impl TryInto<Signature> for ClaimOidcResponse {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Signature, Self::Error> {
        let mpc_signature = match self {
            ClaimOidcResponse::Ok { mpc_signature } => mpc_signature,
            ClaimOidcResponse::Err { msg } => anyhow::bail!("error response: {}", msg),
        };

        Ok(mpc_signature)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserCredentialsRequest {
    pub oidc_token: OidcToken,
    #[serde(with = "hex_signature")]
    pub frp_signature: Signature,
    pub frp_public_key: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum UserCredentialsResponse {
    Ok { recovery_pk: near_crypto::PublicKey },
    Err { msg: String },
}

impl UserCredentialsResponse {
    pub fn err(msg: String) -> Self {
        UserCredentialsResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewAccountRequest {
    pub near_account_id: AccountId,
    pub create_account_options: CreateAccountOptions,
    pub oidc_token: OidcToken,
    #[serde(with = "hex_signature")]
    pub user_credentials_frp_signature: Signature,
    pub frp_public_key: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NewAccountResponse {
    Ok {
        create_account_options: CreateAccountOptions,
        user_recovery_public_key: String,
        near_account_id: AccountId,
    },
    Err {
        msg: String,
    },
}

impl NewAccountResponse {
    pub fn err(msg: String) -> Self {
        NewAccountResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignRequest {
    pub delegate_action: DelegateAction,
    pub oidc_token: OidcToken,
    #[serde(with = "hex_signature")]
    pub frp_signature: Signature,
    #[serde(with = "hex_signature")]
    pub user_credentials_frp_signature: Signature,
    pub frp_public_key: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum SignResponse {
    Ok {
        #[serde(with = "hex_signature")]
        signature: Signature,
    },
    Err {
        msg: String,
    },
}

impl SignResponse {
    pub fn err(msg: String) -> Self {
        SignResponse::Err { msg }
    }
}

/// The set of actions that a user can request us to sign
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SignNodeRequest {
    ClaimOidc(ClaimOidcNodeRequest),
    SignShare(SignShareNodeRequest),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignShareNodeRequest {
    pub oidc_token: OidcToken,
    pub delegate_action: DelegateAction,
    #[serde(with = "hex_signature")]
    pub frp_signature: Signature,
    pub frp_public_key: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimOidcNodeRequest {
    #[serde(with = "hex::serde")]
    pub oidc_token_hash: OidcHash,
    pub public_key: near_crypto::PublicKey,
    #[serde(with = "hex_signature")]
    pub signature: Signature,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyNodeRequest {
    pub oidc_token: OidcToken,
    #[serde(with = "hex_signature")]
    pub frp_signature: Signature,
    pub frp_public_key: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcceptNodePublicKeysRequest {
    pub public_keys: Vec<Point<Ed25519>>,
}

mod hex_signature {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig_share: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(Signature::to_bytes(*sig_share));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_bytes(
            &<[u8; Signature::BYTE_SIZE]>::try_from(
                hex::decode(s).map_err(serde::de::Error::custom)?,
            )
            .map_err(|v: Vec<u8>| {
                serde::de::Error::custom(format!(
                    "signature has incorrect length: expected {} bytes, but got {}",
                    Signature::BYTE_SIZE,
                    v.len()
                ))
            })?,
        )
        .map_err(serde::de::Error::custom)
    }
}

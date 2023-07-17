use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::Signature;
use near_primitives::delegate_action::DelegateAction;
use serde::{Deserialize, Serialize};

use crate::transaction::CreateAccountOptions;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MpcPkRequest {}

#[derive(Serialize, Deserialize, Debug)]
pub enum MpcPkResponse {
    Ok { mpc_pk: String },
    Err { msg: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimOidcRequest {
    #[serde(with = "hex::serde")]
    pub oidc_token_hash: [u8; 32],
    pub public_key: String,
    #[serde(with = "hex_sig_share")]
    pub frp_signature: Signature,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClaimOidcResponse {
    Ok {
        #[serde(with = "hex_sig_share")]
        mpc_signature: Signature,
    },
    Err {
        msg: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserCredentialsRequest {
    pub oidc_token: String,
    pub frp_signature: Signature,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UserCredentialsResponse {
    Ok { recovery_pk: String },
    Err { msg: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewAccountRequest {
    pub near_account_id: String,
    pub create_account_options: CreateAccountOptions,
    pub oidc_token: String,
    pub frp_signature: Signature,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NewAccountResponse {
    Ok {
        create_account_options: CreateAccountOptions,
        user_recovery_public_key: String,
        near_account_id: String,
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
    pub oidc_token: String,
    pub frp_signature: Signature,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum SignResponse {
    Ok { signature: Signature },
    Err { msg: String },
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
    pub oidc_token: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimOidcNodeRequest {
    #[serde(with = "hex::serde")]
    pub oidc_token_hash: [u8; 32],
    pub public_key: String,
    #[serde(with = "hex_sig_share")]
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcceptNodePublicKeysRequest {
    pub public_keys: Vec<Point<Ed25519>>,
}

mod hex_sig_share {
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

use curv::elliptic::curves::{Ed25519, Point};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NewAccountRequest {
    pub public_key: String,
    pub near_account_id: String,
    pub oidc_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NewAccountResponse {
    Ok {
        user_public_key: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct AddKeyRequest {
    pub near_account_id: Option<String>,
    pub public_key: String,
    pub oidc_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AddKeyResponse {
    Ok {
        user_public_key: String,
        near_account_id: String,
    },
    Err {
        msg: String,
    },
}

impl AddKeyResponse {
    pub fn err(msg: String) -> Self {
        AddKeyResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigShareRequest {
    pub oidc_token: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcceptNodePublicKeysRequest {
    pub public_keys: Vec<Point<Ed25519>>,
}

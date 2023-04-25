use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::Signature;
use near_crypto::PublicKey;
use serde::{Deserialize, Serialize};

use crate::transaction::CreateAccountOptions;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewAccountRequest {
    pub create_account_options: CreateAccountOptions,
    pub near_account_id: String,
    pub oidc_token: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct AddKeyRequest {
    pub create_account_options: CreateAccountOptions,
    pub near_account_id: Option<String>,
    pub oidc_token: String,

    #[serde(with = "hex_option_sig_share")]
    pub signature: Option<Signature>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AddKeyResponse {
    Ok {
        full_access_keys: Vec<String>,
        limited_access_keys: Vec<String>,
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
pub struct LeaderRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum LeaderResponse {
    Ok {
        #[serde(with = "hex_sig_share")]
        signature: Signature,
    },
    Err,
}

/// The set of actions that a user can request us to sign
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SigShareRequest {
    Claim(ClaimOidc),
    Add(AddKey),
}

impl SigShareRequest {
    pub fn verify_signature(&self, pk: PublicKey) -> Result<(), String> {
        // TODO verify according to the spec
        Ok(())
    }
}

/// We don't parse these too much, because we need to sign them in a way that can be verified by the client
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimOidc {
    #[serde(with = "hex::serde")]
    pub oidc_token_hash: [u8; 32],
    pub public_key: String,
    #[serde(with = "hex_sig_share")]
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddKey {
    /// If the user left near_account_id blank and it was generated by the leader this is true
    pub account_id_from_leader: bool,
    pub user_recovery_pk: PublicKey,
    pub max_block_height: u64,
    pub nonce: u64,

    /// We don't parse these too much, because we verify the signature created by the client
    pub near_account_id: String,
    pub oidc_token: String,
    pub public_key: String,

    pub signature: Option<Signature>,
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

// There has to be a less dumb way to do this, but I don't have time to work it out
mod hex_option_sig_share {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig_share: &Option<Signature>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match sig_share {
            Some(sig) => hex::encode(Signature::to_bytes(*sig)),
            None => String::new(),
        };
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Signature>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(None);
        }
        let sig = Signature::from_bytes(
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
        .map_err(serde::de::Error::custom)?;
        Ok(Some(sig))
    }
}

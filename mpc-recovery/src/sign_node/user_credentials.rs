use crate::{
    gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    },
    primitives::InternalAccountId,
};
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use curv::elliptic::curves::{Ed25519, Point};
use google_datastore1::api::{Key, PathElement};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedUserCredentials {
    pub node_id: usize,
    pub internal_account_id: InternalAccountId,
    pub public_key: Point<Ed25519>,
    pub encrypted_key_pair: Vec<u8>,
}

impl KeyKind for EncryptedUserCredentials {
    fn kind() -> String {
        "EncryptedUserCredentials".to_string()
    }
}

impl IntoValue for EncryptedUserCredentials {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "node_id".to_string(),
            Value::IntegerValue(self.node_id as i64),
        );
        properties.insert(
            "internal_account_id".to_string(),
            Value::StringValue(self.internal_account_id.clone()),
        );
        properties.insert(
            "public_key".to_string(),
            Value::StringValue(serde_json::to_string(&self.public_key).unwrap()),
        );
        properties.insert(
            "encrypted_key_pair".to_string(),
            Value::StringValue(
                serde_json::to_string(&hex::encode(self.encrypted_key_pair)).unwrap(),
            ),
        );
        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(EncryptedUserCredentials::kind()),
                    name: Some(format!("{}/{}", self.node_id, self.internal_account_id)),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for EncryptedUserCredentials {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, node_id) = properties
                    .remove_entry("node_id")
                    .ok_or_else(|| ConvertError::MissingProperty("node_id".to_string()))?;
                let node_id = i64::from_value(node_id)? as usize;
                let (_, internal_account_id) = properties
                    .remove_entry("internal_account_id")
                    .ok_or_else(|| {
                        ConvertError::MissingProperty("internal_account_id".to_string())
                    })?;
                let internal_account_id = String::from_value(internal_account_id)?;

                let (_, public_key) = properties
                    .remove_entry("public_key")
                    .ok_or_else(|| ConvertError::MissingProperty("public_key".to_string()))?;
                let public_key = String::from_value(public_key)?;
                let public_key = serde_json::from_str(&public_key)
                    .map_err(|_| ConvertError::MalformedProperty("public_key".to_string()))?;

                let (_, encrypted_key_pair) = properties
                    .remove_entry("encrypted_key_pair")
                    .ok_or_else(|| {
                        ConvertError::MissingProperty("encrypted_key_pair".to_string())
                    })?;
                let encrypted_key_pair = String::from_value(encrypted_key_pair)?;
                let encrypted_key_pair = serde_json::from_str(&encrypted_key_pair)
                    .ok()
                    .and_then(|hex: String| hex::decode(hex).ok())
                    .ok_or_else(|| {
                        ConvertError::MalformedProperty("encrypted_key_pair".to_string())
                    })?;

                Ok(Self {
                    node_id,
                    internal_account_id,
                    public_key,
                    encrypted_key_pair,
                })
            }
            value => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }
}

impl EncryptedUserCredentials {
    pub fn random(
        node_id: usize,
        internal_account_id: InternalAccountId,
        cipher: &Aes256Gcm,
    ) -> anyhow::Result<Self> {
        let key_pair = ExpandedKeyPair::create();
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let encrypted_key_pair = cipher
            .encrypt(nonce, serde_json::to_vec(&key_pair)?.as_slice())
            .unwrap();
        Ok(Self {
            node_id,
            internal_account_id,
            public_key: key_pair.public_key,
            encrypted_key_pair,
        })
    }

    pub fn public_key(&self) -> &Point<Ed25519> {
        &self.public_key
    }

    pub fn decrypt_key_pair(&self, cipher: &Aes256Gcm) -> anyhow::Result<ExpandedKeyPair> {
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let key_pair = cipher
            .decrypt(nonce, self.encrypted_key_pair.as_slice())
            .unwrap();
        Ok(serde_json::from_slice(&key_pair)?)
    }
}

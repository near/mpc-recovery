use crate::{
    gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    },
    primitives::InternalAccountId,
};
use curv::elliptic::curves::{Ed25519, Point};
use google_datastore1::api::{Key, PathElement};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserCredentials {
    pub node_id: usize,
    pub internal_account_id: InternalAccountId,
    pub key_pair: ExpandedKeyPair,
}

impl KeyKind for UserCredentials {
    fn kind() -> String {
        "UserCredentials".to_string()
    }
}

impl IntoValue for UserCredentials {
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
            "key_pair".to_string(),
            Value::StringValue(serde_json::to_string(&self.key_pair).unwrap()),
        );
        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(UserCredentials::kind()),
                    name: Some(format!("{}/{}", self.node_id, self.internal_account_id)),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for UserCredentials {
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

                let (_, key_pair) = properties
                    .remove_entry("key_pair")
                    .ok_or_else(|| ConvertError::MissingProperty("key_pair".to_string()))?;
                let key_pair = String::from_value(key_pair)?;
                let key_pair = serde_json::from_str(&key_pair)
                    .map_err(|_| ConvertError::MalformedProperty("key_pair".to_string()))?;

                Ok(Self {
                    node_id,
                    internal_account_id,
                    key_pair,
                })
            }
            value => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }
}

impl UserCredentials {
    pub fn random(node_id: usize, internal_account_id: InternalAccountId) -> Self {
        Self {
            node_id,
            internal_account_id,
            key_pair: ExpandedKeyPair::create(),
        }
    }

    pub fn public_key(&self) -> &Point<Ed25519> {
        &self.key_pair.public_key
    }
}

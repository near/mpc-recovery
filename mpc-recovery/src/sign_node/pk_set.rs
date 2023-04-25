use crate::gcp::{
    error::ConvertError,
    value::{FromValue, IntoValue, Value},
    KeyKind,
};
use curv::elliptic::curves::{Ed25519, Point};
use google_datastore1::api::{Key, PathElement};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAIN_KEY: &str = "main";

#[derive(Serialize, Deserialize, Clone)]
pub struct SignerNodePkSet {
    pub node_id: usize,
    pub public_keys: Vec<Point<Ed25519>>,
}

impl KeyKind for SignerNodePkSet {
    fn kind() -> String {
        "SignerNodePkSet".to_string()
    }
}

impl IntoValue for SignerNodePkSet {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "node_id".to_string(),
            Value::IntegerValue(self.node_id as i64),
        );
        properties.insert(
            "public_keys".to_string(),
            Value::StringValue(serde_json::to_string(&self.public_keys).unwrap()),
        );
        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(SignerNodePkSet::kind()),
                    name: Some(format!("{}/{}", self.node_id, MAIN_KEY)),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for SignerNodePkSet {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, node_id) = properties
                    .remove_entry("node_id")
                    .ok_or_else(|| ConvertError::MissingProperty("node_id".to_string()))?;
                let node_id = i64::from_value(node_id)? as usize;
                let (_, public_keys) = properties
                    .remove_entry("public_keys")
                    .ok_or_else(|| ConvertError::MissingProperty("public_keys".to_string()))?;
                let public_keys = String::from_value(public_keys)?;
                let public_keys = serde_json::from_str(&public_keys)
                    .map_err(|_| ConvertError::MalformedProperty("public_keys".to_string()))?;

                Ok(Self {
                    node_id,
                    public_keys,
                })
            }
            value => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }
}

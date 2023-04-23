use crate::{
    gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    },
    primitives::InternalAccountId,
};
use google_datastore1::api::{Key, PathElement};
use near_crypto::{KeyType, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserSecretKey {
    pub internal_account_id: InternalAccountId,
    pub secret_key: SecretKey,
}

impl KeyKind for UserSecretKey {
    fn kind() -> String {
        "UserSecretKey".to_string()
    }
}

impl IntoValue for UserSecretKey {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "internal_account_id".to_string(),
            Value::StringValue(self.internal_account_id.clone()),
        );
        properties.insert(
            "secret_key".to_string(),
            Value::StringValue(self.secret_key.to_string()),
        );
        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(UserSecretKey::kind()),
                    name: Some(self.internal_account_id),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for UserSecretKey {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, internal_account_id) = properties
                    .remove_entry("internal_account_id")
                    .ok_or_else(|| {
                        ConvertError::MissingProperty("internal_account_id".to_string())
                    })?;
                let internal_account_id = String::from_value(internal_account_id)?;

                let (_, secret_key) = properties
                    .remove_entry("secret_key")
                    .ok_or_else(|| ConvertError::MissingProperty("secret_key".to_string()))?;
                let secret_key = String::from_value(secret_key)?;
                let secret_key = secret_key.parse().unwrap();

                Ok(UserSecretKey {
                    internal_account_id,
                    secret_key,
                })
            }
            value => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", value),
            }),
        }
    }
}

impl UserSecretKey {
    pub fn random(internal_account_id: InternalAccountId) -> Self {
        Self {
            internal_account_id,
            secret_key: SecretKey::from_random(KeyType::ED25519),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }
}

use std::collections::HashMap;

use google_datastore1::api::{Key, PathElement};
use near_crypto::PublicKey;
use serde::{Deserialize, Serialize};

use crate::gcp::{
    error::ConvertError,
    value::{FromValue, IntoValue, Value},
    KeyKind,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OidcDigest {
    pub node_id: usize,
    pub digest: [u8; 32],
    pub public_key: PublicKey,
}

impl KeyKind for OidcDigest {
    fn kind() -> String {
        "OidcDigest".to_string()
    }
}

impl IntoValue for OidcDigest {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "node_id".to_string(),
            Value::IntegerValue(self.node_id as i64),
        );
        properties.insert(
            "digest".to_string(),
            Value::StringValue(hex::encode(self.digest)),
        );
        properties.insert(
            "public_key".to_string(),
            Value::StringValue(serde_json::to_string(&self.public_key).unwrap()),
        );

        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(Self::kind()),
                    name: Some(self.to_name()),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for OidcDigest {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, node_id) = properties
                    .remove_entry("node_id")
                    .ok_or_else(|| ConvertError::MissingProperty("node_id".to_string()))?;
                let node_id = i64::from_value(node_id)? as usize;
                let (_, digest) = properties
                    .remove_entry("digest")
                    .ok_or_else(|| ConvertError::MissingProperty("digest".to_string()))?;
                let digest = hex::decode(String::from_value(digest)?)
                    .map_err(|_| ConvertError::MalformedProperty("digest".to_string()))?;
                let digest = <[u8; 32]>::try_from(digest)
                    .map_err(|_| ConvertError::MalformedProperty("digest".to_string()))?;

                let (_, public_key) = properties
                    .remove_entry("public_key")
                    .ok_or_else(|| ConvertError::MissingProperty("public_key".to_string()))?;
                let public_key = String::from_value(public_key)?;
                let public_key = serde_json::from_str(&public_key)
                    .map_err(|_| ConvertError::MalformedProperty("public_key".to_string()))?;

                Ok(Self {
                    node_id,
                    digest,
                    public_key,
                })
            }
            error => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", error),
            }),
        }
    }
}

impl OidcDigest {
    pub fn to_name(&self) -> String {
        format!("{}/{}", self.node_id, hex::encode(self.digest))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::utils::{claim_oidc_request_digest, oidc_digest};

    use super::*;

    #[test]
    fn test_oidc_digest_from_and_to_value() {
        let public_key = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae".to_string();
        let oidc_token = "validToken:oR8hig9XkU".to_string();

        let oidc_token_hash = oidc_digest(&oidc_token);

        let user_pk: PublicKey = PublicKey::from_str(&public_key).unwrap();

        let oidc_request_digest = match claim_oidc_request_digest(oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest_32 = <[u8; 32]>::try_from(oidc_request_digest).expect("Hash was wrong size");

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest: digest_32,
            public_key: public_key.parse().expect("Failed to parse public key"),
        };

        let val = oidc_digest.clone().into_value();

        let reconstructed_oidc_digest = match OidcDigest::from_value(val) {
            Ok(oidc_digest) => oidc_digest,
            Err(err) => panic!("Failed to reconstruct OidcDigest: {:?}", err),
        };

        // Wrong digest for comparison
        let public_key_2 = "ed25519:EBNJGHctB2LuDsCyMWrfwW87QrAob2kKzoS98PR5vjJn";
        let oidc_digest_2 = OidcDigest {
            node_id: 1,
            digest: digest_32,
            public_key: public_key_2.parse().expect("Failed to parse public key"),
        };

        assert_eq!(oidc_digest, reconstructed_oidc_digest);
        assert_ne!(oidc_digest_2, reconstructed_oidc_digest);
    }

    #[test]
    fn test_oidc_to_name() {
        let public_key = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae".to_string();
        let oidc_token = "validToken:oR8hig9XkU".to_string();
        let user_pk: PublicKey = PublicKey::from_str(&public_key).unwrap();

        let oidc_token_hash = oidc_digest(&oidc_token);

        let digest = match claim_oidc_request_digest(oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest_32 = <[u8; 32]>::try_from(digest).expect("Hash was wrong size");

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest: digest_32,
            public_key: public_key.parse().expect("Failed to parse public key"),
        };

        let name = oidc_digest.to_name();

        assert_eq!(
            name,
            format!(
                "{}/{}",
                oidc_digest.node_id,
                hex::encode(oidc_digest.digest)
            )
        );
    }
}

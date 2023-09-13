use std::collections::HashMap;

use borsh::{self, BorshDeserialize, BorshSerialize};
use google_datastore1::api::{Key, PathElement};
use hex::FromHex;
use jsonwebtoken as jwt;
use jwt::DecodingKey;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

use near_crypto::PublicKey;

use crate::{
    error::MpcError,
    gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    },
    oauth::IdTokenClaims,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OidcHash([u8; 32]);

impl AsRef<[u8]> for OidcHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for OidcHash {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> anyhow::Result<Self> {
        let bytes = <[u8; 32]>::from_hex(hex)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(transparent)]
pub struct OidcToken {
    data: String,
}

impl OidcToken {
    pub fn new(data: &str) -> Self {
        Self { data: data.into() }
    }

    pub fn digest_hash(&self) -> OidcHash {
        let hasher = sha2::Digest::chain(sha2::Sha256::default(), self.data.as_bytes());
        let hash = <[u8; 32]>::try_from(sha2::Digest::finalize(hasher).as_slice())
            .expect("Hash is the wrong size");
        OidcHash(hash)
    }

    pub fn random() -> Self {
        let random: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        Self {
            data: format!("validToken:{}", random),
        }
    }

    pub fn invalid() -> Self {
        Self {
            data: "invalidToken".to_string(),
        }
    }

    // NOTE: code taken directly from jsonwebtoken::verify_signature and modified to suit
    // our needs (i.e. not knowing audience and issuer ahead of time).
    pub fn decode(
        &self,
        key: &DecodingKey,
    ) -> anyhow::Result<(jwt::Header, IdTokenClaims, String)> {
        let mut parts = self.as_ref().rsplitn(2, '.');
        let (Some(signature), Some(message)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into signature and message for OIDC token");
        };
        let mut parts = message.rsplitn(2, '.');
        let (Some(payload), Some(header)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into payload and header for OIDC token");
        };
        let header: jwt::Header = serde_json::from_slice(&b64_decode(header)?)?;
        let claims: IdTokenClaims = serde_json::from_slice(&b64_decode(payload)?)?;

        if !jwt::crypto::verify(signature, message.as_bytes(), key, header.alg)? {
            anyhow::bail!("InvalidSignature");
        }

        Ok((header, claims, signature.into()))
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> anyhow::Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, input)
        .map_err(Into::into)
}

impl std::str::FromStr for OidcToken {
    type Err = MpcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl std::fmt::Display for OidcToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.data)
    }
}

impl AsRef<str> for OidcToken {
    fn as_ref(&self) -> &str {
        &self.data
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OidcDigest {
    pub node_id: usize,
    pub digest: OidcHash,
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
            Value::StringValue(hex::encode(&self.digest)),
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
                let digest = OidcHash(digest);

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
        format!("{}/{}", self.node_id, hex::encode(&self.digest))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::utils::claim_oidc_request_digest;

    use super::*;

    #[test]
    fn test_oidc_digest_from_and_to_value() {
        let oidc_token = OidcToken::new("validToken:oR8hig9XkU");
        let oidc_token_hash = oidc_token.digest_hash();
        let user_pk =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();

        let oidc_request_digest = match claim_oidc_request_digest(&oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest = <[u8; 32]>::try_from(oidc_request_digest).expect("Hash was wrong size");
        let digest = OidcHash(digest);

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest: digest.clone(),
            public_key: user_pk,
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
            digest,
            public_key: public_key_2.parse().expect("Failed to parse public key"),
        };

        assert_eq!(oidc_digest, reconstructed_oidc_digest);
        assert_ne!(oidc_digest_2, reconstructed_oidc_digest);
    }

    #[test]
    fn test_oidc_to_name() {
        let oidc_token = OidcToken::new("validToken:oR8hig9XkU");
        let user_pk =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();
        let oidc_token_hash = oidc_token.digest_hash();

        let digest = match claim_oidc_request_digest(&oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest = <[u8; 32]>::try_from(digest).expect("Hash was wrong size");
        let digest = OidcHash(digest);

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest,
            public_key: user_pk,
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

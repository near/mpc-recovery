use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::primitives::InternalAccountId;
use crate::sign_node::oidc::OidcToken;

#[async_trait::async_trait]
pub trait OAuthTokenVerifier {
    async fn verify_token(token: &OidcToken, audience: &str) -> anyhow::Result<IdTokenClaims>;

    /// This function validates JWT (OIDC ID token) by checking the signature received
    /// from the issuer, issuer, audience, and expiration time.
    fn validate_jwt(
        token: &OidcToken,
        public_key: &[u8],
        issuer: &str,
        audience: &str,
    ) -> anyhow::Result<IdTokenClaims> {
        tracing::info!(
            oidc_token = format!("{:.5}...", token),
            public_key = String::from_utf8(public_key.to_vec()).unwrap_or_default(),
            issuer = issuer,
            audience = audience,
            "validate_jwt call"
        );
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);

        let decoding_key = DecodingKey::from_rsa_pem(public_key)?;

        let claims = decode::<IdTokenClaims>(token.as_ref(), &decoding_key, &validation)
            .map(|t| t.claims)?;

        tracing::info!(
            claims = format!("{:?}", claims),
            "validate_jwt call successful"
        );

        Ok(claims)
    }
}

pub enum SupportedTokenVerifiers {
    PagodaFirebaseTokenVerifier,
    TestTokenVerifier,
}

/* Universal token verifier */
pub struct UniversalTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for UniversalTokenVerifier {
    async fn verify_token(token: &OidcToken, audience: &str) -> anyhow::Result<IdTokenClaims> {
        match get_token_verifier_type(token) {
            SupportedTokenVerifiers::PagodaFirebaseTokenVerifier => {
                return PagodaFirebaseTokenVerifier::verify_token(token, audience).await;
            }
            SupportedTokenVerifiers::TestTokenVerifier => {
                return TestTokenVerifier::verify_token(token, audience).await;
            }
        }
    }
}

fn get_token_verifier_type(token: &OidcToken) -> SupportedTokenVerifiers {
    match token.as_ref().len() > 30 {
        // TODO: add real token type detection, now the system can be bypassed by passing a short token
        true => {
            tracing::info!("Using PagodaFirebaseTokenVerifier");
            SupportedTokenVerifiers::PagodaFirebaseTokenVerifier
        }
        false => {
            tracing::info!("Using TestTokenVerifier");
            SupportedTokenVerifiers::TestTokenVerifier
        }
    }
}

/* Pagoda/Firebase verifier */
pub struct PagodaFirebaseTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for PagodaFirebaseTokenVerifier {
    // Specs for ID token verification:
    // Google: https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
    // Firebase: https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
    async fn verify_token(token: &OidcToken, audience: &str) -> anyhow::Result<IdTokenClaims> {
        let public_keys = get_pagoda_firebase_public_keys()
            .map_err(|e| anyhow::anyhow!("failed to get Firebase public key: {e}"))?;

        let pagoda_firebase_issuer_id: String =
            format!("https://securetoken.google.com/{}", audience);

        let mut last_occured_error =
            anyhow::anyhow!("Unexpected error. Firebase public keys not found");
        for public_key in public_keys {
            match Self::validate_jwt(
                token,
                public_key.as_bytes(),
                &pagoda_firebase_issuer_id,
                audience,
            ) {
                Ok(claims) => {
                    tracing::info!(target: "pagoda-firebase-token-verifier", "access token is valid");
                    return Ok(claims);
                }
                Err(e) => {
                    tracing::info!(target: "pagoda-firebase-token-verifier", "access token verification failed: {}", e);
                    last_occured_error = e;
                }
            }
        }
        Err(last_occured_error)
    }
}

/* Test verifier */
pub struct TestTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for TestTokenVerifier {
    async fn verify_token(token: &OidcToken, _audience: &str) -> anyhow::Result<IdTokenClaims> {
        if let Some(aud) = token.as_ref().strip_prefix("validToken:") {
            tracing::info!(target: "test-token-verifier", "access token is valid");
            Ok(get_test_claims(aud.to_string()))
        } else {
            tracing::info!(target: "test-token-verifier", "access token verification failed");
            Err(anyhow::anyhow!("Invalid token".to_string()))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
}

impl IdTokenClaims {
    pub fn get_internal_account_id(&self) -> InternalAccountId {
        format!("{}:{}", self.iss, self.sub)
    }
}

#[derive(Serialize, Deserialize)]
struct OpenIdConfig {
    jwks_uri: String,
}

#[derive(Serialize, Deserialize)]
struct Jwks {
    keys: Vec<Value>,
}

fn get_pagoda_firebase_public_keys() -> anyhow::Result<Vec<String>> {
    let url =
        "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send()?;
    let json: HashMap<String, String> = response.json()?;
    let keys: Vec<String> = json.values().cloned().collect();
    Ok(keys)
}

pub fn get_test_claims(sub: String) -> IdTokenClaims {
    IdTokenClaims {
        iss: "test_issuer".to_string(),
        sub,
        aud: "test_audience".to_string(),
        exp: Utc::now().timestamp() as usize + 3600,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rand8::rngs::OsRng;
    use rsa::{
        pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
        RsaPrivateKey, RsaPublicKey,
    };

    pub fn compare_claims(claims1: IdTokenClaims, claims2: IdTokenClaims) -> bool {
        claims1.iss == claims2.iss
            && claims1.sub == claims2.sub
            && claims1.aud == claims2.aud
            && claims1.exp == claims2.exp
    }

    #[test]
    fn test_get_pagoda_firebase_public_key() {
        let pk = get_pagoda_firebase_public_keys().unwrap();
        assert!(!pk.is_empty());
    }

    #[test]
    fn test_validate_jwt() {
        let (private_key_der, public_key_der): (Vec<u8>, Vec<u8>) = get_rsa_pem_key_pair();

        let my_claims = IdTokenClaims {
            iss: "test_issuer".to_string(),
            sub: "test_subject".to_string(),
            aud: "test_audience".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = match encode(
            &Header::new(Algorithm::RS256),
            &my_claims,
            &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
        ) {
            Ok(t) => OidcToken::new(t.as_str()),
            Err(e) => panic!("Failed to encode token: {}", e),
        };

        // Valid token and claims
        PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            &my_claims.iss,
            &my_claims.aud,
        )
        .unwrap();

        // Invalid public key
        let (invalid_public_key, _invalid_private_key) = get_rsa_pem_key_pair();
        match PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &invalid_public_key,
            &my_claims.iss,
            &my_claims.aud,
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e.to_string(), "InvalidSignature"),
        }

        // Invalid issuer
        match PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            "invalid_issuer",
            &my_claims.aud,
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e.to_string(), "InvalidIssuer"),
        }

        // Invalid audience
        match PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            &my_claims.iss,
            "invalid_audience",
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e.to_string(), "InvalidAudience"),
        }
    }

    #[tokio::test]
    async fn test_verify_token_valid() {
        let token = OidcToken::new("validToken:test-subject");
        let test_claims = get_test_claims("test-subject".to_string());
        let claims = TestTokenVerifier::verify_token(&token, &test_claims.aud)
            .await
            .unwrap();
        assert!(compare_claims(claims, test_claims));
    }

    #[tokio::test]
    async fn test_verify_token_invalid_with_test_verifier() {
        let token = OidcToken::invalid();
        let result = TestTokenVerifier::verify_token(&token, "rand").await;
        match result {
            Ok(_) => panic!("Token verification should fail"),
            Err(e) => assert_eq!(e.to_string(), "Invalid token"),
        }
    }

    #[tokio::test]
    async fn test_verify_token_valid_with_test_verifier() {
        let token = OidcToken::new("validToken:test-subject");
        let test_claims = get_test_claims("test-subject".to_string());
        let claims = TestTokenVerifier::verify_token(&token, &test_claims.aud)
            .await
            .unwrap();
        assert!(compare_claims(claims, test_claims));
    }

    #[tokio::test]
    async fn test_verify_token_invalid_with_universal_verifier() {
        let token = OidcToken::invalid();
        let result = UniversalTokenVerifier::verify_token(&token, "rand").await;
        match result {
            Ok(_) => panic!("Token verification should fail"),
            Err(e) => assert_eq!(e.to_string(), "Invalid token"),
        }
    }

    #[tokio::test]
    async fn test_verify_token_valid_with_universal_verifier() {
        let token = OidcToken::new("validToken:test-subject");
        let test_claims = get_test_claims("test-subject".to_string());
        let claims = UniversalTokenVerifier::verify_token(&token, &test_claims.aud)
            .await
            .unwrap();
        assert!(compare_claims(claims, test_claims));
    }

    pub fn get_rsa_pem_key_pair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let bits: usize = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_der = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .as_bytes()
            .to_vec();
        let public_key_der = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode public key")
            .as_bytes()
            .to_vec();

        (private_key_der, public_key_der)
    }
}

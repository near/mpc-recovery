use anyhow::Context;
use borsh::BorshSerialize;
use ed25519_dalek::Signature;
use near_crypto::PublicKey;
use sha2::{Digest, Sha256};

use crate::{primitives::HashSalt, sign_node::CommitError};

pub fn claim_oidc_request_digest(oidc_token_hash: [u8; 32]) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // To verify the signature of the message verify:
    // sha256.hash(Borsh.serialize<u32>(SALT + 0) ++ Borsh.serialize<[u8]>(oidc_token_hash))
    let mut hasher = Sha256::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcRequest.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&oidc_token_hash, &mut hasher).context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

pub fn claim_oidc_response_digest(users_signature: Signature) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // If you successfully claim the token you will receive a signature in return of:
    // sha256.hash(Borsh.serialize<u32>(SALT + 1) ++ Borsh.serialize<[u8]>(signature))
    let mut hasher = Sha256::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcResponse.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&users_signature.to_bytes(), &mut hasher)
        .context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

// TODO: is this function necessary? Is there en existing way to do this?
pub fn check_signature(
    public_key: &PublicKey,
    signature: &Signature,
    request_digest: &[u8],
) -> Result<(), CommitError> {
    if !near_crypto::Signature::ED25519(*signature).verify(request_digest, public_key) {
        Err(CommitError::SignatureVerificationFailed(anyhow::anyhow!(
            "Public key {}, digest {} and signature {} don't match",
            &public_key,
            &hex::encode(request_digest),
            &signature
        )))
    } else {
        Ok(())
    }
}

pub fn oidc_digest(oidc_token: &str) -> [u8; 32] {
    let hasher = Sha256::default().chain(oidc_token.as_bytes());

    <[u8; 32]>::try_from(hasher.finalize().as_slice()).expect("Hash is the wrong size")
}

#[cfg(test)]
mod tests {
    use crate::msg::ClaimOidcResponse;

    use super::*;

    #[test]
    fn test_oidc_digest_test() {
        assert_eq!(oidc_digest("oidc_token_1"), oidc_digest("oidc_token_1"));
        assert_ne!(oidc_digest("oidc_token_1"), oidc_digest("oidc_token_2"));
    }

    #[test]
    fn test_claim_oidc_request_digest_and_claim_oidc_response_digest() {
        // prepare digest
        let token_hash = oidc_digest("oidc_token_1");

        let request_digest = match claim_oidc_request_digest(token_hash) {
            Ok(digest) => digest,
            Err(e) => panic!("Failed to generate digest: {}", e),
        };
        // geneate a user key pair
        let user_private_key = [0u8; 32];
        let user_secret_key = ed25519_dalek::ExpandedSecretKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&user_private_key)
                .expect("Can only fail if bytes.len()<32"),
        );
        let user_public_key = ed25519_dalek::PublicKey::from(&user_secret_key);

        // sign the digest
        let request_digest_signature = user_secret_key.sign(&request_digest, &user_public_key);

        // check the signature
        match user_public_key.verify_strict(&request_digest, &request_digest_signature) {
            Ok(_) => (),
            Err(e) => panic!("Failed to verify signature: {}", e),
        };

        // check signature with different digest
        let request_digest_2 = match claim_oidc_request_digest(oidc_digest("oidc_token_2")) {
            Ok(digest) => digest,
            Err(e) => panic!("Failed to generate digest: {}", e),
        };

        if user_public_key
            .verify_strict(&request_digest_2, &request_digest_signature)
            .is_ok()
        {
            panic!("Signature should not match");
        }

        // create and check response digest
        let mpc_private_key = [0u8; 32];
        let mpc_secret_key = ed25519_dalek::ExpandedSecretKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&mpc_private_key)
                .expect("Can only fail if bytes.len()<32"),
        );
        let mpc_public_key = ed25519_dalek::PublicKey::from(&mpc_secret_key);

        let responce_digest = claim_oidc_response_digest(request_digest_signature)
            .expect("Failed to generate responce digest");

        let mpc_response_digest_signature = mpc_secret_key.sign(&responce_digest, &mpc_public_key);

        let _claim_oidc_response = ClaimOidcResponse::Ok {
            mpc_signature: mpc_response_digest_signature,
            recovery_public_key: None,
            near_account_id: None,
        };

        mpc_public_key
            .verify_strict(&responce_digest, &mpc_response_digest_signature)
            .expect("Failed to verify responce signature");
    }
}

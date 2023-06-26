use anyhow::Context;
use borsh::BorshSerialize;
use ed25519_dalek::{Digest, Sha512, Signature};
use near_crypto::PublicKey;

use crate::{primitives::HashSalt, sign_node::CommitError};

pub fn claim_oidc_request_digest(oidc_token_hash: [u8; 64]) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // To verify the signature of the message verify:
    // sha256.hash(Borsh.serialize<u32>(SALT + 0) ++ Borsh.serialize<[u8]>(oidc_token_hash))
    let mut hasher = Sha512::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcRequest.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&oidc_token_hash, &mut hasher).context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

pub fn claim_oidc_response_digest(users_signature: Signature) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // If you successfully claim the token you will receive a signature in return of:
    // sha256.hash(Borsh.serialize<u32>(SALT + 1) ++ Borsh.serialize<[u8]>(signature))
    let mut hasher = Sha512::default();
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

pub fn oidc_digest(oidc_token: &str) -> [u8; 64] {
    let hasher = Sha512::default().chain(oidc_token.as_bytes());

    <[u8; 64]>::try_from(hasher.finalize().as_slice()).expect("Hash is the wrong size")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_digest_test() {
        assert_eq!(oidc_digest("oidc_token_1"), oidc_digest("oidc_token_1"));
        assert_ne!(oidc_digest("oidc_token_1"), oidc_digest("oidc_token_2"));
    }

    #[test]
    fn claim_oidc_response_digest_test() {
        // prepare digest
        let token_hash = oidc_digest("oidc_token_1");

        let digest = match claim_oidc_request_digest(token_hash) {
            Ok(digest) => digest,
            Err(e) => panic!("Failed to generate digest: {}", e),
        };
        // geneate a key pair
        let privkey = [0u8; 32];
        let dalek_secret = ed25519_dalek::ExpandedSecretKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&privkey)
                .expect("Can only fail if bytes.len()<32"),
        );
        let dalek_pub = ed25519_dalek::PublicKey::from(&dalek_secret);

        // sign the digest
        let dalek_sig = dalek_secret.sign(&digest, &dalek_pub);

        // check the signature
        match dalek_pub.verify_strict(&digest, &dalek_sig) {
            Ok(_) => (),
            Err(e) => panic!("Failed to verify signature: {}", e),
        };

        // check signature with different digest
        let digest2 = match claim_oidc_request_digest(oidc_digest("oidc_token_2")) {
            Ok(digest) => digest,
            Err(e) => panic!("Failed to generate digest: {}", e),
        };

        if let Ok(_) = dalek_pub.verify_strict(&digest2, &dalek_sig) {
            panic!("Signature should not match")
        }
    }
}

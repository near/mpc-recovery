use anyhow::Context;
use borsh::BorshSerialize;
use ed25519_dalek::Signature;
use near_crypto::PublicKey;
use near_primitives::delegate_action::DelegateAction;
use sha2::{Digest, Sha256};

use crate::{primitives::HashSalt, sign_node::CommitError};

pub fn claim_oidc_request_digest(
    oidc_token_hash: [u8; 32],
    frp_public_key: PublicKey,
) -> anyhow::Result<Vec<u8>> {
    // As per the readme
    // To verify the signature of the message verify:
    // sha256.hash(Borsh.serialize<u32>(SALT + 0) ++ Borsh.serialize<[u8]>(oidc_token_hash))
    let mut hasher = Sha256::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcRequest.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&oidc_token_hash, &mut hasher).context("Serialization failed")?;
    BorshSerialize::serialize(&frp_public_key, &mut hasher).context("Serialization failed")?;
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

pub fn sign_request_digest(
    delegate_action: DelegateAction,
    oidc_token: String,
    frp_public_key: PublicKey,
) -> Result<Vec<u8>, CommitError> {
    let mut hasher = Sha256::default();
    BorshSerialize::serialize(&HashSalt::SignRequest.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&delegate_action, &mut hasher).context("Serialization failed")?;
    BorshSerialize::serialize(&oidc_token, &mut hasher).context("Serialization failed")?;
    BorshSerialize::serialize(&frp_public_key, &mut hasher).context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

pub fn user_credentials_request_digest(
    oidc_token: String,
    frp_public_key: PublicKey,
) -> anyhow::Result<Vec<u8>> {
    let mut hasher = Sha256::default();
    BorshSerialize::serialize(&HashSalt::UserCredentialsRequest.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&oidc_token, &mut hasher).context("Serialization failed")?;
    BorshSerialize::serialize(&frp_public_key, &mut hasher).context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

pub fn check_digest_signature(
    public_key: &PublicKey,
    signature: &Signature,
    digest: &[u8],
) -> Result<(), anyhow::Error> {
    if !near_crypto::Signature::ED25519(*signature).verify(digest, public_key) {
        Err(anyhow::anyhow!(
            "Public key {}, digest {} and signature {} don't match",
            &public_key,
            &hex::encode(digest),
            &signature
        ))
    } else {
        Ok(())
    }
}

pub fn oidc_digest(oidc_token: &str) -> [u8; 32] {
    let hasher = Sha256::default().chain(oidc_token.as_bytes());

    <[u8; 32]>::try_from(hasher.finalize().as_slice()).expect("Hash is the wrong size")
}

pub fn sign_digest(
    request_digest: &[u8],
    user_secret_key: &near_crypto::SecretKey,
) -> anyhow::Result<Signature> {
    match user_secret_key.sign(request_digest) {
        near_crypto::Signature::ED25519(signature) => Ok(signature),
        _ => anyhow::bail!("Wrong signature type"),
    }
}

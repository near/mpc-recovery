use crate::types::{PublicKey, ScalarExt};
use anyhow::Context;
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    sha2::{Digest, Sha256},
    Scalar, Secp256k1,
};
use near_account_id::AccountId;

// Constant prefix that ensures epsilon derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_epsilon(predecessor_id: &AccountId, path: &str) -> Scalar {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha256::new();
    hasher.update(derivation_path);
    Scalar::from_bytes(&hasher.finalize())
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

pub fn check_ec_signature(
    expected_pk: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: Scalar,
    recovery_id: u8,
) -> anyhow::Result<()> {
    let public_key = expected_pk.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from cait_sith signature")?;
    let found_pk = recover(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(recovery_id).context("invalid recovery ID")?,
    )?
    .to_encoded_point(false);
    if public_key == found_pk {
        return Ok(());
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn recover(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> anyhow::Result<VerifyingKey> {
    VerifyingKey::recover_from_prehash(prehash, signature, recovery_id)
        .context("Unable to recover public key")
}

#[cfg(target_arch = "wasm32")]
pub fn recover(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> anyhow::Result<VerifyingKey> {
    use near_sdk::env;
    // While this function also works on native code, it's a bit weird and unsafe.
    // I'm more comfortable using an existing library instead.
    let recovered_key_bytes =
        env::ecrecover(prehash, &signature.to_bytes(), recovery_id.to_byte(), true)
            .context("Unable to recover public key")?;
    VerifyingKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(
        &recovered_key_bytes.into(),
    ))
    .context("Failed to parse returned key")
}

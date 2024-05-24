use crate::types::{PublicKey, ScalarExt};
use anyhow::Context;
use k256::ecdsa::{RecoveryId, VerifyingKey};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::CurveArithmetic;
use k256::sha2::{Digest, Sha256};
use k256::{AffinePoint, Scalar, Secp256k1};
use near_primitives::types::AccountId;

// Constant prefix that ensures epsilon derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_epsilon(signer_id: &AccountId, path: &str) -> Scalar {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", signer_id, path);
    let mut hasher = Sha256::new();
    hasher.update(derivation_path);
    Scalar::from_bytes(&hasher.finalize())
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

#[derive(Debug)]
pub struct MultichainSignature {
    pub big_r: AffinePoint,
    pub s: Scalar,
    pub recovery_id: u8,
}

// try to get the correct recovery id for this signature by brute force.
pub fn into_eth_sig(
    public_key: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: Scalar,
) -> anyhow::Result<MultichainSignature> {
    let public_key = public_key.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from cait_sith signature")?;
    let pk0 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(0).context("cannot create recovery_id=0")?,
    )
    .context("unable to use 0 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk0 {
        return Ok(MultichainSignature {
            big_r: *big_r,
            s: *s,
            recovery_id: 0,
        });
    }

    let pk1 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(1).context("cannot create recovery_id=1")?,
    )
    .context("unable to use 1 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk1 {
        return Ok(MultichainSignature {
            big_r: *big_r,
            s: *s,
            recovery_id: 1,
        });
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

// Get the x coordinate of a point, as a scalar
// pub fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
//     <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
// }

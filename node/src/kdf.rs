use crate::types::PublicKey;
use crate::util::ScalarExt;
use anyhow::Context;
use cait_sith::FullSignature;
use hkdf::Hkdf;
use k256::ecdsa::{RecoveryId, VerifyingKey};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::CurveArithmetic;
use k256::{AffinePoint, Scalar, Secp256k1};
use near_account_id::AccountId;
use near_primitives::hash::CryptoHash;
use sha2::{Digest, Sha256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";
// Constant prefix that ensures delta derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const DELTA_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 delta derivation:";

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

// In case there are multiple requests in the same block (hence same entropy), we need to ensure
// that we generate different random scalars as delta tweaks.
// Receipt ID should be unique inside of a block, so it serves us as the request identifier.
pub fn derive_delta(receipt_id: CryptoHash, entropy: [u8; 32]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(None, &entropy);
    let info = format!("{DELTA_DERIVATION_PREFIX}:{}", receipt_id);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm).unwrap();
    Scalar::from_bytes(&okm)
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
    sig: &FullSignature<Secp256k1>,
    msg_hash: Scalar,
) -> anyhow::Result<MultichainSignature> {
    let public_key = public_key.to_encoded_point(false);
    let signature =
        k256::ecdsa::Signature::from_scalars(x_coordinate::<k256::Secp256k1>(&sig.big_r), sig.s)
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
            big_r: sig.big_r,
            s: sig.s,
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
            big_r: sig.big_r,
            s: sig.s,
            recovery_id: 1,
        });
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}

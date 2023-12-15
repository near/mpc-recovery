use crate::types::PublicKey;
use crate::util::ScalarExt;
use k256::elliptic_curve::CurveArithmetic;
use k256::{Scalar, Secp256k1};
use near_primitives::types::AccountId;
use sha2::{Digest, Sha256};

// Constant prefix that ensures key derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const KEY_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 key derivation:";

pub fn derive_epsilon(signer_id: &AccountId, path: &str) -> Scalar {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    let derivation_path = format!("{KEY_DERIVATION_PREFIX}{},{}", signer_id, path);
    let mut hasher = Sha256::new();
    hasher.update(derivation_path);
    Scalar::from_bytes(&hasher.finalize())
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

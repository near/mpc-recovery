use crate::util::ScalarExt;
use hkdf::Hkdf;
use k256::Scalar;
use near_primitives::hash::CryptoHash;
use sha2::{Digest, Sha256};

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

// Constant prefix that ensures delta derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const DELTA_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 delta derivation:";

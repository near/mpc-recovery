use k256::{
    elliptic_curve::scalar::FromUintUnchecked, elliptic_curve::CurveArithmetic, Scalar, Secp256k1,
    U256,
};

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl ScalarExt for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        Scalar::from_uint_unchecked(U256::from_le_slice(bytes))
    }
}

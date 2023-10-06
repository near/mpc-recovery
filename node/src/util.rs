use crate::types::PublicKey;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::EncodedPoint;

pub trait NearPublicKeyExt {
    fn into_affine_point(self) -> PublicKey;
}

impl NearPublicKeyExt for near_sdk::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        let mut bytes = self.into_bytes();
        bytes.insert(0, 0x04);
        let point = EncodedPoint::from_bytes(bytes).unwrap();
        PublicKey::from_encoded_point(&point).unwrap()
    }
}

impl NearPublicKeyExt for near_crypto::Secp256K1PublicKey {
    fn into_affine_point(self) -> PublicKey {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(self.as_ref());
        let point = EncodedPoint::from_bytes(bytes).unwrap();
        PublicKey::from_encoded_point(&point).unwrap()
    }
}

impl NearPublicKeyExt for near_crypto::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        match self {
            near_crypto::PublicKey::SECP256K1(public_key) => public_key.into_affine_point(),
            near_crypto::PublicKey::ED25519(_) => panic!("unsupported key type"),
        }
    }
}

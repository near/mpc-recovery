use borsh::{BorshDeserialize, BorshSerialize};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{
    elliptic_curve::{scalar::FromUintUnchecked, CurveArithmetic},
    Scalar, Secp256k1, U256,
};
use k256::{AffinePoint, EncodedPoint};
use serde::{Deserialize, Serialize};

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt {
    fn from_bytes(bytes: &[u8]) -> Self;
}

// TODO prevent bad scalars from beind sent
impl ScalarExt for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        Scalar::from_uint_unchecked(U256::from_be_slice(bytes))
    }
}

// Is there a better way to force a borsh serialization?
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SerializableScalar {
    pub scalar: Scalar,
}

impl BorshSerialize for SerializableScalar {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_ser: [u8; 32] = self.scalar.to_bytes().into();
        BorshSerialize::serialize(&to_ser, writer)
    }
}

impl BorshDeserialize for SerializableScalar {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
        let scalar = Scalar::from_bytes(&from_ser[..]);
        Ok(SerializableScalar { scalar })
    }
}

pub trait NearPublicKeyExt {
    fn into_affine_point(self) -> PublicKey;
}

impl NearPublicKeyExt for String {
    fn into_affine_point(self) -> PublicKey {
        let public_key_value = serde_json::json!(self);
        serde_json::from_value(public_key_value).expect("Failed to deserialize struct")
    }
}

impl NearPublicKeyExt for near_sdk::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        let mut bytes = self.into_bytes();
        bytes[0] = 0x04;
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

pub trait AffinePointExt {
    fn into_near_public_key(self) -> near_crypto::PublicKey;
    fn to_base58(&self) -> String;
}

impl AffinePointExt for AffinePoint {
    fn into_near_public_key(self) -> near_crypto::PublicKey {
        near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &self.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        )
    }

    fn to_base58(&self) -> String {
        let key = near_crypto::Secp256K1PublicKey::try_from(
            &self.to_encoded_point(false).as_bytes()[1..65],
        )
        .unwrap();
        format!("{:?}", key)
    }
}

// Is there a better way to force a borsh serialization?
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}

impl BorshSerialize for SerializableAffinePoint {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_ser = self.affine_point.into_near_public_key();
        BorshSerialize::serialize(&to_ser, writer)
    }
}

impl BorshDeserialize for SerializableAffinePoint {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let from_ser: near_crypto::PublicKey = BorshDeserialize::deserialize_reader(reader)?;
        let affine_point = from_ser.into_affine_point();
        Ok(SerializableAffinePoint { affine_point })
    }
}

#[test]
fn serializeable_scalar_roundtrip() {
    use k256::elliptic_curve::PrimeField;
    let test_vec = vec![
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from_u128(u128::MAX),
        Scalar::from_bytes(&[3; 32]),
    ];

    for scalar in test_vec.into_iter() {
        let input = SerializableScalar { scalar };
        // Test borsh
        {
            let serialized = borsh::to_vec(&input).unwrap();
            let output: SerializableScalar = borsh::from_slice(&serialized).unwrap();
            assert_eq!(input, output, "Failed on {:?}", scalar);
        }

        dbg!(scalar);
        // Test Serde via JSON
        {
            let serialized = serde_json::to_vec(&input).unwrap();
            let output: SerializableScalar = serde_json::from_slice(&serialized).unwrap();
            assert_eq!(input, output, "Failed on {:?}", scalar);
        }
    }
}

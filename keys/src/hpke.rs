use std::sync::Arc;

use borsh::{self, BorshDeserialize, BorshSerialize};
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    OpModeR,
};

/// This can be used to customize the generated key. This will be used as a sort of
/// versioning mechanism for the key.
const INFO_ENTROPY: &[u8] = b"session-key-v1";

// Interchangeable type parameters for the HPKE context.
pub type Kem = X25519HkdfSha256;
pub type Aead = ChaCha20Poly1305;
pub type Kdf = HkdfSha384;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Ciphered {
    pub encapped_key: EncappedKey,
    pub text: CipherText,
    pub tag: Tag,
}

pub struct Tag(AeadTag<Aead>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(<Kem as hpke::Kem>::PublicKey);

// NOTE: Arc is used to hack up the fact that the internal private key does not have Send constraint.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(Arc<<Kem as hpke::Kem>::PrivateKey>);
pub struct EncappedKey(<Kem as hpke::Kem>::EncappedKey);

// Series of bytes that have been previously encoded/encrypted.
pub type CipherText = Vec<u8>;

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        hpke::Serializable::to_bytes(&self.0).into()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, hpke::HpkeError> {
        Ok(Self(hpke::Deserializable::from_bytes(bytes)?))
    }

    /// Assumes the bytes are correctly formatted.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::try_from_bytes(bytes).expect("invalid bytes")
    }

    pub fn encrypt(&self, msg: &[u8], associated_data: &[u8]) -> Ciphered {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_entropy();

        // Encapsulate a key and use the resulting shared secret to encrypt a message. The AEAD context
        // is what you use to encrypt.
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &hpke::OpModeS::Base,
            &self.0,
            INFO_ENTROPY,
            &mut csprng,
        )
        .expect("invalid server pubkey!");

        // On success, seal_in_place_detached() will encrypt the plaintext in place
        let mut ciphertext = msg.to_vec();
        let tag = sender_ctx
            .seal_in_place_detached(&mut ciphertext, associated_data)
            .expect("encryption failed!");

        Ciphered {
            encapped_key: EncappedKey(encapped_key),
            text: ciphertext,
            tag: Tag(tag),
        }
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        PublicKey::try_from_bytes(&<Vec<u8> as serde::Deserialize>::deserialize(deserializer)?)
            .map_err(|err| serde::de::Error::custom(format!("invalid HPKE public key: {err:?}")))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.to_bytes(), writer)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        Ok(Self::from_bytes(
            &<Vec<u8> as BorshDeserialize>::deserialize(buf)?,
        ))
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        hpke::Serializable::to_bytes(self.0.as_ref()).into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, hpke::HpkeError> {
        Ok(Self(Arc::new(hpke::Deserializable::from_bytes(bytes)?)))
    }

    pub fn decrypt(&self, cipher: &Ciphered, associated_data: &[u8]) -> Vec<u8> {
        // Decapsulate and derive the shared secret. This creates a shared AEAD context.
        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.0,
            &cipher.encapped_key.0,
            INFO_ENTROPY,
        )
        .expect("failed to set up receiver!");

        // On success, open_in_place_detached() will decrypt the ciphertext in place
        let mut plaintext = cipher.text.to_vec();
        receiver_ctx
            .open_in_place_detached(&mut plaintext, associated_data, &cipher.tag.0)
            .expect("invalid ciphertext!");

        plaintext
    }
}

impl serde::Serialize for EncappedKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&hpke::Serializable::to_bytes(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for EncappedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self(
            hpke::Deserializable::from_bytes(&<Vec<u8> as serde::Deserialize>::deserialize(
                deserializer,
            )?)
            .map_err(|err| {
                serde::de::Error::custom(format!("invalid HPKE encapped key: {err:?}"))
            })?,
        ))
    }
}

impl serde::Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&hpke::Serializable::to_bytes(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Tag(hpke::Deserializable::from_bytes(
            &<Vec<u8> as serde::Deserialize>::deserialize(deserializer)?,
        )
        .map_err(|err| {
            serde::de::Error::custom(format!("invalid HPKE tag: {err:?}"))
        })?))
    }
}

pub fn generate() -> (SecretKey, PublicKey) {
    let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_entropy();
    let (sk, pk) = <Kem as hpke::Kem>::gen_keypair(&mut csprng);
    (SecretKey(Arc::new(sk)), PublicKey(pk))
}

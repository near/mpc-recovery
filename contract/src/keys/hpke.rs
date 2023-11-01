use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    OpModeR, OpModeS,
};
// use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use rand::rngs::StdRng;
use rand::SeedableRng;

const INFO_STR: &[u8] = b"example session";

// Interchangeable type parameters for the HPKE context.
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

pub struct Cipher {
    pub encapped_key: EncappedKey,
    pub text: CipherText,
    pub tag: Tag,
}

pub type Tag = AeadTag<Aead>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(<Kem as hpke::Kem>::PublicKey);
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(<Kem as hpke::Kem>::PrivateKey);
pub struct EncappedKey(<Kem as hpke::Kem>::EncappedKey);

pub type PublicKeyBytes = [u8; 32];

// Series of bytes that have been previously encoded/encrypted.
pub type CipherText = Vec<u8>;

impl PublicKey {
    pub fn to_bytes(&self) -> PublicKeyBytes {
        hpke::Serializable::to_bytes(&self.0).into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, hpke::HpkeError> {
        Ok(Self(hpke::Deserializable::from_bytes(bytes)?))
    }

    pub fn encrypt(&self, msg: &[u8], associated_data: &[u8]) -> Cipher {
        let mut csprng = StdRng::from_entropy();

        // Encapsulate a key and use the resulting shared secret to encrypt a message. The AEAD context
        // is what you use to encrypt.
        let (encapped_key, mut sender_ctx) =
            hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &self.0, INFO_STR, &mut csprng)
                .expect("invalid server pubkey!");

        // On success, seal_in_place_detached() will encrypt the plaintext in place
        let mut ciphertext = msg.to_vec();
        let tag = sender_ctx
            .seal_in_place_detached(&mut ciphertext, associated_data)
            .expect("encryption failed!");

        Cipher {
            encapped_key: EncappedKey(encapped_key),
            text: ciphertext,
            tag,
        }
    }
}

impl SecretKey {
    pub fn decrypt(&self, cipher: Cipher, associated_data: &[u8]) -> Vec<u8> {
        // Decapsulate and derive the shared secret. This creates a shared AEAD context.
        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.0,
            &cipher.encapped_key.0,
            INFO_STR,
        )
        .expect("failed to set up receiver!");

        // On success, open_in_place_detached() will decrypt the ciphertext in place
        let mut plaintext = cipher.text.to_vec();
        receiver_ctx
            .open_in_place_detached(&mut plaintext, associated_data, &cipher.tag)
            .expect("invalid ciphertext!");

        plaintext
    }
}

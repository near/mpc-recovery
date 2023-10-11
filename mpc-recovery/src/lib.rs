// TODO: FIXME: Remove this once we have a better way to handle these large errors
#![allow(clippy::result_large_err)]

use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::OsRng;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use curv::elliptic::curves::Ed25519;
use curv::elliptic::curves::Point;
use multi_party_eddsa::protocols::ExpandedKeyPair;

pub mod error;
pub mod firewall;
pub mod gcp;
pub mod key_recovery;
pub mod leader_node;
pub mod metrics;
pub mod msg;
pub mod nar;
pub mod oauth;
pub mod primitives;
pub mod relayer;
pub mod sign_node;
pub mod transaction;
pub mod utils;

type NodeId = u64;

pub use leader_node::run as run_leader_node;
pub use leader_node::Config as LeaderConfig;
pub use sign_node::run as run_sign_node;
pub use sign_node::Config as SignerConfig;

pub struct GenerateResult {
    pub pk_set: Vec<Point<Ed25519>>,
    pub secrets: Vec<(ExpandedKeyPair, GenericArray<u8, U32>)>,
}

#[tracing::instrument(level = "debug", skip_all, fields(n = n))]
pub fn generate(n: usize) -> GenerateResult {
    // Let's tie this up to a deterministic RNG when we can
    let sk_set: Vec<_> = (1..=n).map(|_| ExpandedKeyPair::create()).collect();
    let cipher_keys: Vec<_> = (1..=n)
        .map(|_| Aes256Gcm::generate_key(&mut OsRng))
        .collect();
    let pk_set: Vec<_> = sk_set.iter().map(|sk| sk.public_key.clone()).collect();
    tracing::debug!(public_key = ?pk_set);

    GenerateResult {
        pk_set,
        secrets: sk_set.into_iter().zip(cipher_keys.into_iter()).collect(),
    }
}

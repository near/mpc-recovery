use curv::elliptic::curves::Ed25519;
use curv::elliptic::curves::Point;
use multi_party_eddsa::protocols::ExpandedKeyPair;

pub mod gcp;
pub mod key_recovery;
pub mod leader_node;
pub mod msg;
pub mod nar;
pub mod oauth;
pub mod primitives;
pub mod relayer;
pub mod sign_node;
pub mod transaction;

type NodeId = u64;

pub use leader_node::run as run_leader_node;
pub use leader_node::Config as LeaderConfig;
pub use sign_node::run as run_sign_node;

#[tracing::instrument(level = "debug", skip_all, fields(n = n))]
pub fn generate(n: usize) -> (Vec<Point<Ed25519>>, Vec<ExpandedKeyPair>) {
    // Let's tie this up to a deterministic RNG when we can
    let sk_set: Vec<_> = (1..=n).map(|_| ExpandedKeyPair::create()).collect();
    let pk_set: Vec<_> = sk_set.iter().map(|sk| sk.public_key.clone()).collect();
    tracing::debug!(public_key = ?pk_set);

    (pk_set, sk_set)
}

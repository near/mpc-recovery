use std::sync::Arc;

use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{protocol::Protocol, KeygenOutput};
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};
use tokio::sync::RwLock;

pub type PrivateKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
pub type KeygenProtocol = Arc<RwLock<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>>;
pub type ReshareProtocol = Arc<RwLock<dyn Protocol<Output = PrivateKeyShare> + Send + Sync>>;
pub type TripleProtocol =
    Arc<std::sync::RwLock<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>> + Send + Sync>>;

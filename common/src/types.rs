use cait_sith::{protocol::Protocol, KeygenOutput};
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};

pub type PrivateKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
pub type KeygenProtocol = Box<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>;
pub type ReshareProtocol = Box<dyn Protocol<Output = PrivateKeyShare> + Send + Sync>;

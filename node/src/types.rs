use std::sync::Arc;

use cait_sith::protocol::{InitializationError, Participant};
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{protocol::Protocol, KeygenOutput};
use cait_sith::{FullSignature, PresignOutput};
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};
use tokio::sync::{RwLock, RwLockWriteGuard};

pub type SecretKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
pub type ReshareProtocol = Arc<RwLock<dyn Protocol<Output = SecretKeyShare> + Send + Sync>>;
pub type TripleProtocol =
    Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>> + Send + Sync>;
pub type PresignatureProtocol = Box<dyn Protocol<Output = PresignOutput<Secp256k1>> + Send + Sync>;
pub type SignatureProtocol = Box<dyn Protocol<Output = FullSignature<Secp256k1>> + Send + Sync>;

#[derive(Clone)]
pub struct KeygenProtocol {
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    protocol: Arc<RwLock<Box<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>>>,
}

impl KeygenProtocol {
    pub fn new(
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Self, InitializationError> {
        Ok(Self {
            threshold,
            me,
            participants: participants.into(),
            protocol: Arc::new(RwLock::new(Box::new(cait_sith::keygen::<Secp256k1>(
                &participants,
                me,
                threshold,
            )?))),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        *self.write().await = Box::new(cait_sith::keygen::<Secp256k1>(
            &self.participants,
            self.me,
            self.threshold,
        )?);
        Ok(())
    }

    pub async fn write(
        &self,
    ) -> RwLockWriteGuard<'_, Box<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>>
    {
        self.protocol.write().await
    }
}

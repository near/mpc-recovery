use std::sync::Arc;
use std::time::Duration;

use cait_sith::protocol::{InitializationError, Participant};
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{protocol::Protocol, KeygenOutput};
use cait_sith::{FullSignature, PresignOutput};
use k256::{elliptic_curve::CurveArithmetic, Secp256k1};
use tokio::sync::{RwLock, RwLockWriteGuard};

use crate::protocol::contract::ResharingContractState;

/// Default timeout for triple generation protocols. Times out after 5 minutes of being alive.
pub const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub type SecretKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
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
                participants,
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

#[derive(Clone)]
pub struct ReshareProtocol {
    old_participants: Vec<Participant>,
    new_participants: Vec<Participant>,
    me: Participant,
    threshold: usize,
    private_share: Option<SecretKeyShare>,
    protocol: Arc<RwLock<Box<dyn Protocol<Output = SecretKeyShare> + Send + Sync>>>,
    root_pk: PublicKey,
}

impl ReshareProtocol {
    pub fn new(
        private_share: Option<SecretKeyShare>,
        me: Participant,
        contract_state: &ResharingContractState,
    ) -> Result<Self, InitializationError> {
        let old_participants = contract_state
            .old_participants
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        let new_participants = contract_state
            .new_participants
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        Ok(Self {
            protocol: Arc::new(RwLock::new(Box::new(cait_sith::reshare::<Secp256k1>(
                &old_participants,
                contract_state.threshold,
                &new_participants,
                contract_state.threshold,
                me,
                private_share,
                contract_state.public_key,
            )?))),
            private_share,
            me,
            threshold: contract_state.threshold,
            old_participants,
            new_participants,
            root_pk: contract_state.public_key,
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        *self.write().await = Box::new(cait_sith::reshare::<Secp256k1>(
            &self.old_participants,
            self.threshold,
            &self.new_participants,
            self.threshold,
            self.me,
            self.private_share,
            self.root_pk,
        )?);
        Ok(())
    }

    pub async fn write(
        &self,
    ) -> RwLockWriteGuard<'_, Box<dyn Protocol<Output = SecretKeyShare> + Send + Sync>> {
        self.protocol.write().await
    }
}

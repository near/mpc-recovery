use super::contract::primitives::{ParticipantInfo, Participants};
use super::cryptography::CryptographicError;
use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleManager;
use super::SignQueue;
use crate::http_client::MessageQueue;
use crate::protocol::ParticipantInfo;
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};
use crate::types::{KeygenProtocol, PublicKey, ReshareProtocol, SecretKeyShare};
use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

#[derive(Clone)]
pub struct StartedState(pub Option<PersistentNodeData>);

#[derive(Clone)]
pub struct GeneratingState {
    pub participants: Participants,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
    pub messages: Arc<RwLock<MessageQueue>>,
}

impl GeneratingState {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone)]
pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub messages: Arc<RwLock<MessageQueue>>,
}

impl WaitingForConsensusState {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone)]
pub struct RunningState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub sign_queue: Arc<RwLock<SignQueue>>,
    pub triple_manager: Arc<RwLock<TripleManager>>,
    pub presignature_manager: Arc<RwLock<PresignatureManager>>,
    pub signature_manager: Arc<RwLock<SignatureManager>>,
    pub messages: Arc<RwLock<MessageQueue>>,
}

impl RunningState {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone)]
pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
    pub messages: Arc<RwLock<MessageQueue>>,
}

impl ResharingState {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo, CryptographicError> {
        fetch_participant(p, &self.new_participants)
            .or_else(|_| fetch_participant(p, &self.old_participants))
    }
}

#[derive(Clone)]
pub struct JoiningState {
    pub participants: BTreeMap<Participant, ParticipantInfo>,
    pub public_key: PublicKey,
}

impl JoiningState {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone, Default)]
#[allow(clippy::large_enum_variant)]
pub enum NodeState {
    #[default]
    Starting,
    Started(StartedState),
    Generating(GeneratingState),
    WaitingForConsensus(WaitingForConsensusState),
    Running(RunningState),
    Resharing(ResharingState),
    Joining(JoiningState),
}

impl NodeState {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo, CryptographicError> {
        match self {
            NodeState::Running(state) => state.fetch_participant(p),
            NodeState::Generating(state) => state.fetch_participant(p),
            NodeState::WaitingForConsensus(state) => state.fetch_participant(p),
            NodeState::Resharing(state) => state.fetch_participant(p),
            NodeState::Joining(state) => state.fetch_participant(p),
            _ => Err(CryptographicError::UnknownParticipant(*p)),
        }
    }
}

fn fetch_participant<'a>(
    p: &Participant,
    participants: &'a BTreeMap<Participant, ParticipantInfo>,
) -> Result<&'a ParticipantInfo, CryptographicError> {
    participants
        .get(p)
        .ok_or_else(|| CryptographicError::UnknownParticipant(*p))
}

use super::contract::primitives::{ParticipantInfo, Participants};
use super::cryptography::CryptographicError;
use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleManager;
use super::SignQueue;
use crate::http_client::MessageQueue;
use crate::storage::triple_storage::TripleData;
use crate::types::{KeygenProtocol, PublicKey, ReshareProtocol, SecretKeyShare};
use cait_sith::protocol::Participant;
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

impl fmt::Debug for PersistentNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentNodeData")
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct StartedState {
    pub persistent_node_data: Option<PersistentNodeData>,
    pub triple_data: Vec<TripleData>,
}

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

impl fmt::Debug for WaitingForConsensusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitingForConsensusState")
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .field("participants", &self.participants)
            .finish()
    }
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
    pub participants: Participants,
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

    pub fn find_participant_info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        match self {
            NodeState::Starting => None,
            NodeState::Started(_) => None,
            NodeState::Generating(state) => state.participants.find_participant_info(account_id),
            NodeState::WaitingForConsensus(state) => {
                state.participants.find_participant_info(account_id)
            }
            NodeState::Running(state) => state.participants.find_participant_info(account_id),
            NodeState::Resharing(state) => state
                .new_participants
                .find_participant_info(account_id)
                .or_else(|| state.old_participants.find_participant_info(account_id)),
            NodeState::Joining(state) => state.participants.find_participant_info(account_id),
        }
    }
}

fn fetch_participant<'a>(
    p: &Participant,
    participants: &'a Participants,
) -> Result<&'a ParticipantInfo, CryptographicError> {
    participants
        .get(p)
        .ok_or_else(|| CryptographicError::UnknownParticipant(*p))
}

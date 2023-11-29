use super::presignature::PresignatureManager;
use super::signature::SignatureManager;
use super::triple::TripleManager;
use super::SignQueue;
use crate::protocol::ParticipantInfo;
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
    pub participants: BTreeMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

#[derive(Clone)]
pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: BTreeMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

#[derive(Clone)]
pub struct RunningState {
    pub epoch: u64,
    pub participants: BTreeMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub sign_queue: Arc<RwLock<SignQueue>>,
    pub triple_manager: Arc<RwLock<TripleManager>>,
    pub presignature_manager: Arc<RwLock<PresignatureManager>>,
    pub signature_manager: Arc<RwLock<SignatureManager>>,
}

#[derive(Clone)]
pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: BTreeMap<Participant, ParticipantInfo>,
    pub new_participants: BTreeMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
}

#[derive(Clone)]
pub struct JoiningState {
    pub public_key: PublicKey,
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
    pub fn fetch_participant(&self, p: Participant) -> Option<ParticipantInfo> {
        let participants = match self {
            NodeState::Running(state) => &state.participants,
            NodeState::Generating(state) => &state.participants,
            NodeState::WaitingForConsensus(state) => &state.participants,
            NodeState::Resharing(state) => {
                if let Some(info) = state.new_participants.get(&p) {
                    return Some(info.clone());
                } else if let Some(info) = state.old_participants.get(&p) {
                    return Some(info.clone());
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        participants.get(&p).cloned()
    }
}

use super::triple::TripleManager;
use crate::protocol::ParticipantInfo;
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};
use cait_sith::protocol::Participant;
use std::collections::HashMap;

#[derive(Clone)]
pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

#[derive(Clone)]
pub struct StartedState(pub Option<PersistentNodeData>);

#[derive(Clone)]
pub struct GeneratingState {
    pub participants: HashMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

#[derive(Clone)]
pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: HashMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

#[derive(Clone)]
pub struct RunningState {
    pub epoch: u64,
    pub participants: HashMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
    pub triple_manager: TripleManager,
}

#[derive(Clone)]
pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: HashMap<Participant, ParticipantInfo>,
    pub new_participants: HashMap<Participant, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
}

#[derive(Clone)]
pub struct JoiningState {
    pub public_key: PublicKey,
}

#[derive(Clone, Default)]
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

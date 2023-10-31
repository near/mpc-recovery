use super::presignature::PresignatureManager;
use super::triple::TripleManager;
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};
use cait_sith::protocol::Participant;
use std::collections::HashMap;
use url::Url;

pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct StartedState(pub Option<PersistentNodeData>);

pub struct GeneratingState {
    pub participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
}

pub struct WaitingForConsensusState {
    pub epoch: u64,
    pub participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
}

pub struct RunningState {
    pub epoch: u64,
    pub participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub private_share: PrivateKeyShare,
    pub public_key: PublicKey,
    pub triple_manager: TripleManager,
    pub presignature_manager: PresignatureManager,
}

pub struct ResharingState {
    pub old_epoch: u64,
    pub old_participants: HashMap<Participant, Url>,
    pub new_participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
}

pub struct JoiningState {
    pub public_key: PublicKey,
}

#[derive(Default)]
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

use crate::types::PublicKey;
use crate::util::NearPublicKeyExt;
use cait_sith::protocol::Participant;
use mpc_contract::ParticipantInfo;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
pub struct InitializedContractState {
    pub participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub pk_votes: HashMap<near_crypto::PublicKey, HashSet<Participant>>,
}

impl From<mpc_contract::InitializedContractState> for InitializedContractState {
    fn from(value: mpc_contract::InitializedContractState) -> Self {
        InitializedContractState {
            participants: contract_participants_into_cait_participants(value.participants),
            threshold: value.threshold,
            pk_votes: value
                .pk_votes
                .into_iter()
                .map(|(pk, participants)| {
                    (
                        near_crypto::PublicKey::SECP256K1(
                            near_crypto::Secp256K1PublicKey::try_from(&pk.as_bytes()[1..]).unwrap(),
                        ),
                        participants
                            .into_iter()
                            .map(Participant::from)
                            .collect::<HashSet<_>>(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: HashMap<Participant, ParticipantInfo>,
    pub join_votes: HashMap<Participant, HashSet<Participant>>,
    pub leave_votes: HashMap<Participant, HashSet<Participant>>,
}

impl From<mpc_contract::RunningContractState> for RunningContractState {
    fn from(value: mpc_contract::RunningContractState) -> Self {
        RunningContractState {
            epoch: value.epoch,
            participants: contract_participants_into_cait_participants(value.participants),
            threshold: value.threshold,
            public_key: value.public_key.into_affine_point(),
            candidates: value
                .candidates
                .into_iter()
                .map(|(p, p_info)| (Participant::from(p), p_info))
                .collect(),
            join_votes: value
                .join_votes
                .into_iter()
                .map(|(p, ps)| {
                    (
                        Participant::from(p),
                        ps.into_iter().map(Participant::from).collect(),
                    )
                })
                .collect(),
            leave_votes: value
                .leave_votes
                .into_iter()
                .map(|(p, ps)| {
                    (
                        Participant::from(p),
                        ps.into_iter().map(Participant::from).collect(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: HashMap<Participant, Url>,
    pub new_participants: HashMap<Participant, Url>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<Participant>,
}

impl From<mpc_contract::ResharingContractState> for ResharingContractState {
    fn from(value: mpc_contract::ResharingContractState) -> Self {
        ResharingContractState {
            old_epoch: value.old_epoch,
            old_participants: contract_participants_into_cait_participants(value.old_participants),
            new_participants: contract_participants_into_cait_participants(value.new_participants),
            threshold: value.threshold,
            public_key: value.public_key.into_affine_point(),
            finished_votes: value
                .finished_votes
                .into_iter()
                .map(Participant::from)
                .collect(),
        }
    }
}

#[derive(Debug)]
pub enum ProtocolContractState {
    Initialized(InitializedContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolContractState {
    pub fn participants(&self) -> &HashMap<Participant, Url> {
        match self {
            ProtocolContractState::Initialized(InitializedContractState {
                participants, ..
            }) => participants,
            ProtocolContractState::Running(RunningContractState { participants, .. }) => {
                participants
            }
            ProtocolContractState::Resharing(ResharingContractState {
                old_participants, ..
            }) => old_participants,
        }
    }

    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ProtocolContractState::Initialized { .. } => None,
            ProtocolContractState::Running(RunningContractState { public_key, .. }) => {
                Some(public_key)
            }
            ProtocolContractState::Resharing(ResharingContractState { public_key, .. }) => {
                Some(public_key)
            }
        }
    }

    pub fn threshold(&self) -> usize {
        match self {
            ProtocolContractState::Initialized(InitializedContractState { threshold, .. }) => {
                *threshold
            }
            ProtocolContractState::Running(RunningContractState { threshold, .. }) => *threshold,
            ProtocolContractState::Resharing(ResharingContractState { threshold, .. }) => {
                *threshold
            }
        }
    }
}

impl TryFrom<mpc_contract::ProtocolContractState> for ProtocolContractState {
    type Error = ();

    fn try_from(value: mpc_contract::ProtocolContractState) -> Result<Self, Self::Error> {
        match value {
            mpc_contract::ProtocolContractState::NonInitialized => Err(()),
            mpc_contract::ProtocolContractState::Initialized(state) => {
                Ok(ProtocolContractState::Initialized(state.into()))
            }
            mpc_contract::ProtocolContractState::Running(state) => {
                Ok(ProtocolContractState::Running(state.into()))
            }
            mpc_contract::ProtocolContractState::Resharing(state) => {
                Ok(ProtocolContractState::Resharing(state.into()))
            }
        }
    }
}

fn contract_participants_into_cait_participants(
    participants: HashMap<AccountId, ParticipantInfo>,
) -> HashMap<Participant, Url> {
    participants
        .into_values()
        .map(|p| {
            (
                Participant::from(p.id),
                Url::try_from(p.url.as_str()).unwrap(),
            )
        })
        .collect()
}

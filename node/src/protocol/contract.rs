use crate::types::PublicKey;
use crate::util::NearPublicKeyExt;
use cait_sith::protocol::Participant;
use mpc_contract::ProtocolContractState;
use mpc_keys::hpke;
use near_primitives::borsh::BorshDeserialize;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

type ParticipantId = u32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: near_crypto::PublicKey,
}

impl From<mpc_contract::ParticipantInfo> for ParticipantInfo {
    fn from(value: mpc_contract::ParticipantInfo) -> Self {
        ParticipantInfo {
            id: value.id,
            account_id: value.account_id,
            url: value.url,
            cipher_pk: hpke::PublicKey::from_bytes(&value.cipher_pk),
            sign_pk: BorshDeserialize::try_from_slice(value.sign_pk.as_bytes()).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitializedContractState {
    pub participants: HashMap<Participant, ParticipantInfo>,
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
    pub participants: HashMap<Participant, ParticipantInfo>,
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
                .map(|(p, p_info)| (Participant::from(p), p_info.into()))
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
    pub old_participants: HashMap<Participant, ParticipantInfo>,
    pub new_participants: HashMap<Participant, ParticipantInfo>,
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
pub enum ProtocolState {
    Initialized(InitializedContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolState {
    pub fn participants(&self) -> &HashMap<Participant, ParticipantInfo> {
        match self {
            ProtocolState::Initialized(InitializedContractState { participants, .. }) => {
                participants
            }
            ProtocolState::Running(RunningContractState { participants, .. }) => participants,
            ProtocolState::Resharing(ResharingContractState {
                old_participants, ..
            }) => old_participants,
        }
    }

    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ProtocolState::Initialized { .. } => None,
            ProtocolState::Running(RunningContractState { public_key, .. }) => Some(public_key),
            ProtocolState::Resharing(ResharingContractState { public_key, .. }) => Some(public_key),
        }
    }

    pub fn threshold(&self) -> usize {
        match self {
            ProtocolState::Initialized(InitializedContractState { threshold, .. }) => *threshold,
            ProtocolState::Running(RunningContractState { threshold, .. }) => *threshold,
            ProtocolState::Resharing(ResharingContractState { threshold, .. }) => *threshold,
        }
    }
}

impl TryFrom<ProtocolContractState> for ProtocolState {
    type Error = ();

    fn try_from(value: ProtocolContractState) -> Result<Self, Self::Error> {
        match value {
            ProtocolContractState::NonInitialized => Err(()),
            ProtocolContractState::Initialized(state) => {
                Ok(ProtocolState::Initialized(state.into()))
            }
            ProtocolContractState::Running(state) => Ok(ProtocolState::Running(state.into())),
            ProtocolContractState::Resharing(state) => Ok(ProtocolState::Resharing(state.into())),
        }
    }
}

fn contract_participants_into_cait_participants(
    participants: HashMap<AccountId, mpc_contract::ParticipantInfo>,
) -> HashMap<Participant, ParticipantInfo> {
    participants
        .into_values()
        .map(|p| (Participant::from(p.id), p.into()))
        .collect()
}

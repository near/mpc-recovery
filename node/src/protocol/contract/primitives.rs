use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use near_primitives::{borsh::BorshDeserialize, types::AccountId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

type ParticipantId = u32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: ParticipantId, // TODO: do we need this parameter?
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Participants {
    pub participants: BTreeMap<Participant, ParticipantInfo>,
}

impl From<mpc_contract::primitives::Participants> for Participants {
    fn from(contract_participants: mpc_contract::primitives::Participants) -> Self {
        Participants {
            // take position of participant in contract_participants as id for participants
            participants: contract_participants
                .participants
                .into_iter()
                .enumerate()
                .map(|(participant_id, participant)| {
                    let contract_participant_info = participant.1;
                    (
                        Participant::from(participant_id as ParticipantId),
                        ParticipantInfo {
                            id: participant_id as ParticipantId,
                            account_id: AccountId::from_str(
                                &contract_participant_info.account_id.to_string(),
                            )
                            .unwrap(),
                            url: contract_participant_info.url,
                            cipher_pk: hpke::PublicKey::from_bytes(
                                &contract_participant_info.cipher_pk,
                            ),
                            sign_pk: BorshDeserialize::try_from_slice(
                                contract_participant_info.sign_pk.as_bytes(),
                            )
                            .unwrap(),
                        },
                    )
                })
                .collect(),
        }
    }
}

impl IntoIterator for Participants {
    type Item = (Participant, ParticipantInfo);
    type IntoIter = std::collections::btree_map::IntoIter<Participant, ParticipantInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.participants.into_iter()
    }
}

impl Participants {
    pub fn get(&self, id: &Participant) -> Option<&ParticipantInfo> {
        self.participants.get(id)
    }

    pub fn contains_key(&self, id: &Participant) -> bool {
        self.participants.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &Participant> {
        self.participants.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Participant, &ParticipantInfo)> {
        self.participants.iter()
    }

    pub fn find_participant(&self, account_id: &AccountId) -> Option<Participant> {
        self.participants
            .iter()
            .find(|(_, participant_info)| participant_info.account_id == *account_id)
            .map(|(participant, _)| *participant)
    }

    pub fn find_participant_info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants
            .iter()
            .find(|(_, participant_info)| participant_info.account_id == *account_id)
            .map(|(_, participant_info)| participant_info)
    }

    pub fn contains_account_id(&self, account_id: &AccountId) -> bool {
        self.participants
            .iter()
            .any(|(_, participant_info)| participant_info.account_id == *account_id)
    }

    pub fn account_ids(&self) -> Vec<AccountId> {
        self.participants
            .iter()
            .map(|(_, participant_info)| participant_info.account_id.clone())
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Candidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

impl Candidates {
    pub fn get(&self, id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(id)
    }

    pub fn contains_key(&self, id: &AccountId) -> bool {
        self.candidates.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.candidates.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &CandidateInfo)> {
        self.candidates.iter()
    }
}

impl From<mpc_contract::primitives::Candidates> for Candidates {
    fn from(contract_candidates: mpc_contract::primitives::Candidates) -> Self {
        Candidates {
            candidates: contract_candidates
                .candidates
                .into_iter()
                .map(|(account_id, candidate_info)| {
                    (
                        AccountId::from_str(&account_id.to_string()).unwrap(), // TODO: fix unwrap
                        CandidateInfo {
                            account_id: AccountId::from_str(&candidate_info.account_id.to_string())
                                .unwrap(), // TODO: fix unwrap
                            url: candidate_info.url,
                            cipher_pk: hpke::PublicKey::from_bytes(&candidate_info.cipher_pk),
                            sign_pk: near_crypto::PublicKey::SECP256K1(
                                near_crypto::Secp256K1PublicKey::try_from(
                                    &candidate_info.sign_pk.as_bytes()[1..],
                                )
                                .unwrap(),
                            ),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PkVotes {
    pub pk_votes: BTreeMap<near_crypto::PublicKey, HashSet<AccountId>>,
}

impl PkVotes {
    pub fn get(&self, id: &near_crypto::PublicKey) -> Option<&HashSet<AccountId>> {
        self.pk_votes.get(id)
    }
}

impl From<mpc_contract::primitives::PkVotes> for PkVotes {
    fn from(contract_votes: mpc_contract::primitives::PkVotes) -> Self {
        PkVotes {
            pk_votes: contract_votes
                .votes
                .into_iter()
                .map(|(pk, participants)| {
                    (
                        near_crypto::PublicKey::SECP256K1(
                            near_crypto::Secp256K1PublicKey::try_from(&pk.as_bytes()[1..]).unwrap(),
                        ),
                        participants
                            .into_iter()
                            .map(|acc_id: near_sdk::AccountId| {
                                AccountId::from_str(&acc_id.to_string()).unwrap()
                                // TODO: fix unwrap
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Votes {
    pub votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Votes {
    pub fn get(&self, id: &AccountId) -> Option<&HashSet<AccountId>> {
        self.votes.get(id)
    }
}

impl From<mpc_contract::primitives::Votes> for Votes {
    fn from(contract_votes: mpc_contract::primitives::Votes) -> Self {
        Votes {
            votes: contract_votes
                .votes
                .into_iter()
                .map(|(account_id, participants)| {
                    (
                        AccountId::from_str(&account_id.to_string()).unwrap(), // TODO: fix unwrap
                        participants
                            .into_iter()
                            .map(|acc_id: near_sdk::AccountId| {
                                AccountId::from_str(&acc_id.to_string()).unwrap()
                                // TODO: fix unwrap
                            })
                            .collect(), // TODO: remove code duplication
                    )
                })
                .collect(),
        }
    }
}

use mpc_keys::hpke;
use near_primitives::borsh::BorshDeserialize;
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

type ParticipantId = u32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: near_crypto::PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
}

impl Participants {
    pub fn get(&self, id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(id)
    }

    pub fn contains_key(&self, id: &AccountId) -> bool {
        self.participants.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.participants.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &ParticipantInfo)> {
        self.participants.iter()
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

impl From<mpc_contract::primitives::CandidateInfo> for CandidateInfo {
    fn from(contract_info: mpc_contract::primitives::CandidateInfo) -> Self {
        CandidateInfo {
            account_id: AccountId::from(contract_info.account_id),
            url: contract_info.url,
            cipher_pk: hpke::PublicKey::from_bytes(&contract_info.cipher_pk),
            sign_pk: BorshDeserialize::try_from_slice(contract_info.sign_pk.as_bytes()).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PkVotes {
    pub pk_votes: BTreeMap<near_crypto::PublicKey, HashSet<AccountId>>,
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
                            .map(AccountId::from)
                            .collect::<HashSet<_>>(),
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

impl From<mpc_contract::Votes> for Votes {
    fn from(contract_votes: mpc_contract::Votes) -> Self {
        Votes {
            votes: contract_votes
                .votes
                .into_iter()
                .map(|(account_id, votes)| {
                    (
                        account_id,
                        votes
                            .into_iter()
                            .map(|account_id| account_id)
                            .collect::<HashSet<_>>(),
                    )
                })
                .collect(),
        }
    }
}
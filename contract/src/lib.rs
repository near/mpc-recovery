use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault, Promise, PromiseOrValue, PublicKey};
use std::collections::{BTreeMap, HashSet};

type ParticipantId = u32;

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[derive(
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub pk_votes: BTreeMap<PublicKey, HashSet<ParticipantId>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    // TODO: why is this account id for participants instead of participant id?
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: BTreeMap<ParticipantId, ParticipantInfo>,
    pub join_votes: BTreeMap<ParticipantId, HashSet<ParticipantId>>,
    pub leave_votes: BTreeMap<ParticipantId, HashSet<ParticipantId>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: BTreeMap<AccountId, ParticipantInfo>,
    // TODO: only store diff to save on storage
    pub new_participants: BTreeMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<ParticipantId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<[u8; 32], Option<String>>,
}

#[near_bindgen]
impl MpcContract {
    // TODO: only add ignore_state for dev environments
    #[init(ignore_state)]
    pub fn init(threshold: usize, participants: BTreeMap<AccountId, ParticipantInfo>) -> Self {
        MpcContract {
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                participants,
                threshold,
                pk_votes: BTreeMap::new(),
            }),
            pending_requests: LookupMap::new(b"m"),
        }
    }

    pub fn state(self) -> ProtocolContractState {
        self.protocol_state
    }

    pub fn join(
        &mut self,
        participant_id: ParticipantId,
        url: String,
        cipher_pk: hpke::PublicKey,
        sign_pk: PublicKey,
    ) {
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                participants,
                candidates,
                ..
            }) => {
                let account_id = env::signer_account_id();
                if participants.contains_key(&account_id) {
                    env::panic_str("this participant is already in the participant set");
                }
                candidates.insert(
                    participant_id,
                    ParticipantInfo {
                        id: participant_id,
                        account_id,
                        url,
                        cipher_pk,
                        sign_pk,
                    },
                );
            }
            _ => env::panic_str("protocol state can't accept new participants right now"),
        }
    }

    pub fn vote_join(&mut self, participant: ParticipantId) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                join_votes,
                ..
            }) => {
                let voting_participant = participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the participant set")
                    });
                let candidate = candidates
                    .get(&participant)
                    .unwrap_or_else(|| env::panic_str("candidate is not registered"));
                let voted = join_votes.entry(participant).or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.insert(candidate.account_id.clone(), candidate.clone());
                    self.protocol_state =
                        ProtocolContractState::Resharing(ResharingContractState {
                            old_epoch: *epoch,
                            old_participants: participants.clone(),
                            new_participants,
                            threshold: *threshold,
                            public_key: public_key.clone(),
                            finished_votes: HashSet::new(),
                        });
                    true
                } else {
                    false
                }
            }
            _ => env::panic_str("protocol state can't accept new participants right now"),
        }
    }

    pub fn vote_leave(&mut self, participant: ParticipantId) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                leave_votes,
                ..
            }) => {
                let voting_participant = participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the participant set")
                    });
                let candidate = candidates
                    .get(&participant)
                    .unwrap_or_else(|| env::panic_str("candidate is not registered"));
                let voted = leave_votes.entry(participant).or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.remove(&candidate.account_id);
                    self.protocol_state =
                        ProtocolContractState::Resharing(ResharingContractState {
                            old_epoch: *epoch,
                            old_participants: participants.clone(),
                            new_participants,
                            threshold: *threshold,
                            public_key: public_key.clone(),
                            finished_votes: HashSet::new(),
                        });
                    true
                } else {
                    false
                }
            }
            _ => env::panic_str("protocol state can't kick participants right now"),
        }
    }

    pub fn vote_pk(&mut self, public_key: PublicKey) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Initializing(InitializingContractState {
                participants,
                threshold,
                pk_votes,
            }) => {
                let voting_participant = participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the participant set")
                    });
                let voted = pk_votes.entry(public_key.clone()).or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= *threshold {
                    self.protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: 0,
                        participants: participants.clone(),
                        threshold: *threshold,
                        public_key,
                        candidates: BTreeMap::new(),
                        join_votes: BTreeMap::new(),
                        leave_votes: BTreeMap::new(),
                    });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::Running(state) if state.public_key == public_key => true,
            ProtocolContractState::Resharing(state) if state.public_key == public_key => true,
            _ => env::panic_str("can't change public key anymore"),
        }
    }

    pub fn vote_reshared(&mut self, epoch: u64) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Resharing(ResharingContractState {
                old_epoch,
                old_participants,
                new_participants,
                threshold,
                public_key,
                finished_votes,
            }) => {
                if *old_epoch + 1 != epoch {
                    env::panic_str("mismatched epochs");
                }
                let voting_participant = old_participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the old participant set")
                    });
                finished_votes.insert(voting_participant.id);
                if finished_votes.len() >= *threshold {
                    self.protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch + 1,
                        participants: new_participants.clone(),
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        candidates: BTreeMap::new(),
                        join_votes: BTreeMap::new(),
                        leave_votes: BTreeMap::new(),
                    });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::Running(state) => {
                if state.epoch == epoch {
                    true
                } else {
                    env::panic_str("protocol is not resharing right now")
                }
            }
            _ => env::panic_str("protocol is not resharing right now"),
        }
    }

    #[allow(unused_variables)]
    pub fn sign(&mut self, payload: [u8; 32], path: String) -> Promise {
        self.pending_requests.insert(&payload, &None);
        Self::ext(env::current_account_id()).sign_helper(payload)
    }

    pub fn sign_helper(&mut self, payload: [u8; 32]) -> PromiseOrValue<String> {
        if let Some(signature) = self.pending_requests.get(&payload) {
            match signature {
                Some(signature) => {
                    self.pending_requests.remove(&payload);
                    PromiseOrValue::Value(signature)
                }
                None => {
                    env::log_str("not ready");
                    let account_id = env::current_account_id();
                    PromiseOrValue::Promise(Self::ext(account_id).sign_helper(payload))
                }
            }
        } else {
            env::panic_str("unexpected request");
        }
    }

    #[allow(unused_variables)]
    pub fn respond(&mut self, payload: [u8; 32], big_r: String, s: String) {
        self.pending_requests.insert(&payload, &Some(s));
    }
}

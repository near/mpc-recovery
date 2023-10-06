use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, AccountId, PublicKey};
use std::collections::{HashMap, HashSet};

type ParticipantId = u32;

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
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializedContractState {
    pub participants: HashMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub pk_votes: HashMap<PublicKey, HashSet<ParticipantId>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: HashMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub join_votes: HashMap<ParticipantInfo, HashSet<ParticipantId>>,
    pub leave_votes: HashMap<ParticipantInfo, HashSet<ParticipantId>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: HashMap<AccountId, ParticipantInfo>,
    // TODO: only store diff to save on storage
    pub new_participants: HashMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashMap<ParticipantInfo, HashSet<ParticipantId>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    NonInitialized,
    Initialized(InitializedContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
}

impl Default for MpcContract {
    fn default() -> Self {
        Self {
            protocol_state: ProtocolContractState::NonInitialized,
        }
    }
}

#[near_bindgen]
impl MpcContract {
    #[init]
    pub fn init(threshold: usize, participants: HashMap<AccountId, ParticipantInfo>) -> Self {
        MpcContract {
            protocol_state: ProtocolContractState::Initialized(InitializedContractState {
                participants,
                threshold,
                pk_votes: HashMap::new(),
            }),
        }
    }

    pub fn state(self) -> ProtocolContractState {
        self.protocol_state
    }

    pub fn vote_join(&mut self, participant: ParticipantInfo) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                join_votes,
                ..
            }) => {
                let voting_participant = participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the participant set")
                    });
                if participants.contains_key(&participant.account_id) {
                    env::panic_str("this participant is already in the participant set")
                }
                let voted = join_votes.entry(participant.clone()).or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.insert(participant.account_id.clone(), participant);
                    self.protocol_state =
                        ProtocolContractState::Resharing(ResharingContractState {
                            old_epoch: *epoch,
                            old_participants: participants.clone(),
                            new_participants,
                            threshold: *threshold,
                            public_key: public_key.clone(),
                            finished_votes: HashMap::new(),
                        });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::NonInitialized => {
                env::panic_str("protocol state hasn't been initialized yet")
            }
            _ => env::panic_str("protocol state can't accept new participants right now"),
        }
    }

    pub fn vote_leave(&mut self, participant: ParticipantInfo) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                leave_votes,
                ..
            }) => {
                let voting_participant = participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the participant set")
                    });
                if !participants.contains_key(&participant.account_id) {
                    env::panic_str("this participant is not in the participant set")
                }
                let voted = leave_votes.entry(participant.clone()).or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.remove(&participant.account_id);
                    self.protocol_state =
                        ProtocolContractState::Resharing(ResharingContractState {
                            old_epoch: *epoch,
                            old_participants: participants.clone(),
                            new_participants,
                            threshold: *threshold,
                            public_key: public_key.clone(),
                            finished_votes: HashMap::new(),
                        });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::NonInitialized => {
                env::panic_str("protocol state hasn't been initialized yet")
            }
            _ => env::panic_str("protocol state can't kick participants right now"),
        }
    }

    pub fn vote_pk(&mut self, public_key: PublicKey) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Initialized(InitializedContractState {
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
                        join_votes: HashMap::new(),
                        leave_votes: HashMap::new(),
                    });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::NonInitialized => {
                env::panic_str("protocol state hasn't been initialized yet")
            }
            _ => env::panic_str("can't change public key anymore"),
        }
    }

    pub fn vote_reshared(&mut self) -> bool {
        match &mut self.protocol_state {
            ProtocolContractState::Resharing(ResharingContractState {
                old_epoch,
                old_participants,
                new_participants,
                threshold,
                public_key,
                finished_votes,
            }) => {
                let voting_participant = old_participants
                    .get(&env::signer_account_id())
                    .unwrap_or_else(|| {
                        env::panic_str("calling account is not in the old participant set")
                    });
                let voted = finished_votes
                    .entry(voting_participant.clone())
                    .or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= *threshold {
                    self.protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch + 1,
                        participants: new_participants.clone(),
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        join_votes: HashMap::new(),
                        leave_votes: HashMap::new(),
                    });
                    true
                } else {
                    false
                }
            }
            ProtocolContractState::NonInitialized => {
                env::panic_str("protocol state hasn't been initialized yet")
            }
            _ => env::panic_str("protocol is not resharing right now"),
        }
    }

    pub fn sign(payload: Vec<u8>) -> [u8; 32] {
        env::random_seed_array()
    }
}

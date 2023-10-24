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
    pub candidates: HashMap<ParticipantId, ParticipantInfo>,
    pub join_votes: HashMap<ParticipantId, HashSet<ParticipantId>>,
    pub leave_votes: HashMap<ParticipantId, HashSet<ParticipantId>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: HashMap<AccountId, ParticipantInfo>,
    // TODO: only store diff to save on storage
    pub new_participants: HashMap<AccountId, ParticipantInfo>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<ParticipantId>,
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

    pub fn join(&mut self, participant_id: ParticipantId, url: String) {
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
                    },
                );
            }
            ProtocolContractState::NonInitialized => {
                env::panic_str("protocol state hasn't been initialized yet")
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
            ProtocolContractState::NonInitialized => {
                env::panic_str("protocol state hasn't been initialized yet")
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
                        candidates: HashMap::new(),
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
                        candidates: HashMap::new(),
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
}

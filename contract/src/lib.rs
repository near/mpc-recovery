use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::UnorderedMap;
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
)]
pub struct Participant {
    id: ParticipantId,
    account_id: AccountId,
    url: String,
}

#[derive(Serialize, Deserialize)]
pub struct State {
    participants: HashSet<Participant>,
    public_key: Option<PublicKey>,
    threshold: usize,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct MpcContract {
    public_key: Option<PublicKey>,
    threshold: usize,
    participants: UnorderedMap<AccountId, Participant>,
    join_votes: UnorderedMap<Participant, HashSet<ParticipantId>>,
    leave_votes: UnorderedMap<Participant, HashSet<ParticipantId>>,
    pk_votes: UnorderedMap<PublicKey, HashSet<ParticipantId>>,
}

impl Default for MpcContract {
    fn default() -> Self {
        Self {
            public_key: None,
            threshold: 0,
            participants: UnorderedMap::new(b"p"),
            join_votes: UnorderedMap::new(b"j"),
            leave_votes: UnorderedMap::new(b"l"),
            pk_votes: UnorderedMap::new(b"k"),
        }
    }
}

#[near_bindgen]
impl MpcContract {
    #[init]
    pub fn init(threshold: usize, participants: HashMap<AccountId, Participant>) -> Self {
        let mut participant_map = UnorderedMap::new(b"p");
        participant_map.extend(participants);
        MpcContract {
            public_key: None,
            threshold,
            participants: participant_map,
            join_votes: UnorderedMap::new(b"j"),
            leave_votes: UnorderedMap::new(b"l"),
            pk_votes: UnorderedMap::new(b"k"),
        }
    }

    pub fn state(&self) -> State {
        State {
            participants: self.participants.values().cloned().into_iter().collect(),
            public_key: self.public_key.clone(),
            threshold: self.threshold,
        }
    }

    pub fn vote_join(&mut self, participant: Participant) -> bool {
        let voting_participant = self
            .participants
            .get(&env::signer_account_id())
            .unwrap_or_else(|| env::panic_str("calling account is not in the participant set"));
        if self.participants.contains_key(&participant.account_id) {
            env::panic_str("this participant is already in the participant set")
        }
        let voted = self.join_votes.entry(participant.clone()).or_default();
        voted.insert(voting_participant.id);
        if voted.len() >= self.threshold {
            self.join_votes.remove(&participant);
            self.participants
                .insert(participant.account_id.clone(), participant);
            true
        } else {
            false
        }
    }

    pub fn vote_leave(&mut self, participant: Participant) -> bool {
        let voting_participant = self
            .participants
            .get(&env::signer_account_id())
            .unwrap_or_else(|| env::panic_str("calling account is not in the participant set"));
        if !self.participants.contains_key(&participant.account_id) {
            env::panic_str("this participant is not in the participant set")
        }
        let voted = self.leave_votes.entry(participant.clone()).or_default();
        voted.insert(voting_participant.id);
        if voted.len() >= self.threshold {
            self.leave_votes.remove(&participant);
            self.participants.remove(&participant.account_id);
            true
        } else {
            false
        }
    }

    pub fn vote_pk(&mut self, public_key: PublicKey) -> bool {
        let voting_participant = self
            .participants
            .get(&env::signer_account_id())
            .unwrap_or_else(|| env::panic_str("calling account is not in the participant set"));
        match &self.public_key {
            Some(state_public_key) if state_public_key == &public_key => return true,
            Some(_) => env::panic_str("participants already reached consensus on the public key"),
            None => {
                let voted = self.pk_votes.entry(public_key.clone()).or_default();
                voted.insert(voting_participant.id);
                if voted.len() >= self.threshold {
                    self.pk_votes.clear();
                    self.public_key = Some(public_key);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn sign(payload: Vec<u8>) -> [u8; 32] {
        env::random_seed_array()
    }
}

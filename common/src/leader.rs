use crate::{
    types::PublicKey,
    util::{serde_participant, serde_participants},
};
use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectRequest {
    #[serde(with = "serde_participant")]
    pub participant: Participant,
    pub address: Url,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LeaderNodeState {
    Discovering {
        #[serde(with = "serde_participants")]
        joining: HashMap<Participant, Url>,
    },
    Generating {
        #[serde(with = "serde_participants")]
        participants: HashMap<Participant, Url>,
        threshold: usize,
    },
    Running {
        #[serde(with = "serde_participants")]
        participants: HashMap<Participant, Url>,
        public_key: PublicKey,
        threshold: usize,
    },
    Resharing {
        #[serde(with = "serde_participants")]
        old_participants: HashMap<Participant, Url>,
        #[serde(with = "serde_participants")]
        new_participants: HashMap<Participant, Url>,
        public_key: PublicKey,
        threshold: usize,
    },
}

impl Default for LeaderNodeState {
    fn default() -> Self {
        LeaderNodeState::Discovering {
            joining: HashMap::new(),
        }
    }
}

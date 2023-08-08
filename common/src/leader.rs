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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LeaderNodeState {
    #[serde(with = "serde_participants")]
    pub participants: HashMap<Participant, Url>,
    pub public_key: Option<PublicKey>,
    pub threshold: usize,
    #[serde(with = "serde_participants")]
    pub joining: HashMap<Participant, Url>,
}

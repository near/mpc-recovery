use crate::{
    types::PublicKey,
    util::{serde_participant, serde_participants},
};
use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MsgRequest {
    #[serde(with = "serde_participant")]
    pub from: Participant,
    pub msg: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignNodeState {
    #[serde(with = "serde_participants")]
    pub participants: HashMap<Participant, Url>,
    pub public_key: Option<PublicKey>,
}

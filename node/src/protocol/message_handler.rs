use super::state::{GeneratingState, ProtocolState, ResharingState};
use cait_sith::protocol::{MessageData, Participant};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResharingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
}

pub trait MessageHandler {
    fn handle(&mut self, msg: MpcMessage);
}

impl MessageHandler for GeneratingState {
    fn handle(&mut self, msg: MpcMessage) {
        match msg {
            MpcMessage::Generating(msg) => self.protocol.message(msg.from, msg.data),
            _ => {
                tracing::warn!("receive non-processable message for our current state")
            }
        }
    }
}

impl MessageHandler for ResharingState {
    fn handle(&mut self, msg: MpcMessage) {
        match msg {
            MpcMessage::Resharing(msg) => self.protocol.message(msg.from, msg.data),
            _ => {
                tracing::warn!("receive non-processable message for our current state")
            }
        }
    }
}

impl MessageHandler for ProtocolState {
    fn handle(&mut self, msg: MpcMessage) {
        match self {
            ProtocolState::Generating(state) => state.handle(msg),
            ProtocolState::Resharing(state) => state.handle(msg),
            _ => {
                tracing::warn!("receive non-processable message for our current state")
            }
        }
    }
}

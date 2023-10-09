use std::collections::{HashMap, VecDeque};

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
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
}

#[derive(Default)]
pub struct MpcMessageQueue {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
}

impl MpcMessageQueue {
    pub fn push(&mut self, message: MpcMessage) {
        match message {
            MpcMessage::Generating(message) => self.generating.push_back(message),
            MpcMessage::Resharing(message) => self
                .resharing_bins
                .entry(message.epoch)
                .or_default()
                .push_back(message),
        }
    }
}

pub trait MessageHandler {
    fn handle(&mut self, queue: &mut MpcMessageQueue);
}

impl MessageHandler for GeneratingState {
    fn handle(&mut self, queue: &mut MpcMessageQueue) {
        match queue.generating.pop_front() {
            Some(msg) => {
                tracing::debug!("handling new generating message");
                self.protocol.message(msg.from, msg.data);
            }
            None => {
                tracing::debug!("no generating messages to handle")
            }
        };
    }
}

impl MessageHandler for ResharingState {
    fn handle(&mut self, queue: &mut MpcMessageQueue) {
        match queue
            .resharing_bins
            .entry(self.old_epoch)
            .or_default()
            .pop_front()
        {
            Some(msg) => {
                tracing::debug!("handling new resharing message");
                self.protocol.message(msg.from, msg.data);
            }
            None => {
                tracing::debug!("no resharing messages to handle")
            }
        };
    }
}

impl MessageHandler for ProtocolState {
    fn handle(&mut self, queue: &mut MpcMessageQueue) {
        match self {
            ProtocolState::Generating(state) => state.handle(queue),
            ProtocolState::Resharing(state) => state.handle(queue),
            _ => {
                tracing::debug!("skipping message processing")
            }
        }
    }
}

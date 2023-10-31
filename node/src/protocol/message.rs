use std::collections::{HashMap, VecDeque};

use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use cait_sith::protocol::{MessageData, Participant};
use serde::{Deserialize, Serialize};

pub trait MessageCtx {
    fn me(&self) -> Participant;
}

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
pub struct TripleMessage {
    pub id: u64,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: u64,
    pub triple1: u64,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
}

#[derive(Default)]
pub struct MpcMessageQueue {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
    triple_bins: HashMap<u64, HashMap<u64, VecDeque<TripleMessage>>>,
    presignature_bins: HashMap<u64, HashMap<u64, VecDeque<PresignatureMessage>>>,
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
            MpcMessage::Triple(message) => self
                .triple_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Presignature(message) => self
                .presignature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
        }
    }
}

pub trait MessageHandler {
    fn handle<C: MessageCtx + Send + Sync>(&mut self, ctx: C, queue: &mut MpcMessageQueue);
}

impl MessageHandler for GeneratingState {
    fn handle<C: MessageCtx + Send + Sync>(&mut self, _ctx: C, queue: &mut MpcMessageQueue) {
        while let Some(msg) = queue.generating.pop_front() {
            tracing::debug!("handling new generating message");
            self.protocol.message(msg.from, msg.data);
        }
    }
}

impl MessageHandler for ResharingState {
    fn handle<C: MessageCtx + Send + Sync>(&mut self, _ctx: C, queue: &mut MpcMessageQueue) {
        let q = queue.resharing_bins.entry(self.old_epoch).or_default();
        while let Some(msg) = q.pop_front() {
            tracing::debug!("handling new resharing message");
            self.protocol.message(msg.from, msg.data);
        }
    }
}

impl MessageHandler for RunningState {
    fn handle<C: MessageCtx + Send + Sync>(&mut self, _ctx: C, queue: &mut MpcMessageQueue) {
        for (id, queue) in queue.triple_bins.entry(self.epoch).or_default() {
            if let Some(protocol) = self.triple_manager.get_or_generate(*id) {
                while let Some(message) = queue.pop_front() {
                    protocol.message(message.from, message.data);
                }
            }
        }
        for (id, queue) in queue.presignature_bins.entry(self.epoch).or_default() {
            while let Some(message) = queue.pop_front() {
                if let Some(protocol) = self.presignature_manager.get_or_generate(
                    *id,
                    message.triple0,
                    message.triple1,
                    &mut self.triple_manager,
                    &self.public_key,
                    &self.private_share,
                ) {
                    protocol.message(message.from, message.data);
                }
            }
        }
    }
}

impl MessageHandler for NodeState {
    fn handle<C: MessageCtx + Send + Sync>(&mut self, ctx: C, queue: &mut MpcMessageQueue) {
        match self {
            NodeState::Generating(state) => state.handle(ctx, queue),
            NodeState::Resharing(state) => state.handle(ctx, queue),
            NodeState::Running(state) => state.handle(ctx, queue),
            _ => {
                tracing::debug!("skipping message processing")
            }
        }
    }
}

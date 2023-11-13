use std::collections::{HashMap, VecDeque};

use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use mpc_keys::hpke::Ciphered;
use near_crypto::Signature;
use serde::{Deserialize, Serialize};

pub trait MessageCtx {
    fn me(&self) -> Participant;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ResharingMessage {
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
}

#[derive(Default)]
pub struct MpcMessageQueue {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
    triple_bins: HashMap<u64, HashMap<u64, VecDeque<TripleMessage>>>,
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
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MessageHandleError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
}

#[async_trait]
pub trait MessageHandler {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError>;
}

#[async_trait]
impl MessageHandler for GeneratingState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        while let Some(msg) = queue.generating.pop_front() {
            tracing::debug!("handling new generating message");
            self.protocol.write().await.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for ResharingState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        let q = queue.resharing_bins.entry(self.old_epoch).or_default();
        while let Some(msg) = q.pop_front() {
            tracing::debug!("handling new resharing message");
            self.protocol.write().await.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for RunningState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        for (id, queue) in queue.triple_bins.entry(self.epoch).or_default() {
            if let Some(protocol) = self.triple_manager.get_or_generate(*id)? {
                let mut protocol = protocol.write().unwrap();
                while let Some(message) = queue.pop_front() {
                    protocol.message(message.from, message.data);
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl MessageHandler for NodeState {
    async fn handle<C: MessageCtx + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        match self {
            NodeState::Generating(state) => state.handle(ctx, queue).await,
            NodeState::Resharing(state) => state.handle(ctx, queue).await,
            NodeState::Running(state) => state.handle(ctx, queue).await,
            _ => {
                tracing::debug!("skipping message processing");
                Ok(())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The encrypted message with all it's related info.
    pub cipher: Ciphered,
    /// The signature used to verify the authenticity of the encrypted message.
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: Participant,
}

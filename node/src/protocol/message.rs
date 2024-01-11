use super::cryptography::CryptographicError;
use super::presignature::{self, PresignatureId};
use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::triple::TripleId;
use crate::http_client::SendError;
use crate::storage::SecretStorageError;
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use k256::Scalar;
use mpc_keys::hpke::{self, Ciphered};
use near_crypto::Signature;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

pub trait MessageCtx {
    fn my_near_acc_id(&self) -> &AccountId;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GeneratingMessage {
    pub from: AccountId,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ResharingMessage {
    pub epoch: u64,
    pub from: AccountId,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: u64,
    pub from: AccountId,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub epoch: u64,
    pub from: AccountId,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SignatureMessage {
    pub receipt_id: CryptoHash,
    pub proposer: Participant, // TODO: should it be node AccountId?
    pub presignature_id: PresignatureId,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub epoch: u64,
    pub from: AccountId,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum MpcMessage {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage),
}

#[derive(Default)]
pub struct MpcMessageQueue {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
    triple_bins: HashMap<u64, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature_bins: HashMap<u64, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature_bins: HashMap<u64, HashMap<CryptoHash, VecDeque<SignatureMessage>>>,
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
            MpcMessage::Signature(message) => self
                .signature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.receipt_id)
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
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error("failed to send a message: {0}")]
    SendError(SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("invalid state")]
    InvalidStateHandle(String),
    #[error("rpc error: {0}")]
    RpcError(#[from] near_fetch::Error),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

impl From<CryptographicError> for MessageHandleError {
    fn from(value: CryptographicError) -> Self {
        match value {
            CryptographicError::CaitSithInitializationError(e) => {
                Self::CaitSithInitializationError(e)
            }
            CryptographicError::CaitSithProtocolError(e) => Self::CaitSithProtocolError(e),
            CryptographicError::SyncError(e) => Self::SyncError(e),
            CryptographicError::SendError(e) => Self::SendError(e),
            CryptographicError::UnknownParticipant(e) => Self::UnknownParticipant(e),
            CryptographicError::DataConversion(e) => Self::DataConversion(e),
            CryptographicError::Encryption(e) => Self::Encryption(e),
            CryptographicError::InvalidStateHandle(e) => Self::InvalidStateHandle(e),
            CryptographicError::RpcError(e) => Self::RpcError(e),
            CryptographicError::SecretStorageError(e) => Self::SecretStorageError(e),
        }
    }
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
        ctx: C,
        queue: &mut MpcMessageQueue,
    ) -> Result<(), MessageHandleError> {
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = queue.generating.pop_front() {
            tracing::debug!("handling new generating message");
            let participant = self
                .participants
                .find_participant(&msg.from)
                .map(|participant| {
                    tracing::debug!(from = %msg.from, "handling message from");
                    protocol.message(participant, msg.data);
                })
                .unwrap_or_else(|| {
                    tracing::warn!(
                        participant = %msg.from,
                        "received message from unknown participant"
                    );
                });
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
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = q.pop_front() {
            let participant = self
                .old_participants
                .find_participant(&msg.from)
                .map(|participant| {
                    tracing::debug!(from = %msg.from, "handling resharing message from");
                    protocol.message(participant, msg.data);
                })
                .unwrap_or_else(|| {
                    tracing::warn!(
                        participant = %msg.from,
                        "received message from unknown participant in resharing state"
                    );
                });
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
        let mut triple_manager = self.triple_manager.write().await;
        for (id, queue) in queue.triple_bins.entry(self.epoch).or_default() {
            if let Some(protocol) = triple_manager.get_or_generate(*id)? {
                let mut protocol = protocol
                    .write()
                    .map_err(|err| MessageHandleError::SyncError(err.to_string()))?;
                while let Some(message) = queue.pop_front() {
                    let participant = self
                        .participants
                        .find_participant(&message.from)
                        .map(|participant| {
                            tracing::debug!(from = %message.from, "running state, triple message, handling message from");
                            protocol.message(participant, message.data);
                        })
                        .unwrap_or_else(|| {
                            tracing::warn!(
                                participant = %message.from,
                                "received message from unknown participant in running state"
                            );
                        });
                }
            }
        }

        let mut presignature_manager = self.presignature_manager.write().await;
        for (id, queue) in queue.presignature_bins.entry(self.epoch).or_default() {
            let mut leftover_messages = Vec::new();
            while let Some(message) = queue.pop_front() {
                match presignature_manager.get_or_generate(
                    *id,
                    message.triple0,
                    message.triple1,
                    &mut triple_manager,
                    &self.public_key,
                    &self.private_share,
                ) {
                    Ok(protocol) => {
                        let mut protocol = protocol
                            .write()
                            .map_err(|err| MessageHandleError::SyncError(err.to_string()))?;
                        let participant = self
                            .participants
                            .find_participant(&message.from)
                            .map(|participant| {
                                tracing::debug!(from = %message.from, "running state, presignature message, handling message from");
                                protocol.message(participant, message.data);
                            })
                            .unwrap_or_else(|| {
                                tracing::warn!(
                                    participant = %message.from,
                                    "received message from unknown participant in running state"
                                );
                            });
                    }
                    Err(presignature::GenerationError::AlreadyGenerated) => {
                        tracing::info!(id, "presignature already generated, nothing left to do")
                    }
                    Err(presignature::GenerationError::TripleIsMissing(_)) => {
                        // Store the message until we are ready to process it
                        leftover_messages.push(message)
                    }
                    Err(presignature::GenerationError::CaitSithInitializationError(error)) => {
                        return Err(error.into())
                    }
                }
            }
            if !leftover_messages.is_empty() {
                tracing::warn!(
                    msg_count = leftover_messages.len(),
                    "unable to process messages, storing for future"
                );
                queue.extend(leftover_messages);
            }
        }

        let mut signature_manager = self.signature_manager.write().await;
        for (receipt_id, queue) in queue.signature_bins.entry(self.epoch).or_default() {
            let mut leftover_messages = Vec::new();
            while let Some(message) = queue.pop_front() {
                tracing::info!(
                    presignature_id = message.presignature_id,
                    "new signature message"
                );
                // if !self
                //     .sign_queue
                //     .read()
                //     .await
                //     .contains(message.proposer, receipt_id.clone())
                // {
                //     leftover_messages.push(message);
                //     continue;
                // };
                // TODO: Validate that the message matches our sign_queue
                match signature_manager.get_or_generate(
                    *receipt_id,
                    message.proposer,
                    message.presignature_id,
                    message.msg_hash,
                    message.epsilon,
                    message.delta,
                    &mut presignature_manager,
                )? {
                    Some(protocol) => {
                        let mut protocol = protocol
                            .write()
                            .map_err(|err| MessageHandleError::SyncError(err.to_string()))?;
                        let participant = match self.participants.find_participant(&message.from) {
                            Some(participant) => participant,
                            None => {
                                tracing::warn!(
                                    participant = %message.from,
                                    "received message from unknown participant in running state"
                                );
                                continue;
                            }
                        };
                        protocol.message(participant, message.data)
                    }
                    None => {
                        // Store the message until we are ready to process it
                        leftover_messages.push(message)
                    }
                }
            }
            if !leftover_messages.is_empty() {
                tracing::warn!(
                    msg_count = leftover_messages.len(),
                    "unable to process messages, storing for future"
                );
                queue.extend(leftover_messages);
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

/// A signed message that can be encrypted. Note that the message's signature is included
/// in the encrypted message to avoid from it being tampered with without first decrypting.
#[derive(Serialize, Deserialize)]
pub struct SignedMessage<T> {
    /// The message with all it's related info.
    pub msg: T,
    /// The signature used to verify the authenticity of the encrypted message.
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: AccountId,
}

impl<T> SignedMessage<T> {
    pub const ASSOCIATED_DATA: &'static [u8] = b"";
}

impl<T> SignedMessage<T>
where
    T: Serialize,
{
    pub fn encrypt(
        msg: T,
        from: &AccountId,
        sign_sk: &near_crypto::SecretKey,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, CryptographicError> {
        let msg = serde_json::to_vec(&msg)?;
        let sig = sign_sk.sign(&msg);
        let msg = SignedMessage {
            msg,
            sig,
            from: from.clone(),
        };
        let msg = serde_json::to_vec(&msg)?;
        let ciphered = cipher_pk
            .encrypt(&msg, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|e| CryptographicError::Encryption(e.to_string()))?;
        Ok(ciphered)
    }
}

impl<T> SignedMessage<T>
where
    T: for<'a> Deserialize<'a>,
{
    pub async fn decrypt(
        cipher_sk: &hpke::SecretKey,
        protocol_state: &Arc<RwLock<NodeState>>,
        encrypted: Ciphered,
    ) -> Result<T, CryptographicError> {
        let message = cipher_sk
            .decrypt(&encrypted, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|err| CryptographicError::Encryption(err.to_string()))?;
        let SignedMessage::<Vec<u8>> { msg, sig, from } = serde_json::from_slice(&message)?;
        let sign_pk = match protocol_state.read().await.find_participant_info(&from) {
            Some(info) => info.sign_pk.clone(),
            None => {
                return Err(CryptographicError::Encryption(
                    "unknown participant".to_string(),
                ));
            }
        };
        if !sig.verify(&msg, &sign_pk) {
            return Err(CryptographicError::Encryption(
                "invalid signature while verifying authenticity of encrypted ".to_string(),
            ));
        }

        Ok(serde_json::from_slice(&msg)?)
    }
}

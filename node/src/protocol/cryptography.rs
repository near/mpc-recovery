use std::sync::PoisonError;

use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use crate::http_client::SendError;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MpcMessage;
use crate::storage::{SecretNodeStorageBox, SecretStorageError};
use async_trait::async_trait;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use mpc_keys::hpke;
use near_crypto::InMemorySigner;
use near_primitives::types::AccountId;

#[async_trait::async_trait]
pub trait CryptographicCtx {
    async fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn cipher_pk(&self) -> &hpke::PublicKey;
    fn sign_sk(&self) -> &near_crypto::SecretKey;
    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox;
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("failed to send a message: {0}")]
    SendError(#[from] SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error("rpc error: {0}")]
    RpcError(#[from] near_fetch::Error),
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("more than one writing to state: {0}")]
    InvalidStateHandle(String),
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

impl<T> From<PoisonError<T>> for CryptographicError {
    fn from(_: PoisonError<T>) -> Self {
        let typename = std::any::type_name::<T>();
        Self::SyncError(format!("PoisonError: {typename}"))
    }
}

#[async_trait]
pub trait CryptographicProtocol {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError>;
}

#[async_trait]
impl CryptographicProtocol for GeneratingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        mut ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        tracing::info!("generating: progressing key generation");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh keygen protocol");
                    }
                    return Err(err)?;
                }
            };
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("generating: waiting");
                    if let Err(err) = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
                        .await
                    {
                        tracing::warn!(?err, participants = ?self.participants, "generating(wait): failed to send encrypted message");
                    }

                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(m) => {
                    tracing::debug!("generating: sending a message to many participants");
                    let mut messages = self.messages.write().await;
                    for (p, info) in self.participants.iter() {
                        if p == &ctx.me().await {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        messages.push(
                            info.clone(),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me().await,
                                data: m.clone(),
                            }),
                        );
                    }
                }
                Action::SendPrivate(to, m) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    let info = self.fetch_participant(&to)?;
                    self.messages.write().await.push(
                        info.clone(),
                        MpcMessage::Generating(GeneratingMessage {
                            from: ctx.me().await,
                            data: m.clone(),
                        }),
                    );
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "generating: successfully completed key generation"
                    );
                    ctx.secret_storage()
                        .store(&PersistentNodeData {
                            epoch: 0,
                            private_share: r.private_share,
                            public_key: r.public_key,
                        })
                        .await?;
                    // Send any leftover messages
                    if let Err(err) = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
                        .await
                    {
                        tracing::warn!(?err, participants = ?self.participants, "generating(return): failed to send encrypted message");
                    }
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: 0,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                        messages: self.messages,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for WaitingForConsensusState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        if let Err(err) = self
            .messages
            .write()
            .await
            .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
            .await
        {
            tracing::warn!(?err, participants = ?self.participants, "waitingForConsensus: failed to send encrypted message");
        }

        // Wait for ConsensusProtocol step to advance state
        Ok(NodeState::WaitingForConsensus(self))
    }
}

#[async_trait]
impl CryptographicProtocol for ResharingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        tracing::info!("progressing key reshare");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh reshare protocol");
                    }
                    return Err(err)?;
                }
            };
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("resharing: waiting");
                    if let Err(err) = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
                        .await
                    {
                        tracing::warn!(?err, new = ?self.new_participants, old = ?self.old_participants, "resharing(wait): failed to send encrypted message");
                    }

                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(m) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    let mut messages = self.messages.write().await;
                    for (p, info) in self.new_participants.clone() {
                        if p == ctx.me().await {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        messages.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me().await,
                                data: m.clone(),
                            }),
                        )
                    }
                }
                Action::SendPrivate(to, m) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    match self.new_participants.get(&to) {
                        Some(info) => self.messages.write().await.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me().await,
                                data: m.clone(),
                            }),
                        ),
                        None => return Err(CryptographicError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("resharing: successfully completed key reshare");

                    // Send any leftover messages.
                    if let Err(err) = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
                        .await
                    {
                        tracing::warn!(?err, new = ?self.new_participants, old = ?self.old_participants, "resharing(return): failed to send encrypted message");
                    }

                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: self.old_epoch + 1,
                        participants: self.new_participants,
                        threshold: self.threshold,
                        private_share,
                        public_key: self.public_key,
                        messages: self.messages,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for RunningState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        let mut messages = self.messages.write().await;
        // Try sending any leftover messages donated to RunningState.
        if let Err(err) = messages
            .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
            .await
        {
            tracing::warn!(?err, participants = ?self.participants, "running(pre): failed to send encrypted message");
        }

        let mut triple_manager = self.triple_manager.write().await;
        if triple_manager.my_len() < 2 {
            triple_manager.generate()?;
        }
        for (p, msg) in triple_manager.poke()? {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Triple(msg));
        }

        let mut presignature_manager = self.presignature_manager.write().await;
        if presignature_manager.my_len() < 2 {
            // To ensure there is no contention between different nodes we are only using triples
            // that we proposed. This way in a non-BFT environment we are guaranteed to never try
            // to use the same triple as any other node.
            if let Some((triple0, triple1)) = triple_manager.take_two_mine() {
                presignature_manager.generate(
                    triple0,
                    triple1,
                    &self.public_key,
                    &self.private_share,
                )?;
            } else {
                tracing::debug!(
                    "running(pre): we don't have enough triples to generate a presignature"
                );
            }
        }
        drop(triple_manager);
        for (p, msg) in presignature_manager.poke()? {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Presignature(msg));
        }

        let mut sign_queue = self.sign_queue.write().await;
        let mut signature_manager = self.signature_manager.write().await;
        sign_queue.organize(&self, ctx.me().await);
        let my_requests = sign_queue.my_requests(ctx.me().await);
        while presignature_manager.my_len() > 0 {
            let Some((receipt_id, _)) = my_requests.iter().next() else {
                break;
            };
            let Some(presignature) = presignature_manager.take_mine() else {
                break;
            };
            let receipt_id = *receipt_id;
            let my_request = my_requests.remove(&receipt_id).unwrap();
            signature_manager.generate(
                receipt_id,
                presignature,
                self.public_key,
                my_request.msg_hash,
                my_request.epsilon,
                my_request.delta,
            )?;
        }
        drop(sign_queue);
        drop(presignature_manager);
        for (p, msg) in signature_manager.poke()? {
            let info = self.participants.get(&p).unwrap();
            messages.push(info.clone(), MpcMessage::Signature(msg));
        }
        signature_manager
            .publish(ctx.rpc_client(), ctx.signer(), ctx.mpc_contract_id())
            .await?;
        drop(signature_manager);
        if let Err(err) = messages
            .send_encrypted(ctx.me().await, ctx.sign_sk(), ctx.http_client())
            .await
        {
            tracing::warn!(?err, participants = ?self.participants, "running(post): failed to send encrypted message");
        }
        drop(messages);

        Ok(NodeState::Running(self))
    }
}

#[async_trait]
impl CryptographicProtocol for NodeState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        match self {
            NodeState::Generating(state) => state.progress(ctx).await,
            NodeState::Resharing(state) => state.progress(ctx).await,
            NodeState::Running(state) => state.progress(ctx).await,
            NodeState::WaitingForConsensus(state) => state.progress(ctx).await,
            _ => Ok(self),
        }
    }
}

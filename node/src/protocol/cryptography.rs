use std::sync::PoisonError;

use super::state::{GeneratingState, NodeState, ResharingState, RunningState};
use super::Config;
use crate::gcp::error::SecretStorageError;
use crate::http_client::SendError;
use crate::mesh::Mesh;
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::state::{PersistentNodeData, WaitingForConsensusState};
use crate::protocol::MpcMessage;
use crate::storage::secret_storage::SecretNodeStorageBox;
use async_trait::async_trait;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use k256::elliptic_curve::group::GroupEncoding;
use near_crypto::InMemorySigner;
use near_primitives::types::AccountId;

#[async_trait::async_trait]
pub trait CryptographicCtx {
    async fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox;
    fn cfg(&self) -> &Config;

    /// Active participants is the active participants at the beginning of each protocol loop.
    fn mesh(&self) -> &Mesh;
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
        tracing::info!(active = ?ctx.mesh().active_participants().keys_vec(), "generating: progressing key generation");
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
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.http_client(),
                            ctx.mesh().active_participants(),
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?ctx.mesh().active_participants().keys_vec(),
                            "generating(wait): failed to send encrypted message; {failures:?}"
                        );
                    }

                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("generating: sending a message to many participants");
                    let mut messages = self.messages.write().await;
                    for (p, info) in ctx.mesh().active_participants().iter() {
                        if p == &ctx.me().await {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        messages.push(
                            info.clone(),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me().await,
                                data: data.clone(),
                            }),
                        );
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    let info = self.fetch_participant(&to)?;
                    self.messages.write().await.push(
                        info.clone(),
                        MpcMessage::Generating(GeneratingMessage {
                            from: ctx.me().await,
                            data,
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
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.http_client(),
                            ctx.mesh().active_participants(),
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?ctx.mesh().active_participants().keys_vec(),
                            "generating(return): failed to send encrypted message; {failures:?}"
                        );
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
        tracing::debug!("Node state before progress: WaitingForConsensusState");
        let failures = self
            .messages
            .write()
            .await
            .send_encrypted(
                ctx.me().await,
                &ctx.cfg().network_cfg.sign_sk,
                ctx.http_client(),
                ctx.mesh().active_participants(),
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?ctx.mesh().active_participants().keys_vec(),
                "waitingForConsensus: failed to send encrypted message; {failures:?}"
            );
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
        tracing::debug!("Node state before progress: ResharingState");
        // TODO: we are not using active potential participants here, but we should in the future.
        // Currently resharing protocol does not timeout and restart with new set of participants.
        // So if it picks up a participant that is not active, it will never be able to send a message to it.
        let active = ctx
            .mesh()
            .active_participants()
            .and(&ctx.mesh().potential_participants().await);
        tracing::info!(active = ?active.keys().collect::<Vec<_>>(), "progressing key reshare");
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
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.http_client(),
                            &active,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(wait): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    let me = ctx.me().await;
                    let mut messages = self.messages.write().await;
                    for (p, info) in self.new_participants.iter() {
                        if p == &me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        messages.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: me,
                                data: data.clone(),
                            }),
                        )
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    match self.new_participants.get(&to) {
                        Some(info) => self.messages.write().await.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me().await,
                                data,
                            }),
                        ),
                        None => return Err(CryptographicError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("resharing: successfully completed key reshare");

                    // Send any leftover messages.
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.http_client(),
                            &active,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(return): failed to send encrypted message; {failures:?}",
                        );
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
        tracing::debug!("Node state before progress: RunningState");
        let active = ctx.mesh().active_participants();
        if active.len() < self.threshold {
            tracing::info!(
                active = ?active.keys_vec(),
                "running: not enough participants to progress"
            );
            return Ok(NodeState::Running(self));
        }

        let mut messages = self.messages.write().await;
        let mut triple_manager = self.triple_manager.write().await;
        let my_account_id = triple_manager.my_account_id.clone();
        crate::metrics::MESSAGE_QUEUE_SIZE
            .with_label_values(&[&my_account_id])
            .set(messages.len() as i64);
        triple_manager.stockpile(active)?;
        for (p, msg) in triple_manager.poke().await? {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Triple(msg));
        }

        crate::metrics::NUM_TRIPLES_MINE
            .with_label_values(&[&my_account_id])
            .set(triple_manager.mine.len() as i64);
        crate::metrics::NUM_TRIPLES_TOTAL
            .with_label_values(&[&my_account_id])
            .set(triple_manager.triples.len() as i64);
        crate::metrics::NUM_TRIPLE_GENERATORS_INTRODUCED
            .with_label_values(&[&my_account_id])
            .set(triple_manager.introduced.len() as i64);
        crate::metrics::NUM_TRIPLE_GENERATORS_TOTAL
            .with_label_values(&[&my_account_id])
            .set(triple_manager.ongoing.len() as i64);

        let mut presignature_manager = self.presignature_manager.write().await;
        presignature_manager
            .stockpile(
                active,
                &self.public_key,
                &self.private_share,
                &mut triple_manager,
            )
            .await?;
        drop(triple_manager);
        for (p, msg) in presignature_manager.poke()? {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Presignature(msg));
        }

        crate::metrics::NUM_PRESIGNATURES_MINE
            .with_label_values(&[&my_account_id])
            .set(presignature_manager.my_len() as i64);
        crate::metrics::NUM_PRESIGNATURES_TOTAL
            .with_label_values(&[&my_account_id])
            .set(presignature_manager.len() as i64);
        crate::metrics::NUM_PRESIGNATURE_GENERATORS_TOTAL
            .with_label_values(&[&my_account_id])
            .set(presignature_manager.potential_len() as i64 - presignature_manager.len() as i64);

        let mut sign_queue = self.sign_queue.write().await;
        crate::metrics::SIGN_QUEUE_SIZE
            .with_label_values(&[&my_account_id])
            .set(sign_queue.len() as i64);
        sign_queue.organize(self.threshold, active, ctx.me().await, &my_account_id);
        let my_requests = sign_queue.my_requests(ctx.me().await);
        crate::metrics::SIGN_QUEUE_MINE_SIZE
            .with_label_values(&[&my_account_id])
            .set(my_requests.len() as i64);

        let mut signature_manager = self.signature_manager.write().await;
        signature_manager.handle_requests(
            self.threshold,
            active,
            my_requests,
            &mut presignature_manager,
        )?;
        drop(sign_queue);
        drop(presignature_manager);

        for (p, msg) in signature_manager.poke() {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Signature(msg));
        }
        signature_manager
            .publish(
                ctx.rpc_client(),
                ctx.signer(),
                ctx.mpc_contract_id(),
                &my_account_id,
            )
            .await?;
        drop(signature_manager);
        let failures = messages
            .send_encrypted(
                ctx.me().await,
                &ctx.cfg().network_cfg.sign_sk,
                ctx.http_client(),
                active,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?active.keys_vec(),
                "running: failed to send encrypted message; {failures:?}"
            );
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
            _ => {
                tracing::debug!("Node state before progress: Starting or Started Or Joining");
                Ok(self)
            },
        }
    }
}

use super::state::{GeneratingState, NodeState, ResharingState};
use crate::http_client::{self, SendError};
use crate::protocol::message::{GeneratingMessage, ResharingMessage};
use crate::protocol::state::WaitingForConsensusState;
use crate::protocol::MpcMessage;
use async_trait::async_trait;
use cait_sith::protocol::{Action, Participant};
use k256::elliptic_curve::group::GroupEncoding;

pub trait CryptographicCtx {
    fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("failed to send a message: {0}")]
    SendError(#[from] SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
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
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        tracing::info!("progressing key generation");
        loop {
            let action = self.protocol.poke().unwrap();
            match action {
                Action::Wait => {
                    tracing::debug!("waiting");
                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(m) => {
                    tracing::debug!("sending a message to many participants");
                    for (p, url) in &self.participants {
                        if p == &ctx.me() {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        http_client::message(
                            ctx.http_client(),
                            url.clone(),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me(),
                                data: m.clone(),
                            }),
                        )
                        .await?;
                    }
                }
                Action::SendPrivate(to, m) => {
                    tracing::debug!("sending a private message to {to:?}");
                    match self.participants.get(&to) {
                        Some(url) => {
                            http_client::message(
                                ctx.http_client(),
                                url.clone(),
                                MpcMessage::Generating(GeneratingMessage {
                                    from: ctx.me(),
                                    data: m.clone(),
                                }),
                            )
                            .await?
                        }
                        None => {
                            return Err(CryptographicError::UnknownParticipant(to));
                        }
                    }
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "successfully completed key generation"
                    );
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: 0,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl CryptographicProtocol for ResharingState {
    async fn progress<C: CryptographicCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState, CryptographicError> {
        tracing::info!("progressing key reshare");
        loop {
            let action = self.protocol.poke().unwrap();
            match action {
                Action::Wait => {
                    tracing::debug!("waiting");
                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(m) => {
                    tracing::debug!("sending a message to all participants");
                    for (p, url) in &self.new_participants {
                        if p == &ctx.me() {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        http_client::message(
                            ctx.http_client(),
                            url.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me(),
                                data: m.clone(),
                            }),
                        )
                        .await?;
                    }
                }
                Action::SendPrivate(to, m) => {
                    tracing::debug!("sending a private message to {to:?}");
                    match self.new_participants.get(&to) {
                        Some(url) => {
                            http_client::message(
                                ctx.http_client(),
                                url.clone(),
                                MpcMessage::Resharing(ResharingMessage {
                                    epoch: self.old_epoch,
                                    from: ctx.me(),
                                    data: m.clone(),
                                }),
                            )
                            .await?;
                        }
                        None => return Err(CryptographicError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("successfully completed key reshare");
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: self.old_epoch + 1,
                        participants: self.new_participants,
                        threshold: self.threshold,
                        private_share,
                        public_key: self.public_key,
                    }));
                }
            }
        }
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
            _ => Ok(self),
        }
    }
}

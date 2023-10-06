use super::state::{GeneratingState, ProtocolState, ResharingState};
use crate::http_client::{self, SendError};
use crate::protocol::message_handler::{GeneratingMessage, ResharingMessage};
use crate::protocol::state::WaitingForConsensusState;
use crate::protocol::MpcMessage;
use async_trait::async_trait;
use cait_sith::protocol::{Action, Participant};
use k256::elliptic_curve::group::GroupEncoding;

pub trait ProgressCtx {
    fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
}

#[derive(thiserror::Error, Debug)]
pub enum ProgressError {
    #[error("failed to send a message: {0}")]
    SendError(#[from] SendError),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
}

#[async_trait]
pub trait Progress {
    async fn progress<C: ProgressCtx + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<ProtocolState, ProgressError>;
}

#[async_trait]
impl Progress for GeneratingState {
    async fn progress<C: ProgressCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<ProtocolState, ProgressError> {
        tracing::info!("progressing key generation");
        loop {
            let action = self.protocol.poke().unwrap();
            match action {
                Action::Wait => {
                    tracing::debug!("waiting");
                    return Ok(ProtocolState::Generating(self));
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
                            return Err(ProgressError::UnknownParticipant(to));
                        }
                    }
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "successfully completed key generation"
                    );
                    return Ok(ProtocolState::WaitingForConsensus(
                        WaitingForConsensusState {
                            epoch: 0,
                            participants: self.participants,
                            threshold: self.threshold,
                            private_share: r.private_share,
                            public_key: r.public_key,
                        },
                    ));
                }
            }
        }
    }
}

#[async_trait]
impl Progress for ResharingState {
    async fn progress<C: ProgressCtx + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<ProtocolState, ProgressError> {
        tracing::info!("progressing key reshare");
        loop {
            let action = self.protocol.poke().unwrap();
            match action {
                Action::Wait => {
                    tracing::debug!("waiting");
                    return Ok(ProtocolState::Resharing(self));
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
                                    from: ctx.me(),
                                    data: m.clone(),
                                }),
                            )
                            .await?;
                        }
                        None => return Err(ProgressError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("successfully completed key reshare");
                    return Ok(ProtocolState::WaitingForConsensus(
                        WaitingForConsensusState {
                            epoch: self.old_epoch + 1,
                            participants: self.new_participants,
                            threshold: self.threshold,
                            private_share,
                            public_key: self.public_key,
                        },
                    ));
                }
            }
        }
    }
}

#[async_trait]
impl Progress for ProtocolState {
    async fn progress<C: ProgressCtx + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<ProtocolState, ProgressError> {
        match self {
            ProtocolState::Generating(state) => state.progress(ctx).await,
            ProtocolState::Resharing(state) => state.progress(ctx).await,
            _ => Ok(self),
        }
    }
}

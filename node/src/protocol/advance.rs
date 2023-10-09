use std::collections::HashSet;

use super::contract::{ProtocolContractState, ResharingContractState};
use super::state::{
    JoiningState, PersistentNodeData, ProtocolState, RunningState, StartedState,
    WaitingForConsensusState,
};
use crate::protocol::state::{GeneratingState, ResharingState};
use crate::types::PrivateKeyShare;
use crate::util::AffinePointExt;
use crate::{http_client, rpc_client};
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, Participant};
use k256::Secp256k1;
use mpc_contract::ParticipantInfo;
use near_crypto::InMemorySigner;
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::types::AccountId;
use url::Url;

pub trait AdvanceCtx {
    fn me(&self) -> Participant;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn my_address(&self) -> &Url;
}

#[derive(thiserror::Error, Debug)]
pub enum AdvanceError {
    #[error("contract state has been rolled back")]
    ContractStateRollback,
    #[error("contract epoch has been rolled back")]
    EpochRollback,
    #[error("mismatched public key between contract state and local state")]
    MismatchedPublicKey,
    #[error("mismatched threshold between contract state and local state")]
    MismatchedThreshold,
    #[error("mismatched participant set between contract state and local state")]
    MismatchedParticipants,
    #[error("this node has been unexpectedly kicked from the participant set")]
    HasBeenKicked,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
}

#[async_trait]
pub trait Advance {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError>;
}

#[async_trait]
impl Advance for StartedState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match self.0 {
            Some(PersistentNodeData {
                epoch,
                private_share,
                public_key,
            }) => match contract_state {
                ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
                ProtocolContractState::Running(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(AdvanceError::MismatchedPublicKey);
                    }
                    if contract_state.epoch < epoch {
                        return Err(AdvanceError::EpochRollback);
                    } else if contract_state.epoch > epoch {
                        tracing::warn!(
                            "out current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            epoch,
                            contract_state.epoch
                        );
                        return Ok(ProtocolState::Joining(JoiningState { public_key }));
                    }
                    if contract_state.participants.contains_key(&ctx.me()) {
                        tracing::info!(
                            "contract state is running and we are already a participant"
                        );
                        Ok(ProtocolState::Running(RunningState {
                            epoch,
                            participants: contract_state.participants,
                            threshold: contract_state.threshold,
                            private_share,
                            public_key,
                        }))
                    } else {
                        return Ok(ProtocolState::Joining(JoiningState { public_key }));
                    }
                }
                ProtocolContractState::Resharing(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(AdvanceError::MismatchedPublicKey);
                    }
                    if contract_state.old_epoch < epoch {
                        return Err(AdvanceError::EpochRollback);
                    } else if contract_state.old_epoch > epoch {
                        tracing::warn!(
                            "out current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            epoch,
                            contract_state.old_epoch
                        );
                        return Ok(ProtocolState::Joining(JoiningState { public_key }));
                    }
                    tracing::info!("contract state is resharing with us, joining as a participant");
                    start_resharing(Some(private_share), ctx, contract_state)
                }
            },
            None => match contract_state {
                ProtocolContractState::Initialized(contract_state) => {
                    if contract_state.participants.contains_key(&ctx.me()) {
                        tracing::info!("starting key generation as a part of the participant set");
                        let participants = contract_state.participants;
                        let protocol = cait_sith::keygen(
                            &participants.keys().cloned().collect::<Vec<_>>(),
                            ctx.me(),
                            contract_state.threshold,
                        )?;
                        Ok(ProtocolState::Generating(GeneratingState {
                            participants,
                            threshold: contract_state.threshold,
                            protocol: Box::new(protocol),
                        }))
                    } else {
                        tracing::info!("we are not a part of the initial participant set, waiting for key generation to complete");
                        Ok(ProtocolState::Started(self))
                    }
                }
                ProtocolContractState::Running(contract_state) => {
                    Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }))
                }
                ProtocolContractState::Resharing(contract_state) => {
                    Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }))
                }
            },
        }
    }
}

#[async_trait]
impl Advance for GeneratingState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        _ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => {
                tracing::debug!("continuing generation, contract state has not been finalized yet");
                Ok(ProtocolState::Generating(self))
            }
            ProtocolContractState::Running(contract_state) => {
                if contract_state.epoch > 0 {
                    tracing::warn!("contract has already changed epochs, trying to rejoin as a new participant");
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::info!("contract state has finished key generation, trying to catch up");
                if self.participants != contract_state.participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if self.threshold != contract_state.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                Ok(ProtocolState::Generating(self))
            }
            ProtocolContractState::Resharing(contract_state) => {
                if contract_state.old_epoch > 0 {
                    tracing::warn!("contract has already changed epochs, trying to rejoin as a new participant");
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::warn!("contract state is resharing without us, trying to catch up");
                if self.participants != contract_state.old_participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if self.threshold != contract_state.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                Ok(ProtocolState::Generating(self))
            }
        }
    }
}

#[async_trait]
impl Advance for WaitingForConsensusState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(contract_state) => {
                tracing::debug!("waiting for consensus, contract state has not been finalized yet");
                let public_key = self.public_key.into_near_public_key();
                let has_voted = contract_state
                    .pk_votes
                    .get(&public_key)
                    .map(|ps| ps.contains(&ctx.me()))
                    .unwrap_or_default();
                if !has_voted {
                    tracing::info!("we haven't voted yet, voting for the generated public key");
                    rpc_client::vote_for_public_key(
                        ctx.rpc_client(),
                        ctx.signer(),
                        ctx.mpc_contract_id(),
                        &public_key,
                    )
                    .await
                    .unwrap();
                }
                Ok(ProtocolState::WaitingForConsensus(self))
            }
            ProtocolContractState::Running(contract_state) => {
                if contract_state.epoch < self.epoch {
                    return Err(AdvanceError::EpochRollback);
                } else if contract_state.epoch > self.epoch {
                    tracing::warn!(
                        "out current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                        self.epoch,
                        contract_state.epoch
                    );
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::info!("contract state has reached consensus");
                if contract_state.participants != self.participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if contract_state.threshold != self.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                Ok(ProtocolState::Running(RunningState {
                    epoch: self.epoch,
                    participants: self.participants,
                    threshold: self.threshold,
                    private_share: self.private_share,
                    public_key: self.public_key,
                }))
            }
            ProtocolContractState::Resharing(contract_state) => {
                if contract_state.old_epoch + 1 < self.epoch {
                    return Err(AdvanceError::EpochRollback);
                } else if contract_state.old_epoch > self.epoch {
                    tracing::warn!(
                        "out current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                        self.epoch,
                        contract_state.old_epoch
                    );
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                } else if contract_state.old_epoch + 1 == self.epoch {
                    tracing::debug!(
                        "waiting for resharing consensus, contract state has not been finalized yet"
                    );
                    let has_voted = contract_state.finished_votes.contains(&ctx.me());
                    if !has_voted && contract_state.old_participants.contains_key(&ctx.me()) {
                        tracing::info!(
                            epoch = self.epoch,
                            "we haven't voted yet, voting for resharing to complete"
                        );
                        rpc_client::vote_reshared(
                            ctx.rpc_client(),
                            ctx.signer(),
                            ctx.mpc_contract_id(),
                            self.epoch,
                        )
                        .await
                        .unwrap();
                    }
                    return Ok(ProtocolState::WaitingForConsensus(self));
                }
                tracing::info!("contract state is resharing, joining");
                if contract_state.old_participants != self.participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if contract_state.threshold != self.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                start_resharing(Some(self.private_share), ctx, contract_state)
            }
        }
    }
}

#[async_trait]
impl Advance for RunningState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
            ProtocolContractState::Running(contract_state) => {
                if contract_state.epoch < self.epoch {
                    return Err(AdvanceError::EpochRollback);
                } else if contract_state.epoch > self.epoch {
                    tracing::warn!(
                        "out current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                        self.epoch,
                        contract_state.epoch
                    );
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::debug!("continuing to run as normal");
                if contract_state.participants != self.participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if contract_state.threshold != self.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                Ok(ProtocolState::Running(self))
            }
            ProtocolContractState::Resharing(contract_state) => {
                if contract_state.old_epoch < self.epoch {
                    return Err(AdvanceError::EpochRollback);
                } else if contract_state.old_epoch > self.epoch {
                    tracing::warn!(
                        "out current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                        self.epoch,
                        contract_state.old_epoch
                    );
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::info!("contract is resharing");
                if !contract_state.old_participants.contains_key(&ctx.me())
                    || !contract_state.new_participants.contains_key(&ctx.me())
                {
                    return Err(AdvanceError::HasBeenKicked);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                start_resharing(Some(self.private_share), ctx, contract_state)
            }
        }
    }
}

#[async_trait]
impl Advance for ResharingState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        _ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
            ProtocolContractState::Running(contract_state) => {
                if contract_state.epoch <= self.old_epoch {
                    return Err(AdvanceError::EpochRollback);
                } else if contract_state.epoch > self.old_epoch + 1 {
                    tracing::warn!(
                        "expected epoch {} while contract state's is {}, trying to rejoin as a new participant",
                        self.old_epoch + 1,
                        contract_state.epoch
                    );
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::info!("contract state has finished resharing, trying to catch up");
                if contract_state.participants != self.new_participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if contract_state.threshold != self.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                Ok(ProtocolState::Resharing(self))
            }
            ProtocolContractState::Resharing(contract_state) => {
                if contract_state.old_epoch < self.old_epoch {
                    return Err(AdvanceError::EpochRollback);
                } else if contract_state.old_epoch > self.old_epoch {
                    tracing::warn!(
                        "expected resharing from epoch {} while contract is resharing from {}, trying to rejoin as a new participant",
                        self.old_epoch,
                        contract_state.old_epoch
                    );
                    return Ok(ProtocolState::Joining(JoiningState {
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::debug!("continue to reshare as normal");
                if contract_state.old_participants != self.old_participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if contract_state.new_participants != self.new_participants {
                    return Err(AdvanceError::MismatchedParticipants);
                }
                if contract_state.threshold != self.threshold {
                    return Err(AdvanceError::MismatchedThreshold);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                Ok(ProtocolState::Resharing(self))
            }
        }
    }
}

#[async_trait]
impl Advance for JoiningState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
            ProtocolContractState::Running(contract_state) => {
                if contract_state.candidates.contains_key(&ctx.me()) {
                    let voted = contract_state
                        .join_votes
                        .get(&ctx.me())
                        .cloned()
                        .unwrap_or_else(|| HashSet::new());
                    tracing::info!(
                        already_voted = voted.len(),
                        votes_to_go = contract_state.threshold - voted.len(),
                        "trying to get participants to vote for us"
                    );
                    for (p, url) in contract_state.participants {
                        if voted.contains(&p) {
                            continue;
                        }
                        http_client::join(ctx.http_client(), url, &ctx.me())
                            .await
                            .unwrap()
                    }
                    Ok(ProtocolState::Joining(self))
                } else {
                    tracing::info!("sending a transaction to join the participant set");
                    let args = serde_json::json!({
                        "participant_id": ctx.me(),
                        "url": ctx.my_address(),
                    });
                    ctx.rpc_client()
                        .send_tx(
                            ctx.signer(),
                            ctx.mpc_contract_id(),
                            vec![Action::FunctionCall(FunctionCallAction {
                                method_name: "join".to_string(),
                                args: serde_json::to_vec(&args).unwrap(),
                                gas: 300_000_000_000_000,
                                deposit: 0,
                            })],
                        )
                        .await
                        .unwrap();
                    Ok(ProtocolState::Joining(self))
                }
            }
            ProtocolContractState::Resharing(contract_state) => {
                if contract_state.new_participants.contains_key(&ctx.me()) {
                    tracing::info!("joining as a new participant");
                    start_resharing(None, ctx, contract_state)
                } else {
                    tracing::debug!("network is resharing without us, waiting for them to finish");
                    Ok(ProtocolState::Joining(self))
                }
            }
        }
    }
}

#[async_trait]
impl Advance for ProtocolState {
    async fn advance<C: AdvanceCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match self {
            ProtocolState::Starting => {
                // TODO: Load from persistent storage
                Ok(ProtocolState::Started(StartedState(None)))
            }
            ProtocolState::Started(state) => state.advance(ctx, contract_state).await,
            ProtocolState::Generating(state) => state.advance(ctx, contract_state).await,
            ProtocolState::WaitingForConsensus(state) => state.advance(ctx, contract_state).await,
            ProtocolState::Running(state) => state.advance(ctx, contract_state).await,
            ProtocolState::Resharing(state) => state.advance(ctx, contract_state).await,
            ProtocolState::Joining(state) => state.advance(ctx, contract_state).await,
        }
    }
}

fn start_resharing<C: AdvanceCtx>(
    private_share: Option<PrivateKeyShare>,
    ctx: C,
    contract_state: ResharingContractState,
) -> Result<ProtocolState, AdvanceError> {
    let protocol = cait_sith::reshare::<Secp256k1>(
        &contract_state
            .old_participants
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        contract_state.threshold,
        &contract_state
            .new_participants
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        contract_state.threshold,
        ctx.me(),
        private_share,
        contract_state.public_key,
    )?;
    Ok(ProtocolState::Resharing(ResharingState {
        old_epoch: contract_state.old_epoch,
        old_participants: contract_state.old_participants,
        new_participants: contract_state.new_participants,
        threshold: contract_state.threshold,
        public_key: contract_state.public_key,
        protocol: Box::new(protocol),
    }))
}

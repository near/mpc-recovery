use super::contract::ProtocolContractState;
use super::state::{ProtocolState, RunningState, StartedState, WaitingForConsensusState};
use crate::protocol::state::{GeneratingState, ResharingState};
use cait_sith::protocol::{InitializationError, Participant};
use k256::Secp256k1;

pub trait AdvanceCtx {
    fn me(&self) -> Participant;
}

#[derive(thiserror::Error, Debug)]
pub enum AdvanceError {
    #[error("contract state has been rolled back")]
    ContractStateRollback,
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

pub trait Advance {
    fn advance<C: AdvanceCtx>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError>;
}

impl Advance for StartedState {
    fn advance<C: AdvanceCtx>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match self.0 {
            Some((private_share, public_key)) => match contract_state {
                ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
                ProtocolContractState::Running(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(AdvanceError::MismatchedPublicKey);
                    }
                    if contract_state.participants.contains_key(&ctx.me()) {
                        tracing::info!(
                            "contract state is running and we are already a participant"
                        );
                        Ok(ProtocolState::Running(RunningState {
                            participants: contract_state.participants,
                            threshold: contract_state.threshold,
                            private_share,
                            public_key,
                        }))
                    } else {
                        todo!("initiate resharing")
                    }
                }
                ProtocolContractState::Resharing(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(AdvanceError::MismatchedPublicKey);
                    }
                    // TODO: Try to re-join during the resharing phase if still in the participant set
                    tracing::info!("contract state is resharing, we can't join yet");
                    Ok(ProtocolState::Started(self))
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
                ProtocolContractState::Running(_) => todo!("initiate resharing"),
                ProtocolContractState::Resharing(_) => {
                    // TODO: Try to re-join during the resharing phase if still in the participant set
                    tracing::info!("contract state is resharing, we can't join yet");
                    Ok(ProtocolState::Started(self))
                }
            },
        }
    }
}

impl Advance for GeneratingState {
    fn advance<C: AdvanceCtx>(
        self,
        _ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => {
                tracing::debug!("continuing generation, contract state has not been finalized yet");
                Ok(ProtocolState::Generating(self))
            }
            ProtocolContractState::Running(_) => {
                tracing::info!("contract state has finished key generation, trying to catch up");
                Ok(ProtocolState::Generating(self))
            }
            ProtocolContractState::Resharing(_) => {
                tracing::warn!("contract state is resharing without us, trying to catch up");
                Ok(ProtocolState::Generating(self))
            }
        }
    }
}

impl Advance for WaitingForConsensusState {
    fn advance<C: AdvanceCtx>(
        self,
        _ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => {
                tracing::debug!("waiting for consensus, contract state has not been finalized yet");
                Ok(ProtocolState::WaitingForConsensus(self))
            }
            ProtocolContractState::Running(contract_state) => {
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
                    participants: self.participants,
                    threshold: self.threshold,
                    private_share: self.private_share,
                    public_key: self.public_key,
                }))
            }
            ProtocolContractState::Resharing(_) => {
                // TODO: Try to re-join during the resharing phase if still in the participant set
                tracing::info!("contract state is resharing without us, restarting");
                Ok(ProtocolState::Started(StartedState(Some((
                    self.private_share,
                    self.public_key,
                )))))
            }
        }
    }
}

impl Advance for RunningState {
    fn advance<C: AdvanceCtx>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
            ProtocolContractState::Running(contract_state) => {
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
                tracing::info!("contract is resharing");
                if !contract_state.old_participants.contains_key(&ctx.me())
                    || !contract_state.new_participants.contains_key(&ctx.me())
                {
                    return Err(AdvanceError::HasBeenKicked);
                }
                if contract_state.public_key != self.public_key {
                    return Err(AdvanceError::MismatchedPublicKey);
                }
                let protocol = cait_sith::reshare::<Secp256k1>(
                    &contract_state
                        .old_participants
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    self.threshold,
                    &contract_state
                        .new_participants
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    self.threshold,
                    ctx.me(),
                    Some(self.private_share),
                    self.public_key,
                )?;
                Ok(ProtocolState::Resharing(ResharingState {
                    old_participants: contract_state.old_participants,
                    new_participants: contract_state.new_participants,
                    threshold: self.threshold,
                    public_key: self.public_key,
                    protocol: Box::new(protocol),
                }))
            }
        }
    }
}

impl Advance for ResharingState {
    fn advance<C: AdvanceCtx>(
        self,
        _ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match contract_state {
            ProtocolContractState::Initialized(_) => Err(AdvanceError::ContractStateRollback),
            ProtocolContractState::Running(contract_state) => {
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

impl Advance for ProtocolState {
    fn advance<C: AdvanceCtx>(
        self,
        ctx: C,
        contract_state: ProtocolContractState,
    ) -> Result<ProtocolState, AdvanceError> {
        match self {
            ProtocolState::Starting => {
                // TODO: Load from persistent storage
                Ok(ProtocolState::Started(StartedState(None)))
            }
            ProtocolState::Started(state) => state.advance(ctx, contract_state),
            ProtocolState::Generating(state) => state.advance(ctx, contract_state),
            ProtocolState::WaitingForConsensus(state) => state.advance(ctx, contract_state),
            ProtocolState::Running(state) => state.advance(ctx, contract_state),
            ProtocolState::Resharing(state) => state.advance(ctx, contract_state),
        }
    }
}

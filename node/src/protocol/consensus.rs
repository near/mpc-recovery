use super::contract::{ProtocolState, ResharingContractState};
use super::state::{
    JoiningState, NodeState, PersistentNodeData, RunningState, StartedState,
    WaitingForConsensusState,
};
use super::SignQueue;
use crate::protocol::presignature::PresignatureManager;
use crate::protocol::signature::SignatureManager;
use crate::protocol::state::{GeneratingState, ResharingState};
use crate::protocol::triple::TripleManager;
use crate::storage::{SecretNodeStorageBox, SecretStorageError};
use crate::types::{SecretKeyShare, KeygenProtocol};
use crate::util::AffinePointExt;
use crate::{http_client, rpc_client};
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, Participant};
use k256::Secp256k1;
use mpc_keys::hpke;
use near_crypto::InMemorySigner;
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::types::AccountId;
use std::cmp::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

pub trait ConsensusCtx {
    fn my_account_id(&self) -> &AccountId;
    fn http_client(&self) -> &reqwest::Client;
    fn rpc_client(&self) -> &near_fetch::Client;
    fn signer(&self) -> &InMemorySigner;
    fn mpc_contract_id(&self) -> &AccountId;
    fn my_address(&self) -> &Url;
    fn sign_queue(&self) -> Arc<RwLock<SignQueue>>;
    fn cipher_pk(&self) -> &hpke::PublicKey;
    fn sign_pk(&self) -> near_crypto::PublicKey;
    fn sign_sk(&self) -> &near_crypto::SecretKey;
    fn secret_storage(&self) -> &SecretNodeStorageBox;
}

#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
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
    #[error("secret storage error: {0}")]
    SecretStorageError(#[from] SecretStorageError),
}

#[async_trait]
pub trait ConsensusProtocol {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError>;
}

#[async_trait]
impl ConsensusProtocol for StartedState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match self.0 {
            Some(PersistentNodeData {
                epoch,
                private_share,
                public_key,
            }) => match contract_state {
                ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
                ProtocolState::Running(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    match contract_state.epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                "started(running): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                                epoch,
                                contract_state.epoch
                            );
                            Ok(NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key,
                            }))
                        }
                        Ordering::Less => Err(ConsensusError::EpochRollback),
                        Ordering::Equal => {
                            match contract_state
                                .participants
                                .find_participant(ctx.my_account_id())
                            {
                                Some(me) => {
                                    tracing::info!(
                                        "started: contract state is running and we are already a participant"
                                    );
                                    let participants_vec: Vec<Participant> =
                                        contract_state.participants.keys().cloned().collect();
                                    Ok(NodeState::Running(RunningState {
                                        epoch,
                                        participants: contract_state.participants,
                                        threshold: contract_state.threshold,
                                        private_share,
                                        public_key,
                                        sign_queue: ctx.sign_queue(),
                                        triple_manager: Arc::new(RwLock::new(TripleManager::new(
                                            participants_vec.clone(),
                                            me,
                                            contract_state.threshold,
                                            epoch,
                                        ))),
                                        presignature_manager: Arc::new(RwLock::new(
                                            PresignatureManager::new(
                                                participants_vec.clone(),
                                                me,
                                                contract_state.threshold,
                                                epoch,
                                            ),
                                        )),
                                        signature_manager: Arc::new(RwLock::new(
                                            SignatureManager::new(
                                                participants_vec,
                                                me,
                                                contract_state.public_key,
                                                epoch,
                                            ),
                                        )),
                                        messages: Default::default(),
                                    }))
                                }
                                None => Ok(NodeState::Joining(JoiningState {
                                    participants: contract_state.participants,
                                    public_key,
                                })),
                            }
                        }
                    }
                }
                ProtocolState::Resharing(contract_state) => {
                    if contract_state.public_key != public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    match contract_state.old_epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                "started(resharing): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                                epoch,
                                contract_state.old_epoch
                            );
                            Ok(NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key,
                            }))
                        }
                        Ordering::Less => Err(ConsensusError::EpochRollback),
                        Ordering::Equal => {
                            tracing::info!(
                                "started(resharing): contract state is resharing with us, joining as a participant"
                            );
                            start_resharing(Some(private_share), ctx, contract_state).await
                        }
                    }
                }
            },
            None => match contract_state {
                ProtocolState::Initializing(contract_state) => {
                    match contract_state
                        .participants
                        .find_participant(ctx.my_account_id())
                    {
                        Some(me) => {
                            tracing::info!(
                                "started(initializing): starting key generation as a part of the participant set"
                            );
                            let participants = contract_state.participants;
                            let protocol = KeygenProtocol::new(
                                &participants.keys().cloned().collect::<Vec<_>>(),
                                me,
                                contract_state.threshold,
                            )?;
                            Ok(NodeState::Generating(GeneratingState {
                                participants,
                                threshold: contract_state.threshold,
                                protocol,
                                messages: Default::default(),
                            }))
                        }
                        None => {
                            tracing::info!("started(initializing): we are not a part of the initial participant set, waiting for key generation to complete");
                            Ok(NodeState::Started(self))
                        }
                    }
                }
                ProtocolState::Running(contract_state) => Ok(NodeState::Joining(JoiningState {
                    participants: contract_state.participants,
                    public_key: contract_state.public_key,
                })),
                ProtocolState::Resharing(contract_state) => Ok(NodeState::Joining(JoiningState {
                    participants: contract_state.old_participants,
                    public_key: contract_state.public_key,
                })),
            },
        }
    }
}

#[async_trait]
impl ConsensusProtocol for GeneratingState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        _ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => {
                tracing::debug!("generating(initializing): continuing generation, contract state has not been finalized yet");
                Ok(NodeState::Generating(self))
            }
            ProtocolState::Running(contract_state) => {
                if contract_state.epoch > 0 {
                    tracing::warn!("generating(running): contract has already changed epochs, trying to rejoin as a new participant");
                    return Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::info!("generating(running): contract state has finished key generation, trying to catch up");
                if self.participants != contract_state.participants {
                    return Err(ConsensusError::MismatchedParticipants);
                }
                if self.threshold != contract_state.threshold {
                    return Err(ConsensusError::MismatchedThreshold);
                }
                Ok(NodeState::Generating(self))
            }
            ProtocolState::Resharing(contract_state) => {
                if contract_state.old_epoch > 0 {
                    tracing::warn!("generating(resharing): contract has already changed epochs, trying to rejoin as a new participant");
                    return Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.old_participants,
                        public_key: contract_state.public_key,
                    }));
                }
                tracing::warn!("generating(resharing): contract state is resharing without us, trying to catch up");
                if self.participants != contract_state.old_participants {
                    return Err(ConsensusError::MismatchedParticipants);
                }
                if self.threshold != contract_state.threshold {
                    return Err(ConsensusError::MismatchedThreshold);
                }
                Ok(NodeState::Generating(self))
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for WaitingForConsensusState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                tracing::debug!("waiting(initializing): waiting for consensus, contract state has not been finalized yet");
                let public_key = self.public_key.into_near_public_key();
                let has_voted = contract_state
                    .pk_votes
                    .get(&public_key)
                    .map(|ps| ps.contains(ctx.my_account_id()))
                    .unwrap_or_default();
                if !has_voted {
                    tracing::info!("waiting(initializing): we haven't voted yet, voting for the generated public key");
                    rpc_client::vote_for_public_key(
                        ctx.rpc_client(),
                        ctx.signer(),
                        ctx.mpc_contract_id(),
                        &public_key,
                    )
                    .await
                    .unwrap();
                }
                Ok(NodeState::WaitingForConsensus(self))
            }
            ProtocolState::Running(contract_state) => match contract_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                            "waiting(running): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.epoch
                        );
                    Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::info!("waiting(running): contract state has reached consensus");
                    if contract_state.participants != self.participants {
                        return Err(ConsensusError::MismatchedParticipants);
                    }
                    if contract_state.threshold != self.threshold {
                        return Err(ConsensusError::MismatchedThreshold);
                    }
                    if contract_state.public_key != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    let participants_vec: Vec<Participant> =
                        self.participants.keys().cloned().collect();

                    let me = contract_state
                        .participants
                        .find_participant(ctx.my_account_id())
                        .unwrap();

                    Ok(NodeState::Running(RunningState {
                        epoch: self.epoch,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: self.private_share,
                        public_key: self.public_key,
                        sign_queue: ctx.sign_queue(),
                        triple_manager: Arc::new(RwLock::new(TripleManager::new(
                            participants_vec.clone(),
                            me,
                            self.threshold,
                            self.epoch,
                        ))),
                        presignature_manager: Arc::new(RwLock::new(PresignatureManager::new(
                            participants_vec.clone(),
                            me,
                            self.threshold,
                            self.epoch,
                        ))),
                        signature_manager: Arc::new(RwLock::new(SignatureManager::new(
                            participants_vec,
                            me,
                            self.public_key,
                            self.epoch,
                        ))),
                        messages: self.messages,
                    }))
                }
            },
            ProtocolState::Resharing(contract_state) => {
                match (contract_state.old_epoch + 1).cmp(&self.epoch) {
                    Ordering::Greater if contract_state.old_epoch + 2 == self.epoch => {
                        tracing::info!("waiting(resharing): contract state is resharing, joining");
                        if contract_state.old_participants != self.participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.threshold != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        start_resharing(Some(self.private_share), ctx, contract_state).await
                    }
                    Ordering::Greater => {
                        tracing::warn!(
                            "waiting(resharing): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.old_epoch
                        );
                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::debug!(
                            "waiting(resharing): waiting for resharing consensus, contract state has not been finalized yet"
                        );
                        let has_voted = contract_state.finished_votes.contains(ctx.my_account_id());
                        match contract_state
                            .old_participants
                            .find_participant(ctx.my_account_id())
                        {
                            Some(_) => {
                                if !has_voted {
                                    tracing::info!(
                                        epoch = self.epoch,
                                        "waiting(resharing): we haven't voted yet, voting for resharing to complete"
                                    );
                                    rpc_client::vote_reshared(
                                        ctx.rpc_client(),
                                        ctx.signer(),
                                        ctx.mpc_contract_id(),
                                        self.epoch,
                                    )
                                    .await
                                    .unwrap();
                                } else {
                                    tracing::info!(
                                        epoch = self.epoch,
                                        "waiting(resharing): we have voted for resharing to complete"
                                    );
                                }
                            }
                            None => {
                                tracing::info!("waiting(resharing): we are not a part of the old participant set");
                            }
                        }
                        Ok(NodeState::WaitingForConsensus(self))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for RunningState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
            ProtocolState::Running(contract_state) => match contract_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                            "running(running): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.epoch
                        );
                    Ok(NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::debug!("running(running): continuing to run as normal");
                    if contract_state.participants != self.participants {
                        return Err(ConsensusError::MismatchedParticipants);
                    }
                    if contract_state.threshold != self.threshold {
                        return Err(ConsensusError::MismatchedThreshold);
                    }
                    if contract_state.public_key != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    Ok(NodeState::Running(self))
                }
            },
            ProtocolState::Resharing(contract_state) => {
                match contract_state.old_epoch.cmp(&self.epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "running(resharing): our current epoch is {} while contract state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            contract_state.old_epoch
                        );
                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!("running(resharing): contract is resharing");
                        let is_in_old_participant_set = contract_state
                            .old_participants
                            .contains_account_id(ctx.my_account_id());
                        let is_in_new_participant_set = contract_state
                            .new_participants
                            .contains_account_id(ctx.my_account_id());
                        if !is_in_old_participant_set || !is_in_new_participant_set {
                            return Err(ConsensusError::HasBeenKicked);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        start_resharing(Some(self.private_share), ctx, contract_state).await
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for ResharingState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        _ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
            ProtocolState::Running(contract_state) => {
                match contract_state.epoch.cmp(&(self.old_epoch + 1)) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "resharing(running): expected epoch {} while contract state's is {}, trying to rejoin as a new participant",
                            self.old_epoch + 1,
                            contract_state.epoch
                        );
                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!("resharing(running): contract state has finished resharing, trying to catch up");
                        if contract_state.participants != self.new_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.threshold != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        Ok(NodeState::Resharing(self))
                    }
                }
            }
            ProtocolState::Resharing(contract_state) => {
                match contract_state.old_epoch.cmp(&self.old_epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "resharing(resharing): expected resharing from epoch {} while contract is resharing from {}, trying to rejoin as a new participant",
                            self.old_epoch,
                            contract_state.old_epoch
                        );
                        Ok(NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::debug!("resharing(resharing): continue to reshare as normal");
                        if contract_state.old_participants != self.old_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.new_participants != self.new_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if contract_state.threshold != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if contract_state.public_key != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        Ok(NodeState::Resharing(self))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for JoiningState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match contract_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ContractStateRollback),
            ProtocolState::Running(contract_state) => {
                match contract_state
                    .candidates
                    .find_candidate(ctx.my_account_id())
                {
                    Some(candidate_info) => {
                        let voted = contract_state
                            .join_votes
                            .get(ctx.my_account_id())
                            .cloned()
                            .unwrap_or_default();
                        tracing::info!(
                            already_voted = voted.len(),
                            votes_to_go = contract_state.threshold - voted.len(),
                            "joining(running): trying to get participants to vote for us"
                        );
                        for (_, info) in contract_state.participants {
                            if voted.contains(&info.account_id) {
                                continue;
                            }
                            http_client::join(
                                ctx.http_client(),
                                info.url,
                                &candidate_info.account_id,
                            )
                            .await
                            .unwrap()
                        }
                        Ok(NodeState::Joining(self))
                    }
                    None => {
                        tracing::info!(
                            "joining(running): sending a transaction to join the participant set"
                        );
                        let args = serde_json::json!({
                            "url": ctx.my_address(),
                            "cipher_pk": ctx.cipher_pk().to_bytes(),
                            "sign_pk": ctx.sign_pk(),
                        });
                        ctx.rpc_client()
                            .send_tx(
                                ctx.signer(),
                                ctx.mpc_contract_id(),
                                vec![Action::FunctionCall(FunctionCallAction {
                                    method_name: "join".to_string(),
                                    args: args.to_string().into_bytes(),
                                    gas: 300_000_000_000_000,
                                    deposit: 0,
                                })],
                            )
                            .await
                            .unwrap();
                        Ok(NodeState::Joining(self))
                    }
                }
            }
            ProtocolState::Resharing(contract_state) => {
                if contract_state
                    .new_participants
                    .contains_account_id(ctx.my_account_id())
                {
                    tracing::info!("joining(resharing): joining as a new participant");
                    start_resharing(None, ctx, contract_state).await
                } else {
                    tracing::debug!("joining(resharing): network is resharing without us, waiting for them to finish");
                    Ok(NodeState::Joining(self))
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusProtocol for NodeState {
    async fn advance<C: ConsensusCtx + Send + Sync>(
        self,
        ctx: C,
        contract_state: ProtocolState,
    ) -> Result<NodeState, ConsensusError> {
        match self {
            NodeState::Starting => {
                let node_data = ctx.secret_storage().load().await?;
                Ok(NodeState::Started(StartedState(node_data)))
            }
            NodeState::Started(state) => state.advance(ctx, contract_state).await,
            NodeState::Generating(state) => state.advance(ctx, contract_state).await,
            NodeState::WaitingForConsensus(state) => state.advance(ctx, contract_state).await,
            NodeState::Running(state) => state.advance(ctx, contract_state).await,
            NodeState::Resharing(state) => state.advance(ctx, contract_state).await,
            NodeState::Joining(state) => state.advance(ctx, contract_state).await,
        }
    }
}

async fn start_resharing<C: ConsensusCtx>(
    private_share: Option<SecretKeyShare>,
    ctx: C,
    contract_state: ResharingContractState,
) -> Result<NodeState, ConsensusError> {
    let me = contract_state
        .new_participants
        .find_participant(ctx.my_account_id())
        .unwrap();
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
        me,
        private_share,
        contract_state.public_key,
    )?;
    Ok(NodeState::Resharing(ResharingState {
        old_epoch: contract_state.old_epoch,
        old_participants: contract_state.old_participants,
        new_participants: contract_state.new_participants,
        threshold: contract_state.threshold,
        public_key: contract_state.public_key,
        protocol: Arc::new(RwLock::new(protocol)),
        messages: Default::default(),
    }))
}

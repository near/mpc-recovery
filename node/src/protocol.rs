use crate::client::{self};
use crate::rpc_client::{self, SignerContractState};
use crate::types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol};
use cait_sith::protocol::{Action, MessageData, Participant};
use k256::{elliptic_curve::group::GroupEncoding, Secp256k1};
use near_crypto::InMemorySigner;
use near_primitives::types::AccountId;
use reqwest::IntoUrl;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{
    mpsc::{self, error::TryRecvError},
    RwLock,
};
use url::Url;

pub enum MpcSignMsg {
    Msg {
        from: Participant,
        data: MessageData,
    },
}

pub struct MpcSignProtocol {
    me: Participant,
    my_address: Url,
    mpc_contract_id: AccountId,
    rpc_client: near_fetch::Client,
    signer: InMemorySigner,
    receiver: mpsc::Receiver<MpcSignMsg>,
    client: reqwest::Client,
    state: Arc<RwLock<ProtocolState>>,
}

pub enum ProtocolState {
    Starting,
    Started {
        private_share: Option<PrivateKeyShare>,
        public_key: Option<PublicKey>,
    },
    Generating {
        participants: HashMap<Participant, Url>,
        threshold: usize,
        protocol: KeygenProtocol,
    },
    WaitingForConsensus {
        participants: HashMap<Participant, Url>,
        threshold: usize,
        private_share: PrivateKeyShare,
        public_key: PublicKey,
    },
    Running {
        participants: HashMap<Participant, Url>,
        threshold: usize,
        private_share: PrivateKeyShare,
        public_key: PublicKey,
    },
    Resharing {
        old_participants: HashMap<Participant, Url>,
        new_participants: HashMap<Participant, Url>,
        threshold: usize,
        public_key: PublicKey,
        protocol: ReshareProtocol,
    },
}

impl Default for ProtocolState {
    fn default() -> Self {
        ProtocolState::Starting
    }
}

impl MpcSignProtocol {
    pub fn init<U: IntoUrl>(
        me: Participant,
        my_address: U,
        mpc_contract_id: AccountId,
        rpc_client: near_fetch::Client,
        signer: InMemorySigner,
        receiver: mpsc::Receiver<MpcSignMsg>,
    ) -> (Self, Arc<RwLock<ProtocolState>>) {
        let state = Arc::new(RwLock::new(ProtocolState::Starting));
        let protocol = MpcSignProtocol {
            me,
            my_address: my_address.into_url().unwrap(),
            mpc_contract_id,
            rpc_client,
            signer,
            receiver,
            client: reqwest::Client::new(),
            state: state.clone(),
        };
        (protocol, state)
    }

    fn handle_message(state: &mut ProtocolState, msg: MpcSignMsg) -> anyhow::Result<()> {
        match msg {
            MpcSignMsg::Msg { from, data } => {
                tracing::info!("new message from {from:?}");
                match state {
                    ProtocolState::Generating { protocol, .. } => protocol.message(from, data),
                    ProtocolState::Resharing { protocol, .. } => protocol.message(from, data),
                    _ => {
                        tracing::warn!("received a message from {from:?}, but can't p.. it yet")
                        // TODO: save the message to a message queue to process later
                    }
                };
            }
        }

        Ok(())
    }

    async fn advance_keygen_protocol(
        client: &reqwest::Client,
        me: Participant,
        participants: HashMap<Participant, Url>,
        threshold: usize,
        mut protocol: KeygenProtocol,
    ) -> ProtocolState {
        tracing::info!("advancing initial keygen state");
        loop {
            let action = protocol.poke().unwrap();
            match action {
                Action::Wait => {
                    tracing::debug!("waiting");
                    return ProtocolState::Generating {
                        participants,
                        threshold,
                        protocol,
                    };
                }
                Action::SendMany(m) => {
                    tracing::debug!("sending a message to many participants");
                    for (p, url) in &participants {
                        if p == &me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        if let Err(e) = client::message(client, url.clone(), me, m.clone()).await {
                            tracing::error!("failed to send a message to {p:?} {e}, resetting to `Starting` state");
                            return ProtocolState::Starting;
                        }
                    }
                }
                Action::SendPrivate(to, m) => {
                    tracing::debug!("sending a private message to {to:?}");
                    match participants.get(&to) {
                        Some(url) => {
                            if let Err(e) = client::message(client, url.clone(), me, m).await {
                                tracing::error!("failed to send a message to {to:?} {e}, resetting to `Starting` state");
                                return ProtocolState::Starting;
                            }
                        }
                        None => {
                            tracing::error!("sending to an unknown participant {:?}, resetting to `Starting` state", to);
                            return ProtocolState::Starting;
                        }
                    }
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "successfully completed key generation"
                    );
                    return ProtocolState::WaitingForConsensus {
                        participants,
                        threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                    };
                }
            }
        }
    }

    async fn advance_reshare_protocol(
        client: &reqwest::Client,
        me: Participant,
        old_participants: HashMap<Participant, Url>,
        new_participants: HashMap<Participant, Url>,
        threshold: usize,
        mut protocol: ReshareProtocol,
        public_key: PublicKey,
    ) -> ProtocolState {
        tracing::info!("advancing initial keygen state");
        loop {
            let action = protocol.poke().unwrap();
            match action {
                Action::Wait => {
                    tracing::debug!("waiting");
                    return ProtocolState::Resharing {
                        old_participants,
                        new_participants,
                        threshold,
                        public_key,
                        protocol,
                    };
                }
                Action::SendMany(m) => {
                    tracing::debug!("sending a message to many participants");
                    for (p, url) in &new_participants {
                        if p == &me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }
                        if let Err(e) = client::message(client, url.clone(), me, m.clone()).await {
                            tracing::error!("failed to send a message to {p:?} {e}, resetting to `Starting` state");
                            return ProtocolState::Starting;
                        }
                    }
                }
                Action::SendPrivate(to, m) => {
                    tracing::debug!("sending a private message to {to:?}");
                    match new_participants.get(&to) {
                        Some(url) => {
                            if let Err(e) = client::message(client, url.clone(), me, m).await {
                                tracing::error!("failed to send a message to {to:?} {e}, resetting to `Starting` state");
                                return ProtocolState::Starting;
                            }
                        }
                        None => {
                            tracing::error!("sending to an unknown participant {:?}, resetting to `Starting` state", to);
                            return ProtocolState::Starting;
                        }
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("successfully completed key resharing");
                    return ProtocolState::Running {
                        participants: new_participants,
                        threshold,
                        private_share,
                        public_key,
                    };
                }
            }
        }
    }

    fn starting_with_existing_state(
        me: Participant,
        my_public_key: PublicKey,
        private_share: PrivateKeyShare,
        contract_state: SignerContractState,
    ) -> ProtocolState {
        match contract_state.public_key() {
            Some(contract_public_key) if my_public_key == contract_public_key => {
                if contract_state.participants().contains_key(&me) {
                    tracing::info!("we are a part of the current participant set, rejoining");
                    ProtocolState::Running {
                        participants: contract_state.participants(),
                        threshold: contract_state.threshold,
                        private_share: private_share.clone(),
                        public_key: contract_public_key,
                    }
                } else {
                    tracing::info!("we are not a part of the current participant set, trying to connect to other nodes");
                    todo!()
                }
            }
            Some(_) => {
                panic!("contract state public key does not match ours, crashing")
            }
            None => {
                panic!("contract state has somehow lost its public key, crashing")
            }
        }
    }

    fn starting_with_empty_state(
        me: Participant,
        contract_state: SignerContractState,
    ) -> ProtocolState {
        match contract_state.public_key() {
            Some(_) => {
                if contract_state.participants().contains_key(&me) {
                    tracing::warn!(
                        "we are a participant, but lost our private share, trying to re-join"
                    );
                    todo!()
                } else {
                    tracing::info!("we are not a participant yet, trying to join");
                    todo!()
                }
            }
            None => {
                if contract_state.participants().contains_key(&me) {
                    tracing::info!("starting key generation as a part of the participant set");
                    let participants = contract_state.participants();
                    let protocol = cait_sith::keygen(
                        &participants.keys().cloned().collect::<Vec<_>>(),
                        me,
                        contract_state.threshold,
                    )
                    .unwrap();
                    ProtocolState::Generating {
                        participants,
                        threshold: contract_state.threshold,
                        protocol: Box::new(protocol),
                    }
                } else {
                    tracing::info!("we are not a part of the initial participant set, waiting for key generation to complete");
                    // todo!()
                    ProtocolState::Started {
                        private_share: None,
                        public_key: None,
                    }
                }
            }
        }
    }

    fn generating(
        my_participants: HashMap<Participant, Url>,
        threshold: usize,
        protocol: KeygenProtocol,
        contract_state: SignerContractState,
    ) -> ProtocolState {
        let participants = contract_state.participants();
        match contract_state.public_key() {
            Some(_) if participants == my_participants && contract_state.threshold == threshold => {
                tracing::warn!("contract state is finalized without us completing the generation phase, trying to catch up");
                ProtocolState::Generating {
                    participants: my_participants,
                    threshold,
                    protocol,
                }
            }
            Some(_) => {
                tracing::warn!("contract state has a public key with a different participant set/threshold, restarting");
                ProtocolState::Starting
            }
            None => ProtocolState::Generating {
                participants: my_participants,
                threshold,
                protocol,
            },
        }
    }

    fn running(
        me: Participant,
        participants: HashMap<Participant, Url>,
        threshold: usize,
        private_share: PrivateKeyShare,
        public_key: PublicKey,
        contract_state: SignerContractState,
    ) -> ProtocolState {
        let contract_participants = contract_state.participants();
        match contract_state.public_key() {
            Some(contract_public_key)
                if contract_public_key == public_key
                    && contract_participants == participants
                    && contract_state.threshold == threshold =>
            {
                tracing::debug!("continue running as normal");
                ProtocolState::Running {
                    participants,
                    threshold,
                    private_share,
                    public_key,
                }
            }
            Some(contract_public_key)
                if contract_public_key == public_key
                    && contract_participants.contains_key(&me)
                    && contract_state.threshold == threshold =>
            {
                tracing::warn!("contract is resharing with us, following suit");
                let protocol = cait_sith::reshare::<Secp256k1>(
                    &participants.keys().cloned().collect::<Vec<_>>(),
                    threshold,
                    &contract_participants.keys().cloned().collect::<Vec<_>>(),
                    threshold,
                    me,
                    Some(private_share),
                    public_key,
                )
                .unwrap();
                ProtocolState::Resharing {
                    old_participants: participants,
                    new_participants: contract_participants,
                    threshold,
                    public_key,
                    protocol: Box::new(protocol),
                }
            }
            Some(contract_public_key) if contract_public_key == public_key => {
                tracing::error!("contract reshared without us, restarting");
                ProtocolState::Starting
            }
            Some(_) => {
                panic!("contract state changed its public key, crashing")
            }
            None => {
                tracing::info!("contract state has not agreed on a public key yet, waiting...");
                ProtocolState::Running {
                    participants,
                    threshold,
                    private_share,
                    public_key,
                }
            }
        }
    }

    fn resharing(
        old_participants: HashMap<Participant, Url>,
        new_participants: HashMap<Participant, Url>,
        threshold: usize,
        public_key: PublicKey,
        protocol: ReshareProtocol,
        contract_state: SignerContractState,
    ) -> ProtocolState {
        let contract_participants = contract_state.participants();
        match contract_state.public_key() {
            Some(contract_public_key)
                if contract_public_key == public_key
                    && contract_participants == new_participants
                    && contract_state.threshold == threshold =>
            {
                tracing::debug!("continue resharing as normal");
                ProtocolState::Resharing {
                    old_participants,
                    new_participants,
                    threshold,
                    public_key,
                    protocol,
                }
            }
            Some(contract_public_key) if contract_public_key == public_key => {
                tracing::warn!(
                    "contract is resharing again, but we need to finish our resharing first"
                );
                ProtocolState::Resharing {
                    old_participants,
                    new_participants,
                    threshold,
                    public_key,
                    protocol,
                }
            }
            Some(_) => {
                panic!("contract state changed its public key, crashing")
            }
            None => {
                panic!("contract state has somehow lost its public key, crashing")
            }
        }
    }

    async fn advance_protocol(
        client: &reqwest::Client,
        me: Participant,
        mut state: ProtocolState,
        contract_state: SignerContractState,
        rpc_client: &near_fetch::Client,
        signer: &InMemorySigner,
        mpc_contract_id: &AccountId,
    ) -> ProtocolState {
        /*
         * Advance cait-sith protocol
         */
        match state {
            ProtocolState::Generating {
                participants,
                threshold,
                protocol,
            } => {
                state =
                    Self::advance_keygen_protocol(client, me, participants, threshold, protocol)
                        .await;
            }
            ProtocolState::Resharing {
                old_participants,
                new_participants,
                threshold,
                protocol,
                public_key,
            } => {
                state = Self::advance_reshare_protocol(
                    client,
                    me,
                    old_participants,
                    new_participants,
                    threshold,
                    protocol,
                    public_key,
                )
                .await;
            }
            _ => {}
        };

        /*
         * Advance MPC state protocol
         */
        match state {
            ProtocolState::Starting => {
                // TODO: pull state from persistent storage
                tracing::info!(
                    "no existing state found, starting with empty key share and empty public key"
                );
                state = ProtocolState::Started {
                    private_share: None,
                    public_key: None,
                };
            }
            ProtocolState::Started {
                private_share,
                public_key,
            } => match (private_share, public_key) {
                (Some(private_share), Some(public_key)) => {
                    state = Self::starting_with_existing_state(
                        me,
                        public_key,
                        private_share,
                        contract_state,
                    );
                }
                (None, None) => {
                    state = Self::starting_with_empty_state(me, contract_state);
                }
                _ => {
                    tracing::error!("unexpected state (public key and private share should either both be present or both be missing), resetting to `Starting` state");
                    state = ProtocolState::Starting;
                }
            },
            ProtocolState::Generating {
                participants,
                threshold,
                protocol,
            } => {
                state = Self::generating(participants, threshold, protocol, contract_state);
            }
            ProtocolState::WaitingForConsensus {
                participants,
                threshold,
                private_share,
                public_key,
            } => {
                let is_pk_in_state = rpc_client::vote_for_public_key(
                    rpc_client,
                    signer,
                    mpc_contract_id,
                    &public_key,
                )
                .await
                .unwrap();
                if is_pk_in_state {
                    tracing::info!(
                        public_key = hex::encode(public_key.to_bytes()),
                        "contract state is in consensus with our public key"
                    );
                    state = ProtocolState::Running {
                        participants,
                        threshold,
                        private_share,
                        public_key,
                    };
                } else {
                    tracing::debug!(
                        "waiting for contract state to be in consensus with our public key"
                    );
                    state = ProtocolState::WaitingForConsensus {
                        participants,
                        threshold,
                        private_share,
                        public_key,
                    };
                }
            }
            ProtocolState::Running {
                participants,
                threshold,
                private_share,
                public_key,
            } => {
                state = Self::running(
                    me,
                    participants,
                    threshold,
                    private_share,
                    public_key,
                    contract_state,
                );
            }
            ProtocolState::Resharing {
                old_participants,
                new_participants,
                threshold,
                public_key,
                protocol,
            } => {
                state = Self::resharing(
                    old_participants,
                    new_participants,
                    threshold,
                    public_key,
                    protocol,
                    contract_state,
                )
            }
        };

        state
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        tracing::info!("running mpc recovery protocol");
        loop {
            tracing::debug!("trying to advance mpc recovery protocol");
            let contract_state =
                match rpc_client::fetch_mpc_contract_state(&self.rpc_client, &self.mpc_contract_id)
                    .await
                {
                    Ok(contract_state) => contract_state,
                    Err(e) => {
                        tracing::error!("could not fetch contract's state: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
            tracing::debug!(?contract_state);
            let msg_result = self.receiver.try_recv();
            let mut state_guard = self.state.write().await;
            match msg_result {
                Ok(msg) => {
                    tracing::debug!("received a new message");
                    Self::handle_message(&mut state_guard, msg)?;
                }
                Err(TryRecvError::Empty) => {
                    tracing::debug!("no new messages received");
                }
                Err(TryRecvError::Disconnected) => {
                    tracing::debug!("communication was disconnected, no more messages will be received, spinning down");
                    break;
                }
            }
            let mut state = std::mem::take(&mut *state_guard);
            state = Self::advance_protocol(
                &self.client,
                self.me,
                state,
                contract_state,
                &self.rpc_client,
                &self.signer,
                &self.mpc_contract_id,
            )
            .await;
            *state_guard = state;
            drop(state_guard);
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }

        Ok(())
    }
}

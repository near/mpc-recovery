use crate::client::{self};
use cait_sith::protocol::{Action, MessageData, Participant};
use k256::{elliptic_curve::group::GroupEncoding, Secp256k1};
use mpc_recovery_common::{
    leader::LeaderNodeState,
    types::{KeygenProtocol, PrivateKeyShare, PublicKey, ReshareProtocol},
};
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
    leader_url: Url,
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
    Running {
        participants: HashMap<Participant, Url>,
        threshold: usize,
        private_share: PrivateKeyShare,
        public_key: PublicKey,
    },
    Resharing {
        participants: HashMap<Participant, Url>,
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
        leader_url: U,
        receiver: mpsc::Receiver<MpcSignMsg>,
    ) -> (Self, Arc<RwLock<ProtocolState>>) {
        let state = Arc::new(RwLock::new(ProtocolState::Starting));
        let protocol = MpcSignProtocol {
            me,
            my_address: my_address.into_url().unwrap(),
            leader_url: leader_url.into_url().unwrap(),
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
                    tracing::debug!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "successfully completed key generation"
                    );
                    return ProtocolState::Running {
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
        participants: HashMap<Participant, Url>,
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
                        participants,
                        threshold,
                        public_key,
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
                Action::Return(private_share) => {
                    tracing::debug!("successfully completed key resharing");
                    return ProtocolState::Running {
                        participants,
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
        leader_state: LeaderNodeState,
    ) -> ProtocolState {
        match leader_state {
            LeaderNodeState::Discovering { .. } => {
                tracing::info!("leader node has lost its public key, restarting");
                ProtocolState::Starting
            }
            LeaderNodeState::Generating { .. } => {
                tracing::info!("leader node has lost its public key, restarting");
                ProtocolState::Starting
            }
            LeaderNodeState::Running {
                participants,
                public_key,
                threshold,
            } if participants.contains_key(&me) => {
                tracing::info!("we are a part of the current participant set, rejoining");
                if public_key != my_public_key {
                    tracing::error!("saved public key does not match the leader state, restarting");
                    return ProtocolState::Starting;
                }
                ProtocolState::Running {
                    participants,
                    threshold,
                    private_share: private_share.clone(),
                    public_key,
                }
            }
            LeaderNodeState::Running { public_key, .. } => {
                tracing::info!(
                    "network is running without us, waiting for an opportunity to join via reshare"
                );
                if public_key != my_public_key {
                    tracing::error!("saved public key does not match the leader state, restarting");
                    return ProtocolState::Starting;
                }
                ProtocolState::Started {
                    private_share: Some(private_share),
                    public_key: Some(my_public_key),
                }
            }
            LeaderNodeState::Resharing {
                old_participants,
                new_participants,
                public_key,
                threshold,
            } if new_participants.contains_key(&me) => {
                tracing::info!("starting key generation as a part of the participant set");
                if public_key != my_public_key {
                    tracing::error!("saved public key does not match the leader state, restarting");
                    return ProtocolState::Starting;
                }
                let protocol = cait_sith::reshare::<Secp256k1>(
                    &old_participants.keys().cloned().collect::<Vec<_>>(),
                    threshold,
                    &new_participants.keys().cloned().collect::<Vec<_>>(),
                    threshold,
                    me,
                    None,
                    public_key,
                )
                .unwrap();
                ProtocolState::Resharing {
                    participants: new_participants,
                    threshold,
                    public_key,
                    protocol: Box::new(protocol),
                }
            }
            LeaderNodeState::Resharing { public_key, .. } => {
                tracing::info!(
                    "network is resharing without us, waiting for an opportunity to join via another reshare"
                );
                if public_key != my_public_key {
                    tracing::error!("saved public key does not match the leader state, restarting");
                    return ProtocolState::Starting;
                }
                ProtocolState::Started {
                    private_share: Some(private_share),
                    public_key: Some(my_public_key),
                }
            }
        }
    }

    fn starting_with_empty_state(me: Participant, leader_state: LeaderNodeState) -> ProtocolState {
        match leader_state {
            LeaderNodeState::Discovering { joining } if joining.contains_key(&me) => {
                tracing::info!(
                    "leader node has discovered us, waiting to start the generation phase"
                );
                ProtocolState::Started {
                    private_share: None,
                    public_key: None,
                }
            }
            LeaderNodeState::Discovering { .. } => {
                tracing::info!("leader node has not discovered us yet, waiting to be discovered");
                ProtocolState::Started {
                    private_share: None,
                    public_key: None,
                }
            }
            LeaderNodeState::Generating {
                participants,
                threshold,
            } if participants.contains_key(&me) => {
                tracing::info!("starting key generation as a part of the participant set");
                let protocol = cait_sith::keygen(
                    &participants.keys().cloned().collect::<Vec<_>>(),
                    me,
                    threshold,
                )
                .unwrap();
                ProtocolState::Generating {
                    participants,
                    threshold,
                    protocol: Box::new(protocol),
                }
            }
            LeaderNodeState::Generating { .. } => {
                tracing::info!(
                    "network has started key generation without us, waiting for an opportunity to join via reshare"
                );
                ProtocolState::Started {
                    private_share: None,
                    public_key: None,
                }
            }
            LeaderNodeState::Running { .. } => {
                tracing::info!(
                    "network is running without us, waiting for an opportunity to join via reshare"
                );
                ProtocolState::Started {
                    private_share: None,
                    public_key: None,
                }
            }
            LeaderNodeState::Resharing {
                old_participants,
                new_participants,
                public_key,
                threshold,
            } if new_participants.contains_key(&me) => {
                tracing::info!("starting key generation as a part of the participant set");
                let protocol = cait_sith::reshare::<Secp256k1>(
                    &old_participants.keys().cloned().collect::<Vec<_>>(),
                    threshold,
                    &new_participants.keys().cloned().collect::<Vec<_>>(),
                    threshold,
                    me,
                    None,
                    public_key,
                )
                .unwrap();
                ProtocolState::Resharing {
                    participants: new_participants,
                    threshold,
                    public_key,
                    protocol: Box::new(protocol),
                }
            }
            LeaderNodeState::Resharing { .. } => {
                tracing::info!(
                    "network is resharing without us, waiting for an opportunity to join via another reshare"
                );
                ProtocolState::Started {
                    private_share: None,
                    public_key: None,
                }
            }
        }
    }

    fn generating(
        me: Participant,
        my_participants: HashMap<Participant, Url>,
        threshold: usize,
        protocol: KeygenProtocol,
        leader_state: LeaderNodeState,
    ) -> ProtocolState {
        match leader_state {
            LeaderNodeState::Discovering { .. } => {
                tracing::warn!("leader node has regressed to discovery state, restarting");
                ProtocolState::Starting
            }
            LeaderNodeState::Generating { participants, .. } => {
                if participants != my_participants {
                    tracing::error!("leader has lost us during generation, restarting");
                    ProtocolState::Starting
                } else {
                    ProtocolState::Generating {
                        participants,
                        threshold,
                        protocol,
                    }
                }
            }
            LeaderNodeState::Running { participants, .. } => {
                if !participants.contains_key(&me) {
                    tracing::warn!("leader is running without us completing the generation phase, trying to catch up");
                    ProtocolState::Generating {
                        participants,
                        threshold,
                        protocol,
                    }
                } else {
                    tracing::error!("leader advanced to running without us, restarting");
                    ProtocolState::Starting
                }
            }
            LeaderNodeState::Resharing {
                new_participants, ..
            } => {
                if new_participants.contains_key(&me) {
                    tracing::warn!("leader is resharing without us completing the generation phase, trying to catch up");
                    ProtocolState::Generating {
                        participants: my_participants,
                        threshold,
                        protocol,
                    }
                } else {
                    tracing::error!("leader advanced to resharing without us, restarting");
                    ProtocolState::Starting
                }
            }
        }
    }

    fn running(
        me: Participant,
        my_participants: HashMap<Participant, Url>,
        my_threshold: usize,
        private_share: PrivateKeyShare,
        my_public_key: PublicKey,
        leader_state: LeaderNodeState,
    ) -> ProtocolState {
        match leader_state {
            LeaderNodeState::Discovering { .. } => {
                tracing::warn!("leader node has regressed to discovery state, restarting");
                ProtocolState::Starting
            }
            LeaderNodeState::Generating {
                participants,
                threshold,
            } => {
                if participants != my_participants || threshold != my_threshold {
                    tracing::warn!("leader node has regressed to generating state, restarting");
                    ProtocolState::Starting
                } else {
                    tracing::debug!("leader node has not caught up with us yet");
                    ProtocolState::Running {
                        participants: my_participants,
                        threshold: my_threshold,
                        private_share,
                        public_key: my_public_key,
                    }
                }
            }
            LeaderNodeState::Running {
                participants,
                public_key,
                threshold,
            } => {
                if participants != my_participants {
                    tracing::warn!("leader is running without us, restarting");
                    ProtocolState::Starting
                } else if my_threshold != threshold {
                    tracing::warn!("leader threshold is different from ours, restarting");
                    ProtocolState::Starting
                } else if my_public_key != public_key {
                    tracing::warn!("leader public key is different from ours, restarting");
                    ProtocolState::Starting
                } else {
                    tracing::debug!("continue running as normal");
                    ProtocolState::Running {
                        participants,
                        threshold,
                        private_share,
                        public_key,
                    }
                }
            }
            LeaderNodeState::Resharing {
                old_participants,
                new_participants,
                public_key,
                threshold,
            } => {
                if new_participants.contains_key(&me) {
                    tracing::warn!("leader is resharing without us completing the generation phase, trying to catch up");
                    let protocol = cait_sith::reshare::<Secp256k1>(
                        &old_participants.keys().cloned().collect::<Vec<_>>(),
                        threshold,
                        &new_participants.keys().cloned().collect::<Vec<_>>(),
                        threshold,
                        me,
                        Some(private_share),
                        public_key,
                    )
                    .unwrap();
                    ProtocolState::Resharing {
                        participants: new_participants,
                        threshold,
                        public_key,
                        protocol: Box::new(protocol),
                    }
                } else {
                    tracing::error!("leader advanced to resharing without us, restarting");
                    ProtocolState::Starting
                }
            }
        }
    }

    fn resharing(
        my_participants: HashMap<Participant, Url>,
        my_threshold: usize,
        my_public_key: PublicKey,
        protocol: ReshareProtocol,
        leader_state: LeaderNodeState,
    ) -> ProtocolState {
        match leader_state {
            LeaderNodeState::Discovering { .. } => {
                tracing::warn!("leader node has regressed to discovery state, restarting");
                ProtocolState::Starting
            }
            LeaderNodeState::Generating { .. } => {
                tracing::warn!("leader node has regressed to generating state, restarting");
                ProtocolState::Starting
            }
            LeaderNodeState::Running {
                participants,
                public_key,
                threshold,
            } => {
                if participants != my_participants {
                    tracing::warn!("leader is running without us, restarting");
                    ProtocolState::Starting
                } else if my_threshold != threshold {
                    tracing::error!("leader threshold is different from ours, restarting");
                    ProtocolState::Starting
                } else if my_public_key != public_key {
                    tracing::error!("leader public key is different from ours, restarting");
                    ProtocolState::Starting
                } else {
                    tracing::warn!("leader is running without us completing the resharing phase, trying to catch up");
                    ProtocolState::Resharing {
                        participants: my_participants,
                        threshold: my_threshold,
                        public_key: my_public_key,
                        protocol,
                    }
                }
            }
            LeaderNodeState::Resharing {
                new_participants,
                public_key,
                threshold,
                ..
            } => {
                if new_participants != my_participants {
                    tracing::warn!("leader is resharing with a different set, restarting");
                    ProtocolState::Starting
                } else if my_threshold != threshold {
                    tracing::error!("leader threshold is different from ours, restarting");
                    ProtocolState::Starting
                } else if my_public_key != public_key {
                    tracing::error!("leader public key is different from ours, restarting");
                    ProtocolState::Starting
                } else {
                    ProtocolState::Resharing {
                        participants: my_participants,
                        threshold: my_threshold,
                        public_key: my_public_key,
                        protocol,
                    }
                }
            }
        }
    }

    async fn advance_protocol(
        client: &reqwest::Client,
        me: Participant,
        mut state: ProtocolState,
        leader_state: LeaderNodeState,
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
                participants,
                threshold,
                protocol,
                public_key,
            } => {
                state = Self::advance_reshare_protocol(
                    client,
                    me,
                    participants,
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
                        leader_state,
                    );
                }
                (None, None) => {
                    state = Self::starting_with_empty_state(me, leader_state);
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
                state = Self::generating(me, participants, threshold, protocol, leader_state);
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
                    leader_state,
                );
            }
            ProtocolState::Resharing {
                participants,
                threshold,
                public_key,
                protocol,
            } => {
                state = Self::resharing(participants, threshold, public_key, protocol, leader_state)
            }
        };

        state
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        tracing::info!("running mpc recovery protocol");
        loop {
            tracing::debug!("trying to advance mpc recovery protocol");
            let leader_state = match client::connect(
                &self.client,
                self.leader_url.clone(),
                self.me,
                self.my_address.clone(),
            )
            .await
            {
                Ok(leader_state) => leader_state,
                Err(e) => {
                    tracing::error!("could not fetch leader node's state: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            tracing::debug!(?leader_state);
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
            state = Self::advance_protocol(&self.client, self.me, state, leader_state).await;
            *state_guard = state;
            drop(state_guard);
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }

        Ok(())
    }
}

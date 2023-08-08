use crate::client::{self};
use cait_sith::protocol::{Action, MessageData, Participant};
use k256::{elliptic_curve::group::GroupEncoding, Secp256k1};
use mpc_recovery_common::{
    leader::LeaderNodeState,
    types::{KeygenProtocol, PrivateKeyShare, PublicKey},
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
    PreGeneration {
        threshold: usize,
        joining: HashMap<Participant, Url>,
    },
    InitialKeygen {
        participants: HashMap<Participant, Url>,
        threshold: usize,
        protocol: KeygenProtocol,
    },
    Running {
        participants: HashMap<Participant, Url>,
        threshold: usize,
        joining: HashMap<Participant, Url>,
        private_share: PrivateKeyShare,
        public_key: PublicKey,
    },
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
                    ProtocolState::PreGeneration { .. } => todo!(),
                    ProtocolState::InitialKeygen { protocol, .. } => protocol.message(from, data),
                    ProtocolState::Running { .. } => todo!(),
                    ProtocolState::Starting | ProtocolState::Started { .. } => {
                        tracing::warn!("received a message from {from:?}, but can't process it yet")
                    }
                };
            }
        }

        Ok(())
    }

    async fn advance_protocol(
        client: &reqwest::Client,
        me: Participant,
        leader_url: &Url,
        my_address: &Url,
        mut state: ProtocolState,
        leader_state: LeaderNodeState,
    ) -> ProtocolState {
        /*
         * Advance cait-sith protocol
         */
        match state {
            ProtocolState::InitialKeygen {
                participants,
                threshold,
                mut protocol,
            } => {
                tracing::info!("advancing initial keygen state");
                loop {
                    let action = protocol.poke().unwrap();
                    match action {
                        Action::Wait => {
                            tracing::debug!("waiting");
                            state = ProtocolState::InitialKeygen {
                                participants,
                                threshold,
                                protocol,
                            };
                            break;
                        }
                        Action::SendMany(m) => {
                            tracing::debug!("sending a message to many participants");
                            for (p, url) in &participants {
                                if let Err(e) =
                                    client::message(client, url.clone(), me, m.clone()).await
                                {
                                    tracing::error!("failed to send a message to {p:?} {e}, resetting to `Starting` state");
                                    state = ProtocolState::Starting;
                                    return state;
                                }
                            }
                        }
                        Action::SendPrivate(to, m) => {
                            tracing::debug!("sending a private message to {to:?}");
                            match participants.get(&to) {
                                Some(url) => {
                                    if let Err(e) =
                                        client::message(client, url.clone(), me, m).await
                                    {
                                        tracing::error!("failed to send a message to {to:?} {e}, resetting to `Starting` state");
                                        state = ProtocolState::Starting;
                                        return state;
                                    }
                                }
                                None => {
                                    tracing::error!("sending to an unknown participant {:?}, resetting to `Starting` state", to);
                                    state = ProtocolState::Starting;
                                    return state;
                                }
                            }
                        }
                        Action::Return(r) => {
                            tracing::debug!(
                                public_key = hex::encode(r.public_key.to_bytes()),
                                "successfully completed key generation"
                            );
                            state = ProtocolState::Running {
                                participants,
                                threshold,
                                joining: HashMap::new(),
                                private_share: r.private_share,
                                public_key: r.public_key,
                            };
                            break;
                        }
                    }
                }
            }
            _ => {}
        };

        /*
         * Advance MPC state protocol
         */
        fn resolve_against_existing_state(
            me: Participant,
            public_key: &PublicKey,
            private_share: &PrivateKeyShare,
            leader_state: LeaderNodeState,
        ) -> ProtocolState {
            let Some(leader_public_key) = leader_state.public_key else {
                tracing::error!(
                    "we have a public key while leader state does not have a public key, resetting to `Starting` state"
                );
                return ProtocolState::Starting;
            };
            if &leader_public_key != public_key {
                tracing::error!(
                    "saved public key does not match the leader state, resetting to `Starting` state"
                );
                return ProtocolState::Starting;
            }
            if leader_state.participants.contains_key(&me) {
                tracing::info!("we are a part of the current cohort, rejoining as a participants");
                return ProtocolState::Running {
                    participants: leader_state.participants,
                    threshold: leader_state.threshold,
                    joining: leader_state.joining,
                    private_share: private_share.clone(),
                    public_key: leader_public_key,
                };
            }

            todo!("move to key resharing state")
        }

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
                    state = resolve_against_existing_state(
                        me,
                        &public_key,
                        &private_share,
                        leader_state,
                    );
                }
                (None, None) if leader_state.joining.contains_key(&me) => {
                    state = ProtocolState::PreGeneration {
                        threshold: leader_state.threshold,
                        joining: leader_state.joining,
                    };
                }
                (None, None) => {
                    client::connect(client, leader_url.clone(), me, my_address.clone())
                        .await
                        .unwrap();
                    state = ProtocolState::PreGeneration {
                        threshold: leader_state.threshold,
                        joining: leader_state.joining,
                    };
                }
                _ => {
                    tracing::error!("unexpected state (public key and private share should either both be present or both be missing), resetting to `Starting` state");
                    state = ProtocolState::Starting;
                }
            },
            ProtocolState::PreGeneration { threshold, joining }
                if joining.len() >= threshold && joining.contains_key(&me) =>
            {
                tracing::info!(
                    joining_count = joining.len(),
                    threshold,
                    "reached the minimum count of new participants, advancing to initial keygen",
                );

                if leader_state.public_key.is_some() {
                    tracing::warn!(
                        "the network has generated a key without us, resetting to `Starting` state"
                    );
                    state = ProtocolState::Starting;
                    return state;
                }

                let protocol = cait_sith::keygen::<Secp256k1>(
                    &joining.keys().cloned().collect::<Vec<_>>(),
                    me,
                    threshold,
                )
                .unwrap();
                state = ProtocolState::InitialKeygen {
                    participants: joining,
                    threshold,
                    protocol: Box::new(protocol),
                }
            }
            ProtocolState::PreGeneration { threshold, joining } => {
                tracing::info!(
                    joining_count = joining.len(),
                    threshold,
                    "have not reached the minimum count of joining participants (or we are not a part of participants), waiting",
                );

                if leader_state.public_key.is_some() {
                    tracing::warn!(
                        "the network has generated a key without us, resetting to `Starting` state"
                    );
                    state = ProtocolState::Starting;
                    return state;
                }

                if leader_state.participants.len() > 0 {
                    tracing::warn!("the network has changed the participant set without us, resetting to `Starting` state");
                    state = ProtocolState::Starting;
                    return state;
                }
                client::connect(client, leader_url.clone(), me, my_address.clone())
                    .await
                    .unwrap();

                state = ProtocolState::PreGeneration {
                    threshold: leader_state.threshold,
                    joining: leader_state.joining,
                }
            }
            ProtocolState::InitialKeygen {
                participants,
                threshold,
                protocol,
            } => {
                if leader_state.public_key.is_some() {
                    tracing::warn!(
                        "the network has generated a key without us, resetting to `Starting` state"
                    );
                    state = ProtocolState::Starting;
                    return state;
                }

                state = ProtocolState::InitialKeygen {
                    participants,
                    threshold,
                    protocol,
                };
            }
            ProtocolState::Running {
                participants,
                threshold,
                joining,
                private_share,
                public_key,
            } => {
                match leader_state.public_key {
                    Some(leader_public_key) => {
                        if leader_public_key != public_key {
                            tracing::error!("the network has changed the public key, resetting to `Starting` state");
                            state = ProtocolState::Starting;
                            return state;
                        }

                        if leader_state.participants != participants {
                            tracing::warn!("the network has changed the participant set without us, resetting to `Starting` state");
                            state = ProtocolState::Starting;
                            return state;
                        }

                        if leader_state.threshold != threshold {
                            tracing::warn!("the network has changed the threshold without us, resetting to `Starting` state");
                            state = ProtocolState::Starting;
                            return state;
                        }

                        if joining != leader_state.joining {
                            tracing::info!(
                                "{} new sign nodes are trying to join",
                                leader_state.joining.len()
                            );

                            // TODO: move to keyshare state
                            state = ProtocolState::Running {
                                participants,
                                threshold,
                                joining: leader_state.joining,
                                private_share,
                                public_key,
                            };
                        } else {
                            state = ProtocolState::Running {
                                participants,
                                threshold,
                                joining,
                                private_share,
                                public_key,
                            };
                        }
                    }
                    None => {
                        tracing::info!("the network is not aware of the public key yet");
                        state = ProtocolState::Running {
                            participants,
                            threshold,
                            joining,
                            private_share,
                            public_key,
                        };
                    }
                }
            }
        };

        state
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        tracing::info!("running mpc recovery protocol");
        loop {
            tracing::debug!("trying to advance mpc recovery protocol");
            let leader_state = match client::state(&self.client, self.leader_url.clone()).await {
                Ok(leader_state) => leader_state,
                Err(e) => {
                    tracing::error!("could not fetch leader node's state: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            tracing::debug!(?leader_state);
            let msg_result = self.receiver.try_recv();
            let mut state = self.state.write().await;
            match msg_result {
                Ok(msg) => {
                    tracing::debug!("received a new message");
                    Self::handle_message(&mut state, msg)?;
                }
                Err(TryRecvError::Empty) => {
                    tracing::debug!("no new messages received");
                }
                Err(TryRecvError::Disconnected) => {
                    tracing::debug!("communication was disconnected, no more messages will be received, spinning down");
                    break;
                }
            }
            let mut state_tmp = ProtocolState::Starting;
            std::mem::swap(&mut *state, &mut state_tmp);
            let mut state_tmp = Self::advance_protocol(
                &self.client,
                self.me,
                &self.leader_url,
                &self.my_address,
                state_tmp,
                leader_state,
            )
            .await;
            std::mem::swap(&mut *state, &mut state_tmp);
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }

        Ok(())
    }
}

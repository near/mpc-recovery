use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use crate::web::StateView;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

// TODO: this is a basic connection pool and does not do most of the work yet. This is
//       mostly here just to facilitate offline node handling for now.
// TODO/NOTE: we can use libp2p to facilitate most the of low level TCP connection work.
#[derive(Default)]
pub struct Pool {
    http: reqwest::Client,
    connections: RwLock<Participants>,
    potential_connections: RwLock<Participants>,

    /// The currently active participants for this epoch.
    current_active: RwLock<Option<(Participants, Instant)>>,
    // Potentially active participants that we can use to establish a connection in the next epoch.
    potential_active: RwLock<Option<(Participants, Instant)>>,
}

impl Pool {
    pub async fn ping(&self) -> Participants {
        if let Some((ref active, timestamp)) = *self.current_active.read().await {
            if timestamp.elapsed() < DEFAULT_TIMEOUT {
                return active.clone();
            }
        }

        let connections = self.connections.read().await;

        let mut participants = Participants::default();
        for (participant, info) in connections.iter() {
            let Ok(resp) = self.http.get(format!("{}/state", info.url)).send().await else {
                continue;
            };

            let Ok(_state): Result<StateView, _> = resp.json().await else {
                continue;
            };
            participants.insert(participant, info.clone());
        }

        let mut active = self.current_active.write().await;
        *active = Some((participants.clone(), Instant::now()));
        participants
    }

    pub async fn ping_potential(&self) -> Participants {
        if let Some((ref active, timestamp)) = *self.potential_active.read().await {
            if timestamp.elapsed() < DEFAULT_TIMEOUT {
                return active.clone();
            }
        }

        let connections = self.potential_connections.read().await;

        let mut participants = Participants::default();
        for (participant, info) in connections.iter() {
            let Ok(resp) = self.http.get(format!("{}/state", info.url)).send().await else {
                continue;
            };

            let Ok(_state): Result<StateView, _> = resp.json().await else {
                continue;
            };
            participants.insert(participant, info.clone());
        }

        let mut potential_active = self.potential_active.write().await;
        *potential_active = Some((participants.clone(), Instant::now()));
        participants
    }

    pub async fn establish_participants(&self, contract_state: &ProtocolState) {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                self.set_participants(&participants).await;
            }
            ProtocolState::Running(contract_state) => {
                self.set_participants(&contract_state.participants).await;
            }
            ProtocolState::Resharing(contract_state) => {
                self.set_participants(&contract_state.old_participants)
                    .await;
                self.set_potential_participants(&contract_state.new_participants)
                    .await;
            }
        }
    }

    async fn set_participants(&self, participants: &Participants) {
        *self.connections.write().await = participants.clone();
    }

    async fn set_potential_participants(&self, participants: &Participants) {
        *self.potential_connections.write().await = participants.clone();
    }

    pub async fn potential_participants(&self) -> Participants {
        self.potential_connections.read().await.clone()
    }
}

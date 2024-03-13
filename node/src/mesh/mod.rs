use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;

pub mod connection;

#[derive(Default)]
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    pub connections: connection::Pool,

    /// Participants that are active at the beginning of each protocol loop.
    pub active_participants: Participants,

    /// Potential participants that are active at the beginning of each protocol loop. This
    /// includes participants belonging to the next epoch.
    pub active_potential_participants: Participants,
}

impl Mesh {
    /// Participants that are active at the beginning of each protocol loop.
    pub fn active_participants(&self) -> &Participants {
        &self.active_participants
    }

    /// Potential participants that are active at the beginning of each protocol loop. This will
    /// be empty if not in resharing state for the protocol
    pub fn active_potential_participants(&self) -> &Participants {
        &self.active_potential_participants
    }

    /// Get all pontential participants, but they not necessarily be active.
    pub async fn potential_participants(&self) -> Participants {
        self.connections.potential_participants().await
    }

    pub fn all_active_participants(&self) -> Participants {
        let mut participants = self.active_participants.clone();
        let active = self
            .active_potential_participants
            .keys()
            .collect::<Vec<_>>();
        tracing::info!(?active, "Getting potentially active participants");
        for (participant, info) in self.active_potential_participants.iter() {
            if !participants.contains_key(participant) {
                participants.insert(participant, info.clone());
            }
        }
        participants
    }

    pub async fn establish_participants(&mut self, contract_state: &ProtocolState) {
        self.connections
            .establish_participants(contract_state)
            .await;
        self.active_participants = self.connections.ping().await;
        self.active_potential_participants = self.connections.ping_potential().await;
    }
}

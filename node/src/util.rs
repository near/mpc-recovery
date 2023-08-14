pub mod serde_participant {
    use cait_sith::protocol::Participant;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(participant: &Participant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(u32::from_le_bytes(participant.bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Participant, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(u32::deserialize(deserializer)?.into())
    }
}

pub mod serde_participants {
    use cait_sith::protocol::Participant;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;
    use url::Url;

    pub fn serialize<S>(
        participants: &HashMap<Participant, Url>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let participants: HashMap<u32, Url> = participants
            .clone()
            .into_iter()
            .map(|(p, u)| (u32::from_le_bytes(p.bytes()), u))
            .collect();
        Serialize::serialize(&participants, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<Participant, Url>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let participants: HashMap<u32, Url> = Deserialize::deserialize(deserializer)?;
        Ok(participants
            .into_iter()
            .map(|(p, u)| (p.into(), u))
            .collect())
    }
}

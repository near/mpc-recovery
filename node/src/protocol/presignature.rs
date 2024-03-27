use super::message::PresignatureMessage;
use super::triple::{Triple, TripleConfig, TripleId, TripleManager};
use super::Config;
use crate::gcp::error::DatastoreStorageError;
use crate::protocol::contract::primitives::Participants;
use crate::types::{PresignatureProtocol, PublicKey, SecretKeyShare};
use crate::util::AffinePointExt;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use k256::Secp256k1;
use near_lake_primitives::AccountId;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Unique number used to identify a specific ongoing presignature generation protocol.
/// Without `PresignatureId` it would be unclear where to route incoming cait-sith presignature
/// generation messages.
pub type PresignatureId = u64;

/// A completed presignature.
pub struct Presignature {
    pub id: PresignatureId,
    pub output: PresignOutput<Secp256k1>,
    pub participants: Vec<Participant>,
}

#[derive(Copy, Clone, Debug)]
pub struct PresignatureConfig {
    pub min_presignatures: usize,
    pub max_presignatures: usize,
}

/// An ongoing presignature generator.
pub struct PresignatureGenerator {
    pub participants: Vec<Participant>,
    pub protocol: PresignatureProtocol,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub mine: bool,
    pub timestamp: Instant,
}

impl PresignatureGenerator {
    pub fn new(
        protocol: PresignatureProtocol,
        participants: Vec<Participant>,
        triple0: TripleId,
        triple1: TripleId,
        mine: bool,
    ) -> Self {
        Self {
            protocol,
            participants,
            triple0,
            triple1,
            mine,
            timestamp: Instant::now(),
        }
    }

    pub fn poke(&mut self) -> Result<Action<PresignOutput<Secp256k1>>, ProtocolError> {
        if self.timestamp.elapsed() > crate::types::PROTOCOL_PRESIG_TIMEOUT {
            tracing::info!(
                self.triple0,
                self.triple1,
                self.mine,
                "presignature protocol timed out"
            );
            return Err(ProtocolError::Other(
                anyhow::anyhow!("presignature protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("presignature already generated")]
    AlreadyGenerated,
    #[error("triple {0} is missing")]
    TripleIsMissing(TripleId),
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("datastore storage error: {0}")]
    DatastoreStorageError(#[from] DatastoreStorageError),
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct PresignatureManager {
    /// Completed unspent presignatures.
    presignatures: HashMap<PresignatureId, Presignature>,
    /// Ongoing presignature generation protocols.
    generators: HashMap<PresignatureId, PresignatureGenerator>,
    /// List of presignature ids generation of which was initiated by the current node.
    mine: VecDeque<PresignatureId>,
    /// The set of presignatures that were introduced to the system by the current node.
    introduced: HashSet<PresignatureId>,
    /// The set of presignatures that were already taken. This will be maintained for at most
    /// presignature timeout period just so messages are cycled through the system.
    taken: HashMap<PresignatureId, Instant>,

    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
    presig_cfg: PresignatureConfig,
}

impl PresignatureManager {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        my_account_id: AccountId,
        cfg: Config,
    ) -> Self {
        Self {
            presignatures: HashMap::new(),
            generators: HashMap::new(),
            mine: VecDeque::new(),
            introduced: HashSet::new(),
            taken: HashMap::new(),
            me,
            threshold,
            epoch,
            my_account_id,
            presig_cfg: cfg.presig_cfg,
        }
    }

    /// Returns the number of unspent presignatures available in the manager.
    pub fn len(&self) -> usize {
        self.presignatures.len()
    }

    /// Returns the number of unspent presignatures assigned to this node.
    pub fn my_len(&self) -> usize {
        self.mine.len()
    }

    /// Returns the number of unspent presignatures we will have in the manager once
    /// all ongoing generation protocols complete.
    pub fn potential_len(&self) -> usize {
        self.presignatures.len() + self.generators.len()
    }

    /// Returns if there are unspent presignatures available in the manager.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear_taken(&mut self) {
        self.taken
            .retain(|_, instant| instant.elapsed() < crate::types::PROTOCOL_PRESIG_TIMEOUT);
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_internal(
        participants: &Participants,
        me: Participant,
        threshold: usize,
        triple0: Triple,
        triple1: Triple,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        mine: bool,
    ) -> Result<PresignatureGenerator, InitializationError> {
        let participants: Vec<_> = participants.keys().cloned().collect();
        let protocol = Box::new(cait_sith::presign(
            &participants,
            me,
            // These paramaters appear to be to make it easier to use different indexing schemes for triples
            // Introduced in this PR https://github.com/LIT-Protocol/cait-sith/pull/7
            &participants,
            me,
            PresignArguments {
                triple0: (triple0.share, triple0.public),
                triple1: (triple1.share, triple1.public),
                keygen_out: KeygenOutput {
                    private_share: *private_share,
                    public_key: *public_key,
                },
                threshold,
            },
        )?);
        Ok(PresignatureGenerator::new(
            protocol,
            participants,
            triple0.id,
            triple1.id,
            mine,
        ))
    }

    /// Starts a new presignature generation protocol.
    pub fn generate(
        &mut self,
        participants: &Participants,
        triple0: Triple,
        triple1: Triple,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
    ) -> Result<(), InitializationError> {
        let id = rand::random();
        tracing::info!(id, "starting protocol to generate a new presignature");
        let generator = Self::generate_internal(
            participants,
            self.me,
            self.threshold,
            triple0,
            triple1,
            public_key,
            private_share,
            true,
        )?;
        self.generators.insert(id, generator);
        self.introduced.insert(id);
        Ok(())
    }

    pub async fn stockpile(
        &mut self,
        active: &Participants,
        pk: &PublicKey,
        sk_share: &SecretKeyShare,
        triple_manager: &mut TripleManager,
    ) -> Result<(), InitializationError> {
        let PresignatureConfig {
            min_presignatures,
            max_presignatures,
        } = self.presig_cfg;

        let TripleConfig {
            max_concurrent_introduction,
            ..
        } = triple_manager.triple_cfg;

        let not_enough_presignatures = {
            // Stopgap to prevent too many presignatures in the system. This should be around min_presig*nodes*2
            // for good measure so that we have enough presignatures to do sig generation while also maintain
            // the minimum number of presignature where a single node can't flood the system.
            if self.potential_len() >= max_presignatures {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.my_len() < min_presignatures
                    && self.introduced.len() < max_concurrent_introduction
            }
        };

        if not_enough_presignatures {
            // To ensure there is no contention between different nodes we are only using triples
            // that we proposed. This way in a non-BFT environment we are guaranteed to never try
            // to use the same triple as any other node.
            if let Some((triple0, triple1)) = triple_manager.take_two_mine().await {
                let presig_participants = active
                    .intersection(&[&triple0.public.participants, &triple1.public.participants]);
                if presig_participants.len() < self.threshold {
                    tracing::debug!(
                        participants = ?presig_participants.keys_vec(),
                        "running: we don't have enough participants to generate a presignature"
                    );

                    // Insert back the triples to be used later since this active set of
                    // participants were not able to make use of these triples.
                    triple_manager.insert_mine(triple0).await;
                    triple_manager.insert_mine(triple1).await;
                } else {
                    self.generate(&presig_participants, triple0, triple1, pk, sk_share)?;
                }
            } else {
                tracing::debug!("running: we don't have enough triples to generate a presignature");
            }
        }

        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    #[allow(clippy::too_many_arguments)]
    pub async fn get_or_generate(
        &mut self,
        participants: &Participants,
        id: PresignatureId,
        triple0: TripleId,
        triple1: TripleId,
        triple_manager: &mut TripleManager,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
    ) -> Result<&mut PresignatureProtocol, GenerationError> {
        if self.presignatures.contains_key(&id) || self.taken.contains_key(&id) {
            Err(GenerationError::AlreadyGenerated)
        } else {
            match self.generators.entry(id) {
                Entry::Vacant(entry) => {
                    tracing::info!(id, "joining protocol to generate a new presignature");
                    let (triple0, triple1) = match triple_manager
                        .take_two(triple0, triple1, false)
                        .await
                    {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                id,
                                triple0,
                                triple1,
                                "could not initiate non-introduced presignature: triple might not have completed for this node yet"
                            );
                            return Err(error);
                        }
                    };
                    let generator = Self::generate_internal(
                        participants,
                        self.me,
                        self.threshold,
                        triple0,
                        triple1,
                        public_key,
                        private_share,
                        false,
                    )?;
                    let generator = entry.insert(generator);
                    Ok(&mut generator.protocol)
                }
                Entry::Occupied(entry) => Ok(&mut entry.into_mut().protocol),
            }
        }
    }

    pub fn take_mine(&mut self) -> Option<Presignature> {
        tracing::info!(mine = ?self.mine, "my presignatures");
        let my_presignature_id = self.mine.pop_front()?;
        self.taken.insert(my_presignature_id, Instant::now());
        Some(self.presignatures.remove(&my_presignature_id).unwrap())
    }

    pub fn take(&mut self, id: PresignatureId) -> Option<Presignature> {
        self.taken.insert(id, Instant::now());
        self.presignatures.remove(&id)
    }

    pub fn insert_mine(&mut self, presig: Presignature) {
        // Remove from taken list if it was there
        self.taken.remove(&presig.id);
        self.mine.push_back(presig.id);
        self.presignatures.insert(presig.id, presig);
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub fn poke(&mut self) -> Result<Vec<(Participant, PresignatureMessage)>, ProtocolError> {
        let mut messages = Vec::new();
        let mut result = Ok(());
        self.generators.retain(|id, generator| {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        self.introduced.remove(id);
                        result = Err(e);
                        break false;
                    }
                };
                match action {
                    Action::Wait => {
                        tracing::debug!("waiting");
                        // Retain protocol until we are finished
                        return true;
                    }
                    Action::SendMany(data) => {
                        for p in generator.participants.iter() {
                            messages.push((
                                *p,
                                PresignatureMessage {
                                    id: *id,
                                    triple0: generator.triple0,
                                    triple1: generator.triple1,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        PresignatureMessage {
                            id: *id,
                            triple0: generator.triple0,
                            triple1: generator.triple1,
                            epoch: self.epoch,
                            from: self.me,
                            data: data.clone(),
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            id,
                            me = ?self.me,
                            big_r = ?output.big_r.to_base58(),
                            "completed presignature generation"
                        );
                        self.presignatures.insert(
                            *id,
                            Presignature {
                                id: *id,
                                output,
                                participants: generator.participants.clone(),
                            },
                        );
                        if generator.mine {
                            tracing::info!(id, "assigning presignature to myself");
                            self.mine.push_back(*id);
                        }
                        self.introduced.remove(id);

                        crate::metrics::PRESIGNATURE_LATENCY
                            .with_label_values(&[&self.my_account_id.as_ref()])
                            .observe(generator.timestamp.elapsed().as_secs_f64());

                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });
        result.map(|_| messages)
    }
}

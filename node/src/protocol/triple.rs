use super::cryptography::CryptographicError;
use super::message::TripleMessage;
use crate::types::TripleProtocol;
use crate::util::AffinePointExt;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::triples::{TriplePub, TripleShare};
use highway::{HighwayHash, HighwayHasher};
use k256::elliptic_curve::group::GroupEncoding;
use k256::Secp256k1;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use crate::storage::triple_storage::{LockTripleNodeStorageBox, TripleData};


/// Unique number used to identify a specific ongoing triple generation protocol.
/// Without `TripleId` it would be unclear where to route incoming cait-sith triple generation
/// messages.
pub type TripleId = u64;

/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Triple {
    pub id: TripleId,
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct TripleManager {
    /// Completed unspent triples
    pub triples: HashMap<TripleId, Triple>,
    /// Ongoing triple generation protocols
    pub generators: HashMap<TripleId, TripleProtocol>,
    /// List of triple ids generation of which was initiated by the current node.
    pub mine: VecDeque<TripleId>,
    pub participants: Vec<Participant>,
    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub triple_storage: LockTripleNodeStorageBox
}

impl TripleManager {
    pub fn new(
        participants: Vec<Participant>,
        me: Participant,
        threshold: usize,
        epoch: u64,
        triples: Option<HashMap<TripleId, Triple>>,
        triple_storage: LockTripleNodeStorageBox
    ) -> Self {
        Self {
            triples: triples.unwrap_or(HashMap::new()),
            generators: HashMap::new(),
            mine: VecDeque::new(),
            participants,
            me,
            threshold,
            epoch,
            triple_storage
        }
    }

    /// Returns the number of unspent triples available in the manager.
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Returns the number of unspent triples assigned to this node.
    pub fn my_len(&self) -> usize {
        self.mine.len()
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub fn potential_len(&self) -> usize {
        self.len() + self.generators.len()
    }

    /// Starts a new Beaver triple generation protocol.
    pub fn generate(&mut self) -> Result<(), InitializationError> {
        let id = rand::random();
        tracing::debug!(id, "starting protocol to generate a new triple");
        let protocol: TripleProtocol = Box::new(cait_sith::triples::generate_triple::<Secp256k1>(
            &self.participants,
            self.me,
            self.threshold,
        )?);
        self.generators.insert(id, protocol);
        Ok(())
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(&mut self, id0: TripleId, id1: TripleId) -> Result<(Triple, Triple), TripleId> {
        if !self.triples.contains_key(&id0) {
            Err(id0)
        } else if !self.triples.contains_key(&id1) {
            Err(id1)
        } else {
            let triple1 = self.triples.remove(&id0).unwrap();
            let triple2 = self.triples.remove(&id1).unwrap();
            let mut write_lock = self.triple_storage.write().await;
            let account_id = &write_lock.account_id();
            match write_lock.delete(TripleData {account_id: account_id.clone(), triple: triple1.clone()}).await {
                Ok(()) => tracing::info!(id0, "successfully deleted triple"),
                Err(error) => tracing::info!(id0, ?error, "delete triple failed"),
            }
            match write_lock.delete(TripleData {account_id: account_id.clone(), triple: triple2.clone()}).await {
                Ok(()) => tracing::info!(id1, "successfully deleted triple"),
                Err(error) => tracing::info!(id1, ?error, "delete triple failed"),
            }
            Ok((
                triple1,
                triple2
            ))
        }
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&mut self) -> Option<(Triple, Triple)> {
        if self.mine.len() < 2 {
            return None;
        }
        let id0 = self.mine.pop_front()?;
        let id1 = self.mine.pop_front()?;
        tracing::info!(id0, id1, "trying to take two triples");

        let val = self.take_two(id0, id1).await.ok();
        if val.is_none() {
            tracing::warn!(id0, id1, "my triples are gone");
        }
        val
    }

    /// Ensures that the triple with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`
    // TODO: What if the triple completed generation and is already spent?
    pub fn get_or_generate(
        &mut self,
        id: TripleId,
    ) -> Result<Option<&mut TripleProtocol>, CryptographicError> {
        if self.triples.contains_key(&id) {
            Ok(None)
        } else {
            match self.generators.entry(id) {
                Entry::Vacant(e) => {
                    tracing::debug!(id, "joining protocol to generate a new triple");
                    let protocol = Box::new(cait_sith::triples::generate_triple::<Secp256k1>(
                        &self.participants,
                        self.me,
                        self.threshold,
                    )?);
                    let generator = e.insert(protocol);
                    Ok(Some(generator))
                }
                Entry::Occupied(e) => Ok(Some(e.into_mut())),
            }
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub async fn poke(&mut self) -> Result<Vec<(Participant, TripleMessage)>, ProtocolError> {
        let mut messages = Vec::new();
        let mut result = Ok(());
        let mut async_triples_to_insert = Vec::new();
        self.generators.retain(|id, protocol| {
            loop {
                let action = match protocol.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        result = Err(e);
                        break false;
                    }
                };

                match action {
                    Action::Wait => {
                        tracing::debug!("waiting");
                        // Retain protocol until we are finished
                        break true;
                    }
                    Action::SendMany(data) => {
                        for p in &self.participants {
                            messages.push((
                                *p,
                                TripleMessage {
                                    id: *id,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        TripleMessage {
                            id: *id,
                            epoch: self.epoch,
                            from: self.me,
                            data: data.clone(),
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            id,
                            big_a = ?output.1.big_a.to_base58(),
                            big_b = ?output.1.big_b.to_base58(),
                            big_c = ?output.1.big_c.to_base58(),
                            "completed triple generation"
                        );

                        let triple = Triple {
                            id: *id,
                            share: output.0,
                            public: output.1,
                        };

                        // After creation the triple is assigned to a random node, which is NOT necessarily the one that initiated it's creation
                        let triple_is_mine = {
                            // This is an entirely unpredictable value to all participants because it's a combination of big_c_i
                            // It is the same value across all participants
                            let big_c = triple.public.big_c;

                            // We turn this into a u64 in a way not biased to the structure of the byte serialisation so we hash it
                            // We use Highway Hash because the DefaultHasher doesn't guarantee a consistent output across versions
                            let entropy =
                                HighwayHasher::default().hash64(&big_c.to_bytes()) as usize;

                            let num_participants = self.participants.len();
                            // This has a *tiny* bias towards lower indexed participants, they're up to (1 + num_participants / u64::MAX)^2 times more likely to be selected
                            // This is acceptably small that it will likely never result in a biased selection happening
                            let triple_owner = self.participants[entropy % num_participants];

                            triple_owner == self.me
                        };

                        if triple_is_mine {
                            self.mine.push_back(*id);
                        }

                        self.triples.insert(*id, triple.clone());
                        //runtime.block_on(async {
                            // perform async operations
                        //});
                        async_triples_to_insert.push(triple.clone());
                        // Do not retain the protocol
                        break false;
                    }
                }
            }
        });

        let mut write_lock = self.triple_storage.write().await;
        let account_id = write_lock.account_id().clone();
        for triple in async_triples_to_insert {
            match write_lock.insert(TripleData { account_id: account_id.clone(), triple }).await {
                Ok(()) => println!("successfully inserted triple"),
                Err(error) => println!("failed: {}", error),
            }
        }

        result.map(|_| messages)
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs::OpenOptions, ops::Range};

    use crate::{protocol::message::TripleMessage, storage, gcp::GcpService};
    use cait_sith::protocol::{InitializationError, Participant, ProtocolError};
    use itertools::multiunzip;
    use std::io::prelude::*;

    use super::TripleManager;
    use std::sync::Arc;
    use crate::storage::triple_storage::LockTripleNodeStorageBox;
    use tokio::sync::RwLock;

    struct TestManagers {
        managers: Vec<TripleManager>,
    }

    impl TestManagers {
        async fn new(number: u32) -> Self {
            let range = 0..number;
            // Self::wipe_mailboxes(range.clone());
            let participants: Vec<Participant> = range.clone().map(Participant::from).collect();
            let project_id = Some("pagoda-discovery-platform-dev".to_string());
            let env = "xiangyi-dev".to_string();
            let storage_options = storage::Options{gcp_project_id: project_id.clone(), sk_share_secret_id:Some("multichain-sk-share-dev-0".to_string()), gcp_datastore_url:None, env: Some(env)};
            let gcp_service = GcpService::init(&storage_options).await.unwrap();
            let managers = range.clone()
                .map(|num| {
                    let triple_storage: LockTripleNodeStorageBox = Arc::new(RwLock::new(storage::triple_storage::init(&gcp_service, num.to_string())));
                    TripleManager::new(participants.clone(), Participant::from(num), number as usize, 0, None, triple_storage)
                })
                .collect();
            TestManagers { managers }
        }

        fn generate(&mut self, index: usize) -> Result<(), InitializationError> {
            self.managers[index].generate()
        }

        async fn poke(&mut self, index: usize) -> Result<bool, ProtocolError> {
            let mut quiet = true;
            let messages = self.managers[index].poke().await?;
            for (
                participant,
                ref tm @ TripleMessage {
                    id, from, ref data, ..
                },
            ) in messages
            {
                // Self::debug_mailbox(participant.into(), &tm);
                quiet = false;
                let participant_i: u32 = participant.into();
                let manager = &mut self.managers[participant_i as usize];
                if let Some(protocol) = manager.get_or_generate(id).unwrap() {
                    protocol.message(from, data.to_vec());
                } else {
                    println!("Tried to write to completed mailbox {:?}", tm);
                }
            }
            Ok(quiet)
        }

        #[allow(unused)]
        fn wipe_mailboxes(mailboxes: Range<u32>) {
            for m in mailboxes {
                let mut file = OpenOptions::new()
                    .write(true)
                    .append(false)
                    .create(true)
                    .open(format!("{}.csv", m))
                    .unwrap();
                write!(file, "").unwrap();
            }
        }

        // This allows you to see what each node is recieving and when
        #[allow(unused)]
        fn debug_mailbox(participant: u32, TripleMessage { id, from, data, .. }: &TripleMessage) {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(format!("{}.csv", participant))
                .unwrap();

            writeln!(file, "'{id}, {from:?}, {}", hex::encode(data)).unwrap();
        }

        async fn poke_until_quiet(&mut self) -> Result<(), ProtocolError> {
            loop {
                let mut quiet = true;
                for i in 0..self.managers.len() {
                    let poke = self.poke(i).await?;
                    quiet = quiet && poke;
                }
                if quiet {
                    return Ok(());
                }
            }
        }
    }

    // TODO: This test currently takes 22 seconds on my machine, which is much slower than it should be
    // Improve this before we make more similar tests
    #[test]
    fn happy_triple_generation() {

        const M: usize = 2;
        const N: usize = M + 3;
        // Generate 5 triples
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut tm = TestManagers::new(5).await;
            for _ in 0..M {
                Arc::new(tm.generate(0));
            }
            tm.poke_until_quiet().await.unwrap();
            tm.generate(1).unwrap();
            tm.generate(2).unwrap();
            tm.generate(4).unwrap();
    
            tm.poke_until_quiet().await.unwrap();
    
            let inputs = tm
                .managers
                .into_iter()
                .map(|m| (m.my_len(), m.len(), m.generators, m.triples));
    
            let (my_lens, lens, generators, mut triples): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) =
                multiunzip(inputs);
            
                assert_eq!(
                    my_lens.iter().sum::<usize>(),
                    N,
                    "There should be {N} owned completed triples in total",
                );
        
                for l in lens {
                    assert_eq!(l, N, "All nodes should have {N} completed triples")
                }
            
            // This passes, but we don't have deterministic entropy or enough triples
        // to ensure that it will no coincidentally fail
        // TODO: deterministic entropy for testing
        // assert_ne!(
        //     my_lens,
        //     vec![M, 1, 1, 0, 1],
        //     "The nodes that started the triple don't own it"
        // );

        for g in generators.iter() {
            assert!(g.is_empty(), "There are no triples still being generated")
        }

        assert_ne!(
            triples.len(),
            1,
            "The number of triples is not 1 before deduping"
        );

        triples.dedup_by_key(|kv| {
            kv.iter_mut()
                .map(|(id, triple)| (*id, (triple.id, triple.public.clone())))
                .collect::<HashMap<_, _>>()
        });

        assert_eq!(
            triples.len(),
            1,
            "All triple IDs and public parts are identical"
        )
        });
    }
}

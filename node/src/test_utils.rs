use crate::protocol::contract::primitives::Participants;
use crate::protocol::presignature::GenerationError;
use crate::protocol::triple::{Triple, TripleConfig, TripleId, TripleManager};
use crate::protocol::ParticipantInfo;
use crate::storage::triple_storage::LockTripleNodeStorageBox;
use crate::{gcp::GcpService, protocol::message::TripleMessage, storage};

use cait_sith::protocol::{InitializationError, Participant, ProtocolError};
use std::io::prelude::*;
use std::{collections::HashMap, fs::OpenOptions, ops::Range};

use itertools::multiunzip;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

// Constants to be used for testing.
const STARTING_EPOCH: u64 = 0;
const TRIPLE_CFG: TripleConfig = TripleConfig {
    min_triples: 2,
    max_triples: 10,
    max_concurrent_introduction: 4,
    max_concurrent_generation: 16,
};

struct TestTripleManagers {
    managers: Vec<TripleManager>,
    participants: Participants,
}

impl TestTripleManagers {
    async fn new(num_managers: u32, datastore_url: Option<String>) -> Self {
        let mut participants = Participants::default();
        (0..num_managers)
            .map(Participant::from)
            .for_each(|p| participants.insert(&p, ParticipantInfo::new(p.into())));

        let mut services = Vec::with_capacity(num_managers as usize);
        for num in 0..num_managers {
            let service = if let Some(url) = &datastore_url {
                let account_id = format!("account_{num}.testnet").parse().unwrap();
                let storage_options = storage::Options {
                    gcp_project_id: "triple-test".to_string(),
                    sk_share_secret_id: None,
                    gcp_datastore_url: Some(url.clone()),
                    env: "triple-test".to_string(),
                };
                Some(
                    GcpService::init(&account_id, &storage_options)
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            services.push(service);
        }

        let managers = (0..num_managers)
            .map(|num| {
                let account_id = format!("account_{num}.testnet").parse().unwrap();
                let triple_storage: LockTripleNodeStorageBox = Arc::new(RwLock::new(
                    storage::triple_storage::init(services[num as usize].as_ref(), &account_id),
                ));
                TripleManager::new(
                    Participant::from(num),
                    num_managers as usize,
                    STARTING_EPOCH,
                    &TRIPLE_CFG,
                    vec![],
                    triple_storage,
                    &account_id,
                )
            })
            .collect();
        TestTripleManagers {
            managers,
            participants,
        }
    }

    fn generate(&mut self, index: usize) -> Result<(), InitializationError> {
        self.managers[index].generate(&self.participants)
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
            if let Some(protocol) = manager.get_or_generate(id, &self.participants).unwrap() {
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

    async fn take_two(
        &mut self,
        index: usize,
        triple_id0: u64,
        triple_id1: u64,
    ) -> Result<(Triple, Triple), GenerationError> {
        self.managers[index].take_two(triple_id0, triple_id1).await
    }

    fn triples(&self, index: usize) -> HashMap<TripleId, Triple> {
        self.managers[index].triples.clone()
    }

    fn mine(&self, index: usize) -> VecDeque<TripleId> {
        self.managers[index].mine.clone()
    }

    fn triple_storage(&self, index: usize) -> LockTripleNodeStorageBox {
        self.managers[index].triple_storage.clone()
    }
}

pub async fn test_triple_generation(datastore_url: Option<String>) {
    const M: usize = 2;
    const N: usize = M + 3;
    // Generate 5 triples
    let mut tm = TestTripleManagers::new(5, datastore_url).await;
    for _ in 0..M {
        tm.generate(0).unwrap();
    }
    tm.poke_until_quiet().await.unwrap();

    tm.generate(1).unwrap();
    tm.generate(2).unwrap();
    tm.generate(4).unwrap();

    tm.poke_until_quiet().await.unwrap();

    let inputs = tm.managers.into_iter().map(|m| {
        (
            m.my_len(),
            m.len(),
            m.generators,
            m.triples,
            m.triple_storage,
            m.mine,
        )
    });

    let (my_lens, lens, generators, mut triples, triple_stores, mines): (
        Vec<_>,
        Vec<_>,
        Vec<_>,
        Vec<_>,
        Vec<_>,
        Vec<_>,
    ) = multiunzip(inputs);

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

    // validates that the triples loaded from triple_storage is the same as the ones generated
    for i in 0..triples.len() {
        let local_mine = mines.get(i).unwrap();
        let local_triples = triples.get(i).unwrap();
        let triple_store = triple_stores.get(i).unwrap();

        let datastore_loaded_triples = {
            let triple_store = triple_store.read().await;
            let datastore_loaded_triples = triple_store
                .load()
                .await
                .expect("the triple loading result should return Ok");
            assert_eq!(
                datastore_loaded_triples.len(),
                local_triples.len(),
                "the number of triples loaded from datastore and stored locally should match"
            );
            datastore_loaded_triples
        };

        for loaded_triple_data in datastore_loaded_triples {
            let loaded_triple = loaded_triple_data.triple;
            assert!(
                local_triples.contains_key(&loaded_triple.id),
                "the loaded triple id should exist locally"
            );
            let local_triple = local_triples.get(&loaded_triple.id).unwrap();
            assert_eq!(
                local_triple.public, loaded_triple.public,
                "local and datastore loaded triple should have same public field value."
            );
            assert_eq!(
                local_triple.share.a, loaded_triple.share.a,
                "local and datastore loaded triple should have same share.a value."
            );
            assert_eq!(
                local_triple.share.b, loaded_triple.share.b,
                "local and datastore loaded triple should have same share.b value."
            );
            assert_eq!(
                local_triple.share.c, loaded_triple.share.c,
                "local and datastore loaded triple should have same share.c value."
            );
            assert_eq!(
                local_mine.contains(&loaded_triple.id),
                loaded_triple_data.mine,
                "local and datastore loaded triple should have same mine value."
            );
        }
    }

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
}

pub async fn test_triple_deletion(datastore_url: Option<String>) {
    // Generate 3 triples
    let mut tm = TestTripleManagers::new(2, datastore_url).await;
    for _ in 0..3 {
        tm.generate(0).unwrap();
    }
    tm.poke_until_quiet().await.unwrap();

    for i in 0..2 {
        let mut mine = tm.mine(i);
        if mine.len() < 2 {
            continue;
        }
        let id0 = mine.pop_front().unwrap();
        let id1 = mine.pop_front().unwrap();
        let triples = tm.triples(i);
        assert_eq!(triples.len(), 3);
        let triple0 = triples.get(&id0).unwrap();
        assert!(
            tm.take_two(i, id0, id1).await.is_ok(),
            "take_two for participant 0 should succeed for id0 and id1"
        );

        let triple_storage = tm.triple_storage(i);
        {
            let triple_storage = triple_storage.read().await;
            let loaded_triples = triple_storage
                .load()
                .await
                .expect("expected triples to load successfully");
            assert_eq!(
                loaded_triples.len(),
                1,
                "the triples left in store for participant 0 should be 1"
            );
        }

        //verify that if in take_two, one of the triples were accidentally deleted, double deletion will not cause issue
        {
            let mut triple_storage = triple_storage.write().await;
            let del_res_mine_false = triple_storage.delete(triple0.id).await;
            let del_res_mine_true = triple_storage.delete(triple0.id).await;
            assert!(
                del_res_mine_false.is_ok() && del_res_mine_true.is_ok(),
                "repeatedly deleting a triple won't err out"
            );
        };

        {
            let triple_storage = triple_storage.read().await;
            let loaded_triples = triple_storage
                .load()
                .await
                .expect("expected to be able to load recently added triple");
            assert_eq!(
                loaded_triples.len(),
                1,
                "the triples left in store for participant 0 should still be 1"
            );
        }

        //insert triple0 and delete it with the wrong mine value, that does not impact deletion success
        {
            let mut triple_storage = triple_storage.write().await;
            triple_storage
                .insert(triple0.clone(), true)
                .await
                .expect("expected insert to succeed");
            triple_storage
                .delete(triple0.id)
                .await
                .expect("expected delete to succeed");
        }

        {
            let triple_storage = triple_storage.read().await;
            let loaded = triple_storage
                .load()
                .await
                .expect("expected to be able to load at least one triple");
            assert_eq!(
                loaded.len(),
                1,
                "the triples left in store for participant 0 should still be 1"
            );
        }
    }
}

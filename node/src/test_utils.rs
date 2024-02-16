use std::{collections::HashMap, fs::OpenOptions, ops::Range};

use crate::{gcp::GcpService, protocol::message::TripleMessage, storage};
use cait_sith::protocol::{InitializationError, Participant, ProtocolError};
use std::io::prelude::*;

use crate::protocol::presignature::GenerationError;
use crate::protocol::triple::Triple;
use crate::protocol::triple::TripleId;
use crate::protocol::triple::TripleManager;
use crate::storage::triple_storage::LockTripleNodeStorageBox;
use crate::storage::triple_storage::TripleData;
use itertools::multiunzip;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

struct TestTripleManagers {
    managers: Vec<TripleManager>,
}

impl TestTripleManagers {
    async fn new(num_managers: u32, datastore_url: Option<String>) -> Self {
        let range = 0..num_managers;
        let participants: Vec<Participant> = range.clone().map(Participant::from).collect();
        let gcp_service = if let Some(url) = datastore_url {
            let storage_options = storage::Options {
                gcp_project_id: Some("triple-test".to_string()),
                sk_share_secret_id: None,
                gcp_datastore_url: Some(url),
                env: Some("triple-test".to_string()),
            };
            GcpService::init(&storage_options).await.unwrap()
        } else {
            None
        };

        let managers = range
            .clone()
            .map(|num| {
                let triple_storage: LockTripleNodeStorageBox = Arc::new(RwLock::new(
                    storage::triple_storage::init(&gcp_service, num.to_string()),
                ));
                TripleManager::new(
                    participants.clone(),
                    Participant::from(num),
                    num_managers as usize,
                    0,
                    vec![],
                    triple_storage,
                )
            })
            .collect();
        TestTripleManagers { managers }
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

    async fn take_two(
        &mut self,
        index: usize,
        triple_id0: u64,
        triple_id1: u64,
        mine: bool,
    ) -> Result<(Triple, Triple), GenerationError> {
        self.managers[index]
            .take_two(triple_id0, triple_id1, mine)
            .await
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
        Arc::new(tm.generate(0));
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
        let triple_read_lock = triple_store.read().await;
        let datastore_loaded_triples_res = triple_read_lock.load().await;
        drop(triple_read_lock);
        assert!(
            datastore_loaded_triples_res.is_ok(),
            "the triple loading result should return Ok"
        );
        let datastore_loaded_triples = datastore_loaded_triples_res.ok().unwrap();
        assert_eq!(
            datastore_loaded_triples.len(),
            local_triples.len(),
            "the number of triples loaded from datastore and stored locally should match"
        );
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
        Arc::new(tm.generate(0));
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
            tm.take_two(i, id0, id1, true).await.is_ok(),
            "take_two for participant 0 should succeed for id0 and id1"
        );

        let triple_storage = tm.triple_storage(i);
        let read_lock = triple_storage.read().await;
        let loaded_triples_res = read_lock.load().await;
        drop(read_lock);
        assert!(loaded_triples_res.is_ok());
        let loaded_triples = loaded_triples_res.unwrap();
        assert_eq!(
            loaded_triples.len(),
            1,
            "the triples left in store for participant 0 should be 1"
        );

        //verify that if in take_two, one of the triples were accidentally deleted, double deletion will not cause issue
        let mut write_lock = triple_storage.write().await;
        let del_res_mine_false = write_lock
            .delete(TripleData {
                account_id: "0".to_string(),
                triple: triple0.clone(),
                mine: false,
            })
            .await;
        let del_res_mine_true = write_lock
            .delete(TripleData {
                account_id: "0".to_string(),
                triple: triple0.clone(),
                mine: true,
            })
            .await;
        drop(write_lock);
        assert!(
            del_res_mine_false.is_ok() && del_res_mine_true.is_ok(),
            "repeatedly deleting a triple won't err out"
        );
        let read_lock = triple_storage.read().await;
        let loaded_triples_res = read_lock.load().await;
        drop(read_lock);
        assert!(loaded_triples_res.is_ok());
        let loaded_triples = loaded_triples_res.unwrap();
        assert!(
            loaded_triples.len() == 1,
            "the triples left in store for participant 0 should still be 1"
        );

        //insert triple0 and delete it with the wrong mine value, that does not impact deletion success
        let mut write_lock = triple_storage.write().await;
        let _insert_result = write_lock
            .insert(TripleData {
                account_id: "0".to_string(),
                triple: triple0.clone(),
                mine: true,
            })
            .await;
        let _del_res_mine_false = write_lock
            .delete(TripleData {
                account_id: "0".to_string(),
                triple: triple0.clone(),
                mine: false,
            })
            .await;
        drop(write_lock);
        let read_lock = triple_storage.read().await;
        let loaded_triples_res = read_lock.load().await;
        drop(read_lock);
        assert!(
            loaded_triples_res.unwrap().len() == 1,
            "the triples left in store for participant 0 should still be 1"
        );
    }
}

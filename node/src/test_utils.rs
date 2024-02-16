
use std::{collections::HashMap, fs::OpenOptions, ops::Range};

use crate::{gcp::GcpService, protocol::message::TripleMessage, storage};
use cait_sith::protocol::{InitializationError, Participant, ProtocolError};
use std::io::prelude::*;

use crate::protocol::triple::TripleManager;
use crate::storage::triple_storage::LockTripleNodeStorageBox;
use std::sync::Arc;
use tokio::sync::RwLock;
use itertools::multiunzip;

struct TestManagers {
    managers: Vec<TripleManager>,
}

impl TestManagers {
    async fn new(number: u32, datastore_url: Option<String>) -> Self {
        let range = 0..number;
        // Self::wipe_mailboxes(range.clone());
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
            .map(|num| {
                let triple_storage: LockTripleNodeStorageBox = Arc::new(RwLock::new(
                    storage::triple_storage::init(&gcp_service, num.to_string()),
                ));
                TripleManager::new(
                    participants.clone(),
                    Participant::from(num),
                    number as usize,
                    0,
                    vec![],
                    triple_storage,
                )
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

pub async fn happy_triple_generation(datastore_url: Option<String>) {
    const M: usize = 2;
    const N: usize = M + 3;
    // Generate 5 triples
    let mut tm = TestManagers::new(5, datastore_url).await;
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
        )
    });

    let (my_lens, lens, generators, mut triples, triple_stores): (
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
        let local_triples = triples.get(i).unwrap();
        let triple_store = triple_stores.get(i).unwrap();
        let triple_read_lock = triple_store.read().await;
        let datastore_loaded_triples_res = triple_read_lock.load().await;
        assert!(datastore_loaded_triples_res.is_ok(), "the triple loading result should return Ok");
        let datastore_loaded_triples = datastore_loaded_triples_res.ok().unwrap();
        assert_eq!(datastore_loaded_triples.len(), local_triples.len(), "the number of triples loaded from datastore and stored locally should match");
        for loaded_triple in datastore_loaded_triples {
            assert!(local_triples.contains_key(&loaded_triple.triple.id), "the loaded triple id should exist locally");
            let local_triple = local_triples.get(&loaded_triple.triple.id).unwrap();
            assert_eq!(local_triple.public, loaded_triple.triple.public, "local and datastore loaded triple should have same public field value.");
            assert_eq!(local_triple.share.a, local_triple.share.a, "local and datastore loaded triple should have same share.a value.");
            assert_eq!(local_triple.share.b, local_triple.share.b, "local and datastore loaded triple should have same share.b value.");
            assert_eq!(local_triple.share.c, local_triple.share.c, "local and datastore loaded triple should have same share.c value.");
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

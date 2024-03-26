pub mod actions;

use crate::with_multichain_nodes;
use actions::wait_for;
use k256::elliptic_curve::point::AffineCoordinates;
use mpc_recovery_integration_tests::env::containers::DockerClient;
use mpc_recovery_integration_tests::multichain::MultichainConfig;
use mpc_recovery_node::kdf::{self, x_coordinate};
use mpc_recovery_node::protocol::presignature::PresignatureConfig;
use mpc_recovery_node::protocol::triple::TripleConfig;
use mpc_recovery_node::test_utils;
use mpc_recovery_node::types::LatestBlockHeight;
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use near_workspaces::Account;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let new_node_account = ctx.nodes.ctx().worker.dev_create_account().await?;

            ctx.nodes
                .start_node(
                    new_node_account.id(),
                    new_node_account.secret_key(),
                    &ctx.cfg,
                )
                .await?;

            // Wait for new node to add itself as a candidate
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            let participant_accounts: Vec<Account> = ctx
                .nodes
                .near_acc_sk()
                .iter()
                .map(|(account_id, account_sk)| {
                    Account::from_secret_key(
                        account_id.clone(),
                        account_sk.clone(),
                        &ctx.nodes.ctx().worker,
                    )
                })
                .filter(|account| account.id() != new_node_account.id())
                .collect();

            // vote for new node
            let vote_futures = participant_accounts
                .iter()
                .map(|account| {
                    let result = account
                        .call(ctx.nodes.ctx().mpc_contract.id(), "vote_join")
                        .args_json(serde_json::json!({
                            "candidate_account_id": new_node_account.id()
                        }))
                        .transact();
                    result
                })
                .collect::<Vec<_>>();

            futures::future::join_all(vote_futures).await;

            let state_1 = wait_for::running_mpc(&ctx, 1).await?;
            assert_eq!(state_1.participants.len(), 4);

            assert_eq!(
                state_0.public_key, state_1.public_key,
                "public key must stay the same"
            );

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_and_presignatures() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_basic() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state_0).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_offline_node() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 4).await?;

            // Kill the node then have presignature and signature generation only use the active set of nodes
            // to start generating presignatures and signatures.
            ctx.nodes.kill_node(2).await?;

            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state_0).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
#[ignore = "This test is too slow to run in CI"]
async fn test_signature_large_stockpile() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 10;
    const NODES: usize = 8;
    const THRESHOLD: usize = 4;
    const MIN_TRIPLES: usize = 10;
    const MAX_TRIPLES: usize = 2 * NODES * MIN_TRIPLES;

    let triple_cfg = TripleConfig {
        // This is the min triples required by each node.
        min_triples: MIN_TRIPLES,
        // This is the total amount of triples that will be generated by all nodes.
        max_triples: MAX_TRIPLES,
        // This is the amount each node can introduce a triple generation protocol into the system.
        max_concurrent_introduction: 4,
        // This is the maximum amount of triples that can be generated concurrently by the whole system.
        max_concurrent_generation: 24,
    };
    let presig_cfg = PresignatureConfig {
        // this is the min presignatures required by each node
        min_presignatures: 10,
        // This is the total amount of presignatures that will be generated by all nodes.
        max_presignatures: 1000,
    };

    let config = MultichainConfig {
        triple_cfg,
        presig_cfg,
        nodes: NODES,
        threshold: THRESHOLD,
    };

    with_multichain_nodes(config, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), NODES);
            wait_for::has_at_least_triples(&ctx, triple_cfg.min_triples).await?;
            wait_for::has_at_least_presignatures(&ctx, SIGNATURE_AMOUNT).await?;

            for _ in 0..SIGNATURE_AMOUNT {
                actions::single_signature_production(&ctx, &state_0).await?;
            }
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_key_derivation() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_presignatures(&ctx, 3).await?;

            for _ in 0..3 {
                let mpc_pk: k256::AffinePoint = state_0.public_key.clone().into_affine_point();
                let (_, payload_hashed, account, tx_hash) = actions::request_sign(&ctx).await?;
                let payload_hashed_rev = {
                    let mut rev = payload_hashed;
                    rev.reverse();
                    rev
                };
                let sig = wait_for::signature_responded(&ctx, tx_hash).await?;

                let hd_path = "test";
                let derivation_epsilon = kdf::derive_epsilon(account.id(), hd_path);
                let user_pk = kdf::derive_key(mpc_pk, derivation_epsilon);
                let multichain_sig =
                    kdf::into_eth_sig(&user_pk, &sig, k256::Scalar::from_bytes(&payload_hashed))
                        .unwrap();

                // start recovering the address and compare them:
                let user_pk_x = kdf::x_coordinate::<k256::Secp256k1>(&user_pk);
                let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
                    1 => secp256k1::Parity::Odd,
                    0 => secp256k1::Parity::Even,
                    _ => unreachable!(),
                };
                let user_pk_x =
                    secp256k1::XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
                let user_secp_pk =
                    secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
                let user_addr = actions::public_key_to_address(&user_secp_pk);
                let r = x_coordinate::<k256::Secp256k1>(&multichain_sig.big_r);
                let s = multichain_sig.s;
                let signature_for_recovery: [u8; 64] = {
                    let mut signature = [0u8; 64];
                    signature[..32].copy_from_slice(&r.to_bytes());
                    signature[32..].copy_from_slice(&s.to_bytes());
                    signature
                };
                let recovered_addr = web3::signing::recover(
                    &payload_hashed_rev,
                    &signature_for_recovery,
                    multichain_sig.recovery_id as i32,
                )
                .unwrap();
                assert_eq!(user_addr, recovered_addr);
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_persistence_for_generation() -> anyhow::Result<()> {
    let docker_client = DockerClient::default();
    let gcp_project_id = "test-triple-persistence";
    let docker_network = "test-triple-persistence";
    docker_client.create_network(docker_network).await?;
    let datastore =
        crate::env::containers::Datastore::run(&docker_client, docker_network, gcp_project_id)
            .await?;
    let datastore_url = datastore.local_address.clone();
    // verifies that @triple generation, the datastore triples are in sync with local generated triples
    test_utils::test_triple_generation(Some(datastore_url.clone())).await;
    Ok(())
}

#[test(tokio::test)]
async fn test_triples_persistence_for_deletion() -> anyhow::Result<()> {
    let docker_client = DockerClient::default();
    let gcp_project_id = "test-triple-persistence";
    let docker_network = "test-triple-persistence";
    docker_client.create_network(docker_network).await?;
    let datastore =
        crate::env::containers::Datastore::run(&docker_client, docker_network, gcp_project_id)
            .await?;
    let datastore_url = datastore.local_address.clone();
    // verifies that @triple deletion, the datastore is working as expected
    test_utils::test_triple_deletion(Some(datastore_url)).await;
    Ok(())
}

#[test(tokio::test)]
async fn test_latest_block_height() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            let gcp_services = ctx.nodes.gcp_services().await?;
            for gcp_service in &gcp_services {
                let latest = LatestBlockHeight::fetch(gcp_service).await?;
                assert!(latest.block_height > 10);
            }

            // test manually updating the latest block height
            let gcp_service = gcp_services[0].clone();
            let latest = LatestBlockHeight {
                account_id: gcp_service.account_id.to_string(),
                block_height: 1000,
            };
            latest.store(&gcp_service).await?;
            let new_latest = LatestBlockHeight::fetch(&gcp_service).await?;
            assert_eq!(new_latest.block_height, latest.block_height);

            Ok(())
        })
    })
    .await
}

pub mod actions;

use crate::with_multichain_nodes;
use actions::wait_for;
use k256::elliptic_curve::point::AffineCoordinates;
use mpc_recovery_integration_tests::env::containers::DockerClient;
use mpc_recovery_integration_tests::multichain::MultichainConfig;
use mpc_recovery_node::kdf::{self, x_coordinate};
use mpc_recovery_node::test_utils;
use mpc_recovery_node::types::LatestBlockHeight;
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(account.id(), account.secret_key(), ctx.cfg.triple_stockpile)
                .await?;

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
async fn test_signature() -> anyhow::Result<()> {
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
async fn test_key_derivation() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            for _ in 0..5 {
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

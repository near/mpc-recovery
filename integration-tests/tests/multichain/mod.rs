pub mod actions;

use crate::with_multichain_nodes;
use actions::wait_for;
use mpc_recovery_integration_tests::env::containers::DockerClient;
use mpc_recovery_node::test_utils;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(account.id(), account.secret_key())
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
    with_multichain_nodes(3, |ctx| {
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
    with_multichain_nodes(3, |ctx| {
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

use crate::{wait_for, with_multichain_nodes};
use mpc_recovery_integration_tests::containers;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| async move {
        // Wait for network to complete key generation
        let state_0 = wait_for::running_mpc(&ctx, 0).await?;
        assert_eq!(state_0.participants.len(), 3);

        let docker_client = containers::DockerClient::default();
        let account = ctx.worker.dev_create_account().await?;
        let node = containers::Node::run(
            &docker_client,
            crate::NETWORK,
            3,
            &ctx.near_rpc,
            ctx.mpc_contract.id(),
            account.id(),
            account.secret_key(),
        )
        .await?;

        // Wait for network to complete key reshare
        let state_1 = wait_for::running_mpc(&ctx, 1).await?;
        assert_eq!(state_1.participants.len(), 4);

        assert_eq!(
            state_0.public_key, state_1.public_key,
            "public key must stay the same"
        );

        drop(node);

        Ok(())
    })
    .await
}

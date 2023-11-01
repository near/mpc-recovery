use crate::{wait_for, with_multichain_nodes};
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |mut ctx| {
        Box::pin(async move {
            // Wait for network to complete key generation
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(3, account.id(), account.secret_key())
                .await?;

            // Wait for network to complete key reshare
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
async fn test_triples() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            wait_for::has_at_least_triples(&ctx, 0, 2).await?;

            Ok(())
        })
    })
    .await
}

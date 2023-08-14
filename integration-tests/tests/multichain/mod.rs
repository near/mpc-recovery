use std::time::Duration;

use test_log::test;

use crate::with_multichain_nodes;

#[test(tokio::test)]
async fn test_basic_multichain() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(100)).await;

            Ok(())
        })
    })
    .await
}

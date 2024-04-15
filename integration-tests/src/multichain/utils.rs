use near_workspaces::{result::ExecutionFinalResult, Account, AccountId};

pub async fn vote_join(
    accounts: Vec<Account>,
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> anyhow::Result<()> {
    let vote_futures = accounts
        .iter()
        .map(|account| {
            tracing::info!(
                "{} voting for new participant: {}",
                account.id(),
                account_id
            );
            account
                .call(mpc_contract, "vote_join")
                .args_json(serde_json::json!({
                    "candidate_account_id": account_id
                }))
                .transact()
        })
        .collect::<Vec<_>>();

    futures::future::join_all(vote_futures)
        .await
        .iter()
        .for_each(|result| {
            assert!(result.as_ref().unwrap().failures().is_empty());
        });

    Ok(())
}

pub async fn vote_leave(
    accounts: Vec<Account>,
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> Vec<Result<ExecutionFinalResult, near_workspaces::error::Error>> {
    let vote_futures = accounts
        .iter()
        .filter(|account| account.id() != account_id)
        .map(|account| {
            account
                .call(mpc_contract, "vote_leave")
                .args_json(serde_json::json!({
                    "kick": account_id
                }))
                .transact()
        })
        .collect::<Vec<_>>();

    futures::future::join_all(vote_futures).await
}

use near_workspaces::{result::ExecutionFinalResult, Account, AccountId};

pub async fn vote_join(
    accounts: &Vec<Account>,
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> anyhow::Result<()> {
    let vote_futures = accounts
        .iter()
        .map(|account| {
            let result = account
                .call(&mpc_contract, "vote_join")
                .args_json(serde_json::json!({
                    "candidate_account_id": account_id
                }))
                .transact();
            result
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
    accounts: &Vec<Account>,
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> Vec<Result<ExecutionFinalResult, near_workspaces::error::Error>> {
    let vote_futures = accounts
        .iter()
        .filter(|account| account.id() != account_id)
        .map(|account| {
            let result = account
                .call(mpc_contract, "vote_leave")
                .args_json(serde_json::json!({
                    "acc_id_to_leave": account_id
                }))
                .transact();
            result
        })
        .collect::<Vec<_>>();

    futures::future::join_all(vote_futures).await
}

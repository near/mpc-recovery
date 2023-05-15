use workspaces::{network::Sandbox, AccountId, Contract, Worker};

pub async fn initialize_social_db(worker: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    let social_db = worker
        .import_contract(&"social.near".parse()?, &workspaces::mainnet().await?)
        .transact()
        .await?;
    social_db
        .call("new")
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(social_db)
}

// Linkdrop contains top-level account creation logic
pub async fn initialize_linkdrop(worker: &Worker<Sandbox>) -> anyhow::Result<()> {
    let near_root_account = worker.root_account()?;
    near_root_account
        .deploy(include_bytes!("../../linkdrop.wasm"))
        .await?
        .into_result()?;
    near_root_account
        .call(near_root_account.id(), "new")
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(())
}

pub async fn create_account(
    worker: &Worker<Sandbox>,
) -> anyhow::Result<(AccountId, near_crypto::SecretKey)> {
    let (account_id, account_sk) = worker.dev_generate().await;
    worker
        .create_tla(account_id.clone(), account_sk.clone())
        .await?
        .into_result()?;

    let account_sk: near_crypto::SecretKey =
        serde_json::from_str(&serde_json::to_string(&account_sk)?)?;

    Ok((account_id, account_sk))
}

// Makes sure that the target account has at least target amount of NEAR
pub async fn up_funds_for_account(
    worker: &Worker<Sandbox>,
    target_account_id: &AccountId,
    target_amount: u128,
) -> anyhow::Result<()> {
    // Max balance we can transfer out of a freshly created dev account
    const DEV_ACCOUNT_AVAILABLE_BALANCE: u128 = 99 * 10u128.pow(24);

    let diff: u128 = target_amount - worker.view_account(target_account_id).await?.balance;
    // Integer ceiling division
    let n = (diff + DEV_ACCOUNT_AVAILABLE_BALANCE - 1) / DEV_ACCOUNT_AVAILABLE_BALANCE;
    let futures = (0..n).map(|_| async {
        let tmp_account = worker.dev_create_account().await?;
        tmp_account
            .transfer_near(target_account_id, DEV_ACCOUNT_AVAILABLE_BALANCE)
            .await?
            .into_result()?;
        tmp_account
            .delete_account(target_account_id)
            .await?
            .into_result()?;

        Ok::<(), anyhow::Error>(())
    });
    futures::future::join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}

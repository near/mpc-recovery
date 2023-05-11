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
    while worker.view_account(target_account_id).await?.balance < target_amount {
        let tmp_account = worker.dev_create_account().await?;
        tmp_account
            .transfer_near(target_account_id, 99 * 10u128.pow(24))
            .await?
            .into_result()?;
        tmp_account
            .delete_account(target_account_id)
            .await?
            .into_result()?;
    }
    Ok(())
}

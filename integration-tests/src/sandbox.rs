use workspaces::{network::Sandbox, Account, Contract, Worker};

pub async fn initialize_social_db(worker: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    tracing::info!("Initializing social DB contract...");
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

    tracing::info!("Social DB contract initialized");
    Ok(social_db)
}

// Linkdrop contains top-level account creation logic
pub async fn initialize_linkdrop(worker: &Worker<Sandbox>) -> anyhow::Result<()> {
    tracing::info!("Initializing linkdrop contract...");
    let near_root_account = worker.root_account()?;
    near_root_account
        .deploy(include_bytes!("../linkdrop.wasm"))
        .await?
        .into_result()?;
    near_root_account
        .call(near_root_account.id(), "new")
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    tracing::info!("Linkdrop contract initialized");
    Ok(())
}

pub async fn create_account(
    worker: &Worker<Sandbox>,
    prefix: &str,
    initial_balance: u128,
) -> anyhow::Result<Account> {
    tracing::info!("Creating account with random account_id...");
    let new_account = worker
        .root_account()?
        .create_subaccount(prefix)
        .initial_balance(initial_balance)
        .transact()
        .await?
        .into_result()?;

    tracing::info!("Account created: {}", new_account.id());
    Ok(new_account)
}

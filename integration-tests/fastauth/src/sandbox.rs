use near_workspaces::types::NearToken;
use near_workspaces::{network::Sandbox, types::SecretKey, AccessKey, Account, Contract, Worker};

const BATCH_COUNT_LIMIT: usize = 100;

pub async fn initialize_social_db(worker: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    tracing::info!("Initializing social DB contract...");
    let social_db = worker
        .import_contract(&"social.near".parse()?, &near_workspaces::mainnet().await?)
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

// Linkdrop contract contains top-level account creation logic.
pub async fn initialize_linkdrop(worker: &Worker<Sandbox>) -> anyhow::Result<()> {
    tracing::info!("Initializing linkdrop contract...");
    let near_root_account = worker.root_account()?;
    near_root_account
        .deploy(include_bytes!("../res/linkdrop.wasm"))
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
    initial_balance: NearToken,
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

pub async fn gen_rotating_keys(account: &Account, amount: usize) -> anyhow::Result<Vec<SecretKey>> {
    let mut keys = Vec::with_capacity(amount + 1);
    keys.push(account.secret_key().clone());

    // Each batch transaction has a limit of BATCH_COUNT_LIMIT actions.
    let num_batches = amount / BATCH_COUNT_LIMIT + 1;
    let rem_batches = amount % BATCH_COUNT_LIMIT;
    let batch_counts = (0..num_batches).map(|i| {
        if i == num_batches - 1 {
            rem_batches
        } else {
            BATCH_COUNT_LIMIT
        }
    });

    for batch_count in batch_counts {
        let mut batch_tx = account.batch(account.id());
        for _ in 0..batch_count {
            let sk = SecretKey::from_seed(
                near_workspaces::types::KeyType::ED25519,
                &rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
                    .take(10)
                    .map(char::from)
                    .collect::<String>(),
            );
            batch_tx = batch_tx.add_key(sk.public_key(), AccessKey::full_access());
            keys.push(sk);
        }
        batch_tx.transact().await?.into_result()?;
    }

    Ok(keys)
}

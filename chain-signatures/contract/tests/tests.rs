use mpc_contract::primitives::CandidateInfo;
use near_workspaces::AccountId;
use std::collections::HashMap;

const CONTRACT_FILE_PATH: &str = "../../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

#[tokio::test]
async fn test_contract_can_not_be_reinitialized() -> anyhow::Result<()> {

    //let worker = near_workspaces::sandbox_with_builder_and_version(network_builder, "3f684fdc1d972f352ec6a1bf8d1e78b1b5a124b3").await?;
    let worker = near_workspaces::sandbox().await?;
    let wasm = std::fs::read(CONTRACT_FILE_PATH)?;
    let contract = worker.dev_deploy(&wasm).await?;

    let candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();

    let result1 = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": candidates,
            "contract_version": 1
        }))
        .transact()
        .await?;

    println!("{result1:?}");
    assert!(result1.is_success());

    let result2 = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": candidates
        }))
        .transact()
        .await?;

    assert!(result2.is_failure());

    Ok(())
}
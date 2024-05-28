use mpc_contract::{primitives::CandidateInfo, MpcContract, VersionedMpcContract};
use near_sdk::env;
use near_workspaces::AccountId;
use std::collections::{BTreeMap, HashMap};

const CONTRACT_FILE_PATH: &str = "../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

#[tokio::test]
async fn test_contract_can_not_be_reinitialized() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let wasm = std::fs::read(CONTRACT_FILE_PATH)?;
    let contract = worker.dev_deploy(&wasm).await?;

    let candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();

    let result1 = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": candidates
        }))
        .transact()
        .await?;

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

#[test]
fn test_old_state_can_be_migrated_to_v0() -> anyhow::Result<()> {
    let old_contract = MpcContract::init(3, BTreeMap::new());
    env::state_write(&old_contract);

    let v0_contract = VersionedMpcContract::migrate_state_old_to_v0();
    let expected_contract = VersionedMpcContract::V0(old_contract);

    assert_eq!(
        format!("{v0_contract:#?}"),
        format!("{expected_contract:#?}")
    );

    Ok(())
}

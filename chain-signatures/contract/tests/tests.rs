use mpc_contract::{primitives::{CandidateInfo, SignRequest}, SignatureRequest};
use near_workspaces::AccountId;
use std::collections::HashMap;
use near_gas::NearGas;
use near_workspaces::types::NearToken;

const CONTRACT_FILE_PATH: &str = "../../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

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

#[tokio::test]
async fn test_contract_sign_respond_work_for_v1() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let wasm = std::fs::read(CONTRACT_FILE_PATH)?;
    let contract = worker.dev_deploy(&wasm).await?;

    let candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();

    let result1 = contract
        .call("init_running")
        .args_json(serde_json::json!({
            "threshold": 2,
            "participants": candidates,
            "epoch": 0,
            "public_key": "secp256k1:54hU5wcCmVUPFWLDALXMh1fFToZsVXrx9BbTbHzSfQq1Kd1rJZi52iPa4QQxo6s5TgjWqgpY8HamYuUDzG6fAaUq"

        }))
        .transact()
        .await?;

    assert!(result1.is_success());

    let signature_request = SignatureRequest::new(
        [12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 38],
        contract.id(),
        "test"
    );

    let sign_tx_status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "payload":[12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 38], "path": "test", "key_version": 0
        }))
        .gas(NearGas::from_tgas(300))
        .deposit(NearToken::from_yoctonear(30))
        .transact_async()
        .await?;

    std::thread::sleep(std::time::Duration::from_secs(2));
    let respond_result = contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": signature_request,
            "response": "signature"
        }))
        .gas(NearGas::from_tgas(300))
        .transact()
        .await?;

    assert!(respond_result.is_success());

    std::thread::sleep(std::time::Duration::from_secs(2));
    let sign_result = sign_tx_status.await?;

    println!("{sign_result:?}");

    assert!(sign_result.is_success());

    Ok(())
}
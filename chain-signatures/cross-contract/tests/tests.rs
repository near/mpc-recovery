use mpc_contract::{primitives::{CandidateInfo, SignRequest}, SignatureRequest};
use near_workspaces::AccountId;
use std::collections::HashMap;
use near_gas::NearGas;
use near_workspaces::types::NearToken;

const MPC_CONTRACT_FILE_PATH: &str = "../../target/wasm32-unknown-unknown/release/mpc_contract.wasm";
const CROSS_CONTRACT_FILE_PATH: &str = "/Users/xiangyiz/workspace/near/mpc-recovery/chain-signatures/cross-contract/target/wasm32-unknown-unknown/release/cross_contract.wasm";

#[tokio::test]
async fn test_contract_sign_respond_work_for_v1() -> anyhow::Result<()> {

    std::env::set_var("NEAR_SANDBOX_BIN_PATH", "/Users/xiangyiz/.near/near-sandbox-1.40.0/near-sandbox");
    let worker = near_workspaces::sandbox().await?;

    // Deploy mpc contract
    let mpc_contract_wasm = std::fs::read(MPC_CONTRACT_FILE_PATH)?;
    let mpc_contract = worker.dev_deploy(&mpc_contract_wasm).await?;
    // Deploy contract for testing
    let contract_wasm = std::fs::read(CROSS_CONTRACT_FILE_PATH)?;
    let contract = worker.dev_deploy(&contract_wasm).await?;

    let candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();

    let result1 = mpc_contract
        .call("init_running")
        .args_json(serde_json::json!({
            "threshold": 2,
            "participants": candidates,
            "contract_version": "V1",
            "epoch": 0,
            "public_key": "secp256k1:54hU5wcCmVUPFWLDALXMh1fFToZsVXrx9BbTbHzSfQq1Kd1rJZi52iPa4QQxo6s5TgjWqgpY8HamYuUDzG6fAaUq"

        }))
        .transact()
        .await?;

    assert!(result1.is_success());

    let result_init_2 = contract
        .call("init")
        .args_json(serde_json::json!({ "mpc_account": mpc_contract.id() }))
        .transact()
        .await?;

    //println!("{result_init_2:?}");
    assert!(result_init_2.is_success());

    let predecessor = contract.id();
    let signature_request = SignatureRequest::new(
        [12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 38],
        predecessor,
        "test"
    );

    let sign_tx_status = contract
        .call("sign")
        .args_json(serde_json::json!(
            {"payload":[12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 38], "path": "test", "key_version": 0}
        ))
        .gas(NearGas::from_tgas(300))
        .deposit(NearToken::from_yoctonear(30))
        .transact_async()
        .await?;

    std::thread::sleep(std::time::Duration::from_secs(10));
    let respond_result = mpc_contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": signature_request,
            "response": "lalala"
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
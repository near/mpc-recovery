#[cfg(test)]
mod tests {
    use crate::primitives::CandidateInfo;
    use near_workspaces::AccountId;
    use std::collections::HashMap;

    const CONTRACT_FILE_PATH: &str = "./../target/wasm32-unknown-unknown/release/mpc_contract.wasm";

    #[tokio::test]
    async fn test_contract_can_not_be_reinitialized() -> anyhow::Result<()> {
        let worker = near_workspaces::sandbox().await?;
        let wasm = std::fs::read(CONTRACT_FILE_PATH)?;
        let contract = worker.dev_deploy(&wasm).await?;

        let candidates: HashMap<AccountId, CandidateInfo> = HashMap::new();

        let status1 = contract
            .call("init")
            .args_json(serde_json::json!({
                "threshold": 2,
                "candidates": candidates
            }))
            .transact()
            .await?;

        assert!(status1.is_success());

        let status2 = contract
            .call("init")
            .args_json(serde_json::json!({
                "threshold": 2,
                "candidates": candidates
            }))
            .transact()
            .await?;

        assert!(status2.is_failure());

        Ok(())
    }
}

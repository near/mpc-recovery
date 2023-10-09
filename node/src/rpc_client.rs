use crate::protocol::ProtocolContractState;
use near_crypto::InMemorySigner;
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionStatus;
use serde_json::json;

pub async fn fetch_mpc_contract_state(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<ProtocolContractState> {
    let protocol_state: mpc_contract::ProtocolContractState =
        rpc_client.view(mpc_contract_id, "state", ()).await?;
    protocol_state
        .try_into()
        .map_err(|_| anyhow::anyhow!("protocol state has not been initialized yet"))
}

pub async fn vote_for_public_key(
    rpc_client: &near_fetch::Client,
    signer: &InMemorySigner,
    mpc_contract_id: &AccountId,
    public_key: &near_crypto::PublicKey,
) -> anyhow::Result<bool> {
    let args = json!({
        "public_key": public_key
    });
    let result = rpc_client
        .send_tx(
            signer,
            mpc_contract_id,
            vec![Action::FunctionCall(FunctionCallAction {
                method_name: "vote_pk".to_string(),
                args: serde_json::to_vec(&args)?,
                gas: 300_000_000_000_000,
                deposit: 0,
            })],
        )
        .await?;

    match result.status {
        FinalExecutionStatus::SuccessValue(value) => Ok(serde_json::from_slice(&value)?),
        status => anyhow::bail!("unexpected status: {:?}", status),
    }
}

pub async fn vote_reshared(
    rpc_client: &near_fetch::Client,
    signer: &InMemorySigner,
    mpc_contract_id: &AccountId,
    epoch: u64,
) -> anyhow::Result<bool> {
    let args = json!({
        "epoch": epoch
    });
    let result = rpc_client
        .send_tx(
            signer,
            mpc_contract_id,
            vec![Action::FunctionCall(FunctionCallAction {
                method_name: "vote_reshared".to_string(),
                args: serde_json::to_vec(&args)?,
                gas: 300_000_000_000_000,
                deposit: 0,
            })],
        )
        .await?;

    match result.status {
        FinalExecutionStatus::SuccessValue(value) => Ok(serde_json::from_slice(&value)?),
        status => anyhow::bail!("unexpected status: {:?}", status),
    }
}

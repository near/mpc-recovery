use crate::protocol::ProtocolState;

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_primitives::views::FinalExecutionStatus;

use serde_json::json;

pub async fn fetch_mpc_contract_state(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<ProtocolState> {
    let protocol_state: mpc_contract::ProtocolContractState =
        rpc_client.view(mpc_contract_id, "state").await?.json()?;
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
    tracing::info!(%public_key, "voting for public key");
    let result = rpc_client
        .call(signer, mpc_contract_id, "vote_pk")
        .args_json(json!({
            "public_key": public_key
        }))
        .max_gas()
        .retry_exponential(10, 5)
        .transact()
        .await?;

    match result.status() {
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
    let result = rpc_client
        .call(signer, mpc_contract_id, "vote_reshared")
        .args_json(json!({
            "epoch": epoch
        }))
        .max_gas()
        .retry_exponential(10, 5)
        .transact()
        .await?;

    match result.status() {
        FinalExecutionStatus::SuccessValue(value) => Ok(serde_json::from_slice(&value)?),
        status => anyhow::bail!("unexpected status: {:?}", status),
    }
}

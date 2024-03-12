use crate::MultichainTestContext;
use anyhow::Context;
use backon::ExponentialBuilder;
use backon::Retryable;
use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_contract::primitives::ContractSignResponse;
use mpc_contract::ProtocolContractState;
use mpc_contract::RunningContractState;
use mpc_recovery_node::web::StateView;
use near_jsonrpc_client::methods::tx::RpcTransactionStatusRequest;
use near_jsonrpc_client::methods::tx::TransactionInfo;
use near_lake_primitives::CryptoHash;
use near_primitives::views::FinalExecutionStatus;

pub async fn running_mpc<'a>(
    ctx: &MultichainTestContext<'a>,
    epoch: u64,
) -> anyhow::Result<RunningContractState> {
    let is_running = || async {
        let state: ProtocolContractState = ctx
            .rpc_client
            .view(ctx.nodes.ctx().mpc_contract.id(), "state", ())
            .await?;

        match state {
            ProtocolContractState::Running(running) if running.epoch >= epoch => Ok(running),
            ProtocolContractState::Running(running) => {
                anyhow::bail!("running with an older epoch: {}", running.epoch)
            }
            _ => anyhow::bail!("not running"),
        }
    };
    is_running
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| format!("mpc nodes did not reach epoch '{epoch}' before deadline"))
}

pub async fn has_at_least_triples<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_triple_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_triples = |id| {
        move || async move {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running { triple_count, .. }
                    if triple_count >= expected_triple_count =>
                {
                    Ok(state_view)
                }
                StateView::Running { .. } => anyhow::bail!("node does not have enough triples yet"),
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_triples(id)
            .retry(&ExponentialBuilder::default().with_max_times(8))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_triple_count}' triples before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

pub async fn has_at_least_presignatures<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_presignature_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_presignatures = |id| {
        move || async move {
            let state_view: StateView = ctx
                .http_client
                .get(format!("{}/state", ctx.nodes.url(id)))
                .send()
                .await?
                .json()
                .await?;

            match state_view {
                StateView::Running {
                    presignature_count, ..
                } if presignature_count >= expected_presignature_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough presignatures yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_presignatures(id)
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_presignature_count}' presignatures before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

pub async fn signature_responded(
    ctx: &MultichainTestContext<'_>,
    tx_hash: CryptoHash,
) -> anyhow::Result<FullSignature<Secp256k1>> {
    let is_tx_ready = || async {
        let outcome_view = ctx
            .jsonrpc_client
            .call(RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    hash: tx_hash,
                    account_id: ctx.nodes.ctx().mpc_contract.id().clone(),
                },
            })
            .await?;
        let FinalExecutionStatus::SuccessValue(payload) = outcome_view.status else {
            anyhow::bail!("tx finished unsuccessfully: {:?}", outcome_view.status);
        };
        let sign_response: ContractSignResponse = serde_json::from_slice(&payload)?;
        let signature = cait_sith::FullSignature::<Secp256k1> {
            big_r: sign_response.big_r,
            s: sign_response.s,
        };
        Ok(signature)
    };

    let signature = is_tx_ready
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| "failed to wait for signature response")?;
    Ok(signature)
}

use crate::MultichainTestContext;
use anyhow::Context;
use backon::ExponentialBuilder;
use backon::Retryable;
use cait_sith::FullSignature;
use k256::AffinePoint;
use k256::Scalar;
use k256::Secp256k1;
use mpc_contract::ProtocolContractState;
use mpc_contract::RunningContractState;
use mpc_recovery_node::web::StateView;
use near_jsonrpc_client::methods::tx::RpcTransactionStatusRequest;
use near_jsonrpc_client::methods::tx::TransactionInfo;
use near_lake_primitives::CryptoHash;
use near_primitives::views::FinalExecutionStatus;
use near_workspaces::Account;

pub async fn running_mpc<'a>(
    ctx: &MultichainTestContext<'a>,
    epoch: Option<u64>,
) -> anyhow::Result<RunningContractState> {
    let is_running = || async {
        let state: ProtocolContractState = ctx
            .rpc_client
            .view(ctx.nodes.ctx().mpc_contract.id(), "state", ())
            .await?;

        match state {
            ProtocolContractState::Running(running) => match epoch {
                None => Ok(running),
                Some(expected_epoch) if running.epoch >= expected_epoch => Ok(running),
                Some(_) => {
                    anyhow::bail!("running with an older epoch: {}", running.epoch)
                }
            },
            _ => anyhow::bail!("not running"),
        }
    };
    let err_msg = format!(
        "mpc did not reach {} in time",
        if epoch.is_some() {
            "expected epoch"
        } else {
            "running state"
        }
    );
    is_running
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| err_msg)
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
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_triple_count}' triples before deadline"))?;
        state_views.push(state_view);
    }
    Ok(state_views)
}

pub async fn has_at_least_mine_triples<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_mine_triple_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_mine_triples = |id| {
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
                    triple_mine_count, ..
                } if triple_mine_count >= expected_mine_triple_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough mine triples yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_mine_triples(id)
            .retry(&ExponentialBuilder::default().with_max_times(15))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_mine_triple_count}' triples before deadline"))?;
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

pub async fn has_at_least_mine_presignatures<'a>(
    ctx: &MultichainTestContext<'a>,
    expected_mine_presignature_count: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough_mine_presignatures = |id| {
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
                    presignature_mine_count,
                    ..
                } if presignature_mine_count >= expected_mine_presignature_count => Ok(state_view),
                StateView::Running { .. } => {
                    anyhow::bail!("node does not have enough mine presignatures yet")
                }
                StateView::NotRunning => anyhow::bail!("node is not running"),
            }
        }
    };

    let mut state_views = Vec::new();
    for id in 0..ctx.nodes.len() {
        let state_view = is_enough_mine_presignatures(id)
            .retry(&ExponentialBuilder::default().with_max_times(6))
            .await
            .with_context(|| format!("mpc node '{id}' failed to generate '{expected_mine_presignature_count}' presignatures before deadline"))?;
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
        let (big_r, s): (AffinePoint, Scalar) = serde_json::from_slice(&payload)?;
        let signature = cait_sith::FullSignature::<Secp256k1> { big_r, s };
        Ok(signature)
    };

    let signature = is_tx_ready
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| "failed to wait for signature response")?;
    Ok(signature)
}

pub async fn signature_payload_responded(
    ctx: &MultichainTestContext<'_>,
    account: Account,
    payload: [u8; 32],
    payload_hashed: [u8; 32],
) -> anyhow::Result<FullSignature<Secp256k1>> {
    let is_signature_ready = || async {
        let (_, _, _, tx_hash) = crate::multichain::actions::request_sign_non_random(
            &ctx,
            account.clone(),
            payload,
            payload_hashed,
        )
        .await?;
        signature_responded(ctx, tx_hash).await
    };

    let signature = is_signature_ready
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| "failed to wait for signature response")?;
    Ok(signature)
}

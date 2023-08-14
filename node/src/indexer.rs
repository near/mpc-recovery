use near_lake_framework::{LakeBuilder, LakeContext};
use near_lake_primitives::{receipts::ExecutionStatus, AccountId};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SignPayload {
    payload: Vec<u8>,
}

#[derive(LakeContext)]
struct Context {
    signer_account: AccountId,
}

async fn handle_block(
    mut block: near_lake_primitives::block::Block,
    ctx: &Context,
) -> anyhow::Result<()> {
    for tx in block.transactions() {
        if tx.receiver_id() == &ctx.signer_account
            && matches!(
                tx.status(),
                ExecutionStatus::SuccessValue(_) | ExecutionStatus::SuccessReceiptId(_)
            )
        {
            for action in tx.actions_included() {
                if let Some(function_call) = action.as_function_call() {
                    if function_call.method_name() == "sign" {
                        if let Ok(sign_payload) =
                            serde_json::from_slice::<'_, SignPayload>(&function_call.args())
                        {
                            tracing::info!(
                                signer_id = tx.signer_id().to_string(),
                                bytes = sign_payload.payload.len(),
                                "new sign event"
                            )
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn run(near_network: &str, signer_account: AccountId) -> anyhow::Result<()> {
    let mut config_builder = LakeBuilder::default();
    config_builder = match near_network {
        "mainnet" => config_builder.mainnet().start_block_height(98924566),
        "testnet" => config_builder.testnet().start_block_height(134986320),
        other => anyhow::bail!("unrecognized NEAR network: {other}"),
    };
    let context = Context { signer_account };
    let lake = config_builder.build()?;
    lake.run_with_context(handle_block, &context)?;
    Ok(())
}

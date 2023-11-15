use near_lake_framework::{LakeBuilder, LakeContext};
use near_lake_primitives::{receipts::ExecutionStatus, AccountId};
use serde::{Deserialize, Serialize};

/// Configures exporter of span and trace data.
#[derive(Debug, clap::Parser)]
pub struct Options {
    /// AWS S3 bucket name for NEAR Lake Indexer
    #[clap(
        long,
        env("MPC_RECOVERY_INDEXER_S3_BUCKET"),
        default_value = "near-lake-data-testnet"
    )]
    pub s3_bucket: String,

    /// AWS S3 region name for NEAR Lake Indexer
    #[clap(
        long,
        env("MPC_RECOVERY_INDEXER_S3_REGION"),
        default_value = "eu-central-1"
    )]
    pub s3_region: String,

    /// The block height to start indexing from.
    // Defaults to the latest block on 2023-11-14 07:40:22 AM UTC
    #[clap(long, default_value = "145964826")]
    pub start_block_height: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--s3-bucket".to_string(),
            self.s3_bucket,
            "--s3-region".to_string(),
            self.s3_region,
            "--start-block-height".to_string(),
            self.start_block_height.to_string(),
        ]
    }
}

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
                            serde_json::from_slice::<'_, SignPayload>(function_call.args())
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

pub fn run(options: &Options, signer_account: AccountId) -> anyhow::Result<()> {
    let lake = LakeBuilder::default()
        .s3_bucket_name(&options.s3_bucket)
        .s3_region_name(&options.s3_region)
        .start_block_height(options.start_block_height)
        .build()?;
    let context = Context { signer_account };
    lake.run_with_context(handle_block, &context)?;
    Ok(())
}

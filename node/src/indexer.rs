use crate::protocol::{SignQueue, SignRequest};
use near_lake_framework::{LakeBuilder, LakeContext};
use near_lake_primitives::actions::ActionMetaDataExt;
use near_lake_primitives::{receipts::ExecutionStatus, AccountId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configures indexer.
#[derive(Debug, Clone, clap::Parser)]
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

    /// AWS S3 URL for NEAR Lake Indexer (can be used to point to LocalStack)
    #[clap(long, env("MPC_RECOVERY_INDEXER_S3_URL"))]
    pub s3_url: Option<String>,

    /// The block height to start indexing from.
    // Defaults to the latest block on 2023-11-14 07:40:22 AM UTC
    #[clap(
        long,
        env("MPC_RECOVERY_INDEXER_START_BLOCK_HEIGHT"),
        default_value = "145964826"
    )]
    pub start_block_height: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = vec![
            "--s3-bucket".to_string(),
            self.s3_bucket,
            "--s3-region".to_string(),
            self.s3_region,
            "--start-block-height".to_string(),
            self.start_block_height.to_string(),
        ];

        if let Some(s3_url) = self.s3_url {
            opts.extend(vec!["--s3-url".to_string(), s3_url]);
        }

        opts
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SignPayload {
    payload: [u8; 32],
}

#[derive(LakeContext)]
struct Context {
    mpc_contract_id: AccountId,
    queue: Arc<RwLock<SignQueue>>,
}

async fn handle_block(
    mut block: near_lake_primitives::block::Block,
    ctx: &Context,
) -> anyhow::Result<()> {
    for action in block.actions().cloned().collect::<Vec<_>>() {
        if action.receiver_id() == ctx.mpc_contract_id {
            let receipt = block.receipt_by_id(&action.receipt_id()).unwrap();
            let ExecutionStatus::SuccessValue(result) = receipt.status() else {
                continue;
            };
            if let Some(function_call) = action.as_function_call() {
                if function_call.method_name() == "sign" {
                    if let Ok(sign_payload) =
                        serde_json::from_slice::<'_, SignPayload>(function_call.args())
                    {
                        let Ok(entropy) = serde_json::from_slice::<'_, [u8; 32]>(&result) else {
                            continue;
                        };
                        tracing::info!(
                            receipt_id = %receipt.receipt_id(),
                            caller_id = receipt.predecessor_id().to_string(),
                            payload = hex::encode(sign_payload.payload),
                            entropy = hex::encode(entropy),
                            "indexed new `sign` function call"
                        );
                        let mut queue = ctx.queue.write().await;
                        queue.add(SignRequest {
                            receipt_id: receipt.receipt_id(),
                            msg_hash: sign_payload.payload,
                            entropy,
                        });
                        drop(queue);
                    }
                }
            }
        }
    }
    if block.block_height() % 1000 == 0 {
        tracing::info!(block_height = block.block_height(), "indexed block")
    }
    Ok(())
}

pub fn run(
    options: Options,
    mpc_contract_id: AccountId,
    queue: Arc<RwLock<SignQueue>>,
) -> anyhow::Result<()> {
    tracing::info!(
        s3_bucket = options.s3_bucket,
        s3_region = options.s3_region,
        s3_url = options.s3_url,
        start_block_height = options.start_block_height,
        %mpc_contract_id,
        "starting indexer"
    );
    let mut lake_builder = LakeBuilder::default()
        .s3_bucket_name(options.s3_bucket)
        .s3_region_name(options.s3_region)
        .start_block_height(options.start_block_height);
    let lake = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            if let Some(s3_url) = options.s3_url {
                let aws_config = aws_config::from_env().load().await;
                let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
                    .endpoint_url(s3_url)
                    .build();
                lake_builder = lake_builder.s3_config(s3_config);
            }
            lake_builder.build()
        })?;
    let context = Context {
        mpc_contract_id,
        queue,
    };
    lake.run_with_context(handle_block, &context)?;
    Ok(())
}

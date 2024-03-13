use crate::gcp::GcpService;
use crate::kdf;
use crate::protocol::{SignQueue, SignRequest};
use crate::types::LatestBlockHeight;
use near_lake_framework::{LakeBuilder, LakeContext};
use near_lake_primitives::actions::ActionMetaDataExt;
use near_lake_primitives::{receipts::ExecutionStatus, AccountId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Configures indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_options")]
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
    path: String,
}

#[derive(LakeContext)]
struct Context {
    mpc_contract_id: AccountId,
    gcp_service: GcpService,
    queue: Arc<RwLock<SignQueue>>,
    latest_block_height: Arc<RwLock<LatestBlockHeight>>,
}

async fn handle_block(
    mut block: near_lake_primitives::block::Block,
    ctx: &Context,
) -> anyhow::Result<()> {
    for action in block.actions().cloned().collect::<Vec<_>>() {
        if action.receiver_id() == ctx.mpc_contract_id {
            let receipt = block.receipt_by_id(&action.receipt_id()).unwrap();
            let ExecutionStatus::SuccessReceiptId(receipt_id) = receipt.status() else {
                continue;
            };
            if let Some(function_call) = action.as_function_call() {
                if function_call.method_name() == "sign" {
                    if let Ok(sign_payload) =
                        serde_json::from_slice::<'_, SignPayload>(function_call.args())
                    {
                        if receipt.logs().is_empty() {
                            tracing::warn!("`sign` did not produce entropy");
                            continue;
                        }
                        let Ok(entropy) = serde_json::from_str::<'_, [u8; 32]>(&receipt.logs()[1])
                        else {
                            tracing::warn!(
                                "`sign` did not produce entropy correctly: {:?}",
                                receipt.logs()[0]
                            );
                            continue;
                        };
                        let epsilon =
                            kdf::derive_epsilon(&action.predecessor_id(), &sign_payload.path);
                        let delta = kdf::derive_delta(receipt_id, entropy);
                        tracing::info!(
                            receipt_id = %receipt_id,
                            caller_id = receipt.predecessor_id().to_string(),
                            payload = hex::encode(sign_payload.payload),
                            entropy = hex::encode(entropy),
                            "indexed new `sign` function call"
                        );
                        let mut queue = ctx.queue.write().await;
                        queue.add(SignRequest {
                            receipt_id,
                            msg_hash: sign_payload.payload,
                            epsilon,
                            delta,
                            entropy,
                            time_added: Instant::now(),
                        });
                        crate::metrics::NUM_SIGN_REQUESTS
                            .with_label_values(&[&ctx.gcp_service.account_id.to_string()])
                            .inc();
                        drop(queue);
                    }
                }
            }
        }
    }

    ctx.latest_block_height
        .write()
        .await
        .set(block.block_height())
        .store(&ctx.gcp_service)
        .await?;

    if block.block_height() % 1000 == 0 {
        tracing::info!(block_height = block.block_height(), "indexed block");
    }
    Ok(())
}

pub fn run(
    options: Options,
    mpc_contract_id: AccountId,
    node_account_id: AccountId,
    queue: Arc<RwLock<SignQueue>>,
    gcp_service: crate::gcp::GcpService,
) -> anyhow::Result<()> {
    tracing::info!(
        s3_bucket = options.s3_bucket,
        s3_region = options.s3_region,
        s3_url = options.s3_url,
        start_block_height = options.start_block_height,
        %mpc_contract_id,
        "starting indexer"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (lake, latest_block_height) = rt.block_on(async {
        let latest = match LatestBlockHeight::fetch(&gcp_service).await {
            Ok(latest) => latest,
            Err(err) => {
                tracing::error!(%err, "failed to fetch latest block height; using start_block_height={} instead", options.start_block_height);
                LatestBlockHeight {
                    account_id: node_account_id.to_string(),
                    block_height: options.start_block_height,
                }
            }
        };

        let mut lake_builder = LakeBuilder::default()
            .s3_bucket_name(options.s3_bucket)
            .s3_region_name(options.s3_region)
            .start_block_height(latest.block_height);

        if let Some(s3_url) = options.s3_url {
            let aws_config = aws_config::from_env().load().await;
            let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
                .endpoint_url(s3_url)
                .build();
            lake_builder = lake_builder.s3_config(s3_config);
        }
        anyhow::Ok((anyhow::Context::context(lake_builder.build(), "could not build lake indexer")?, latest))
    })?;
    let context = Context {
        mpc_contract_id,
        gcp_service,
        queue,
        latest_block_height: Arc::new(RwLock::new(latest_block_height)),
    };
    lake.run_with_context(handle_block, &context)?;
    Ok(())
}

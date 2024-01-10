use crate::{wait_for, with_multichain_nodes};
use anyhow::Context;
use backon::{ExponentialBuilder, Retryable};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::ScalarExt;
use near_crypto::{InMemorySigner, Signer};
use near_fetch::signer::ExposeAccountId;
use near_jsonrpc_client::methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest;
use near_jsonrpc_client::methods::tx::{RpcTransactionStatusRequest, TransactionInfo};
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_primitives::views::FinalExecutionStatus;
use rand::Rng;
use std::time::Duration;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |mut ctx| {
        Box::pin(async move {
            // Wait for network to complete key generation
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(3, account.id(), account.secret_key())
                .await?;

            // Wait for network to complete key reshare
            let state_1 = wait_for::running_mpc(&ctx, 1).await?;
            assert_eq!(state_1.participants.len(), 4);

            assert_eq!(
                state_0.public_key, state_1.public_key,
                "public key must stay the same"
            );

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_and_presignatures() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            // Wait for network to complete key generation
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            for i in 0..ctx.nodes.len() {
                wait_for::has_at_least_triples(&ctx, i, 2).await?;
            }
            for i in 0..ctx.nodes.len() {
                wait_for::has_at_least_presignatures(&ctx, i, 2).await?;
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            // Wait for network to complete key generation
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            for i in 0..ctx.nodes.len() {
                wait_for::has_at_least_triples(&ctx, i, 2).await?;
            }
            for i in 0..ctx.nodes.len() {
                wait_for::has_at_least_presignatures(&ctx, i, 2).await?;
            }

            let worker = &ctx.nodes.ctx().worker;
            let (account_id, secret_key) = worker.dev_generate().await;
            worker
                .create_tla(account_id.clone(), secret_key.clone())
                .await?
                .into_result()?;
            let payload: [u8; 32] = rand::thread_rng().gen();
            let signer = InMemorySigner {
                account_id: account_id.clone(),
                public_key: secret_key.public_key().clone().into(),
                secret_key: secret_key.to_string().parse()?,
            };
            let (nonce, block_hash, _) = ctx
                .rpc_client
                .fetch_nonce(signer.account_id(), &signer.public_key())
                .await?;
            let tx_hash = ctx
                .jsonrpc_client
                .call(&RpcBroadcastTxAsyncRequest {
                    signed_transaction: Transaction {
                        nonce,
                        block_hash,
                        signer_id: signer.account_id().clone(),
                        public_key: signer.public_key(),
                        receiver_id: ctx.nodes.ctx().mpc_contract.id().clone(),
                        actions: vec![Action::FunctionCall(FunctionCallAction {
                            method_name: "sign".to_string(),
                            args: serde_json::to_vec(&serde_json::json!({
                                "payload": payload,
                                "path": "test",
                            }))?,
                            gas: 300_000_000_000_000,
                            deposit: 0,
                        })],
                    }
                    .sign(&signer),
                })
                .await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
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
            let mut bytes = vec![0x04];
            bytes.extend_from_slice(&state_0.public_key.as_bytes()[1..]);
            let point = EncodedPoint::from_bytes(bytes).unwrap();
            let public_key = AffinePoint::from_encoded_point(&point).unwrap();
            let epsilon = kdf::derive_epsilon(&account_id, "test");

            assert!(signature.verify(
                &kdf::derive_key(public_key, epsilon),
                &Scalar::from_bytes(&payload),
            ));

            Ok(())
        })
    })
    .await
}

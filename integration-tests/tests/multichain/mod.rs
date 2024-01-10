use crate::{wait_for, with_multichain_nodes};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::ScalarExt;
use near_crypto::InMemorySigner;
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::views::ExecutionStatusView;
use rand::Rng;
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
                .add_node(account.id(), account.secret_key())
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

            let worker = &ctx.nodes.ctx().worker;
            let (account_id, secret_key) = worker.dev_generate().await;
            worker
                .create_tla(account_id.clone(), secret_key.clone())
                .await?
                .into_result()?;
            let payload: [u8; 32] = rand::thread_rng().gen();
            let outcome = ctx
                .rpc_client
                .send_tx(
                    &InMemorySigner {
                        account_id: account_id.clone(),
                        public_key: secret_key.public_key().clone().into(),
                        secret_key: secret_key.to_string().parse()?,
                    },
                    ctx.nodes.ctx().mpc_contract.id(),
                    vec![Action::FunctionCall(FunctionCallAction {
                        method_name: "sign".to_string(),
                        args: serde_json::to_vec(&serde_json::json!({
                            "payload": payload,
                            "path": "test",
                        }))?,
                        gas: 300_000_000_000_000,
                        deposit: 0,
                    })],
                )
                .await?;
            let ExecutionStatusView::SuccessReceiptId(receipt_id) =
                outcome.transaction_outcome.outcome.status
            else {
                anyhow::bail!("missing receipt id");
            };

            let signature = wait_for::has_response(&ctx, receipt_id).await?;
            let signature_output = cait_sith::FullSignature::<Secp256k1> {
                big_r: signature.big_r,
                s: signature.s,
            };

            let mut bytes = vec![0x04];
            bytes.extend_from_slice(&state_0.public_key.as_bytes()[1..]);
            let point = EncodedPoint::from_bytes(bytes).unwrap();
            let public_key = AffinePoint::from_encoded_point(&point).unwrap();
            let epsilon = kdf::derive_epsilon(&account_id, "test");

            assert!(signature_output.verify(
                &kdf::derive_key(public_key, epsilon),
                &Scalar::from_bytes(&payload),
            ));

            Ok(())
        })
    })
    .await
}

pub mod wait_for;

use crate::MultichainTestContext;

use cait_sith::FullSignature;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_contract::RunningContractState;
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest;
use near_lake_primitives::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_workspaces::Account;
use rand::Rng;

use std::time::Duration;

pub async fn request_sign(
    ctx: &MultichainTestContext<'_>,
) -> anyhow::Result<([u8; 32], Account, CryptoHash)> {
    let worker = &ctx.nodes.ctx().worker;
    let account = worker.dev_create_account().await?;
    let payload: [u8; 32] = rand::thread_rng().gen();
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().clone().into(),
        secret_key: account.secret_key().to_string().parse()?,
    };
    let (nonce, block_hash, _) = ctx
        .rpc_client
        .fetch_nonce(&signer.account_id, &signer.public_key)
        .await?;
    let tx_hash = ctx
        .jsonrpc_client
        .call(&RpcBroadcastTxAsyncRequest {
            signed_transaction: Transaction {
                nonce,
                block_hash,
                signer_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
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
    Ok((payload, account, tx_hash))
}

pub async fn assert_signature(
    account_id: &near_workspaces::AccountId,
    pk_bytes: &[u8],
    payload: &[u8; 32],
    signature: &FullSignature<Secp256k1>,
) {
    let point = EncodedPoint::from_bytes(pk_bytes).unwrap();
    let public_key = AffinePoint::from_encoded_point(&point).unwrap();
    let epsilon = kdf::derive_epsilon(account_id, "test");

    assert!(signature.verify(
        &kdf::derive_key(public_key, epsilon),
        &Scalar::from_bytes(payload),
    ));
}

pub async fn single_signature_production(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
) -> anyhow::Result<()> {
    let (payload, account, tx_hash) = request_sign(ctx).await?;
    let signature = wait_for::signature_responded(ctx, tx_hash).await?;

    let mut pk_bytes = vec![0x04];
    pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);
    assert_signature(account.id(), &pk_bytes, &payload, &signature).await;

    Ok(())
}

#[test]
fn test_proposition() {
    // let big_r = "0478986e65711a4dc50d542a4217362739bf81487fb85109b04cee98bbbe6208d6bccf7e3d0a80186ce189e5cde17f38ae90c5ce8d763ba66fc5519b09ece2898e";
    let big_r = "043f8fdd413b470a3333beaddf39dcad0850563262f52f8c8b4e7cdb512b92ce7f1ede039a3fb68707ee58aed75f0def763a82308937f62d83f0da5db66033222f";
    // let s = "4c94690437e7ee537a2c2238cb303f4218319266e9d3a074acdebf3ec39e9ecf";
    let s = "79e3c20191b1b32f5177f12346de442acd46bab29b07c46470cbcc8b2930e7bf";
    // let public_key = "024106C78BF2FD1DF1C9F2F75D7D98E4C107475CAEA8AAFC0CDD27BA9BBA929D49";
    // let public_key = "032628FCF372DCF6F36FFD478A2C33D99B61D599B0539481F33CA8E165CA8D15DB";
    let mpc_key = "032628FCF372DCF6F36FFD478A2C33D99B61D599B0539481F33CA8E165CA8D15DB";

    let mpc_pk = mpc_key.to_string().into_affine_point();
    let derivation_epsilon: k256::Scalar =
        kdf::derive_epsilon(&"acc_mc.test.near".parse().unwrap(), "test");
    let user_pk: AffinePoint = kdf::derive_key(mpc_pk, derivation_epsilon);

    let big_r = hex::decode(big_r).unwrap();
    let big_r = EncodedPoint::from_bytes(big_r).unwrap();
    let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();

    let s = hex::decode(s).unwrap();
    let s = k256::Scalar::from_uint_unchecked(k256::U256::from_be_slice(s.as_slice()));

    println!("R: {big_r:#?}");
    println!("S: {s:#?}");

    let signature = cait_sith::FullSignature::<Secp256k1> { big_r, s };
    // let mut pk_bytes = vec![0x04];
    // pk_bytes.extend_from_slice(&public_key.as_bytes()[1..]);
    // let point = EncodedPoint::from_bytes(pk_bytes).unwrap();
    // let public_key = AffinePoint::from_encoded_point(&point).unwrap();
    // let public_key: AffinePoint = public_key.to_string().into_affine_point();

    let mut msg_hash = [0u8; 32];
    for i in 0..32 {
        msg_hash[i] = i as u8;
    }
    let msg_hash = k256::Scalar::from_bytes(&msg_hash);
    assert!(signature.verify(&user_pk, &msg_hash), "Signature failed");
}

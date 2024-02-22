pub mod wait_for;

use crate::{account, MultichainTestContext};

use anyhow::Ok;
use curv::arithmetic::Converter;
use k256::ecdsa::hazmat::VerifyPrimitive;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Field;
use k256::{ecdsa, AffinePoint, FieldBytes, PublicKey, Scalar, Secp256k1};
use mpc_contract::RunningContractState;
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest;
use near_lake_primitives::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_workspaces::types::{KeyType, SecretKey};
use near_workspaces::{Account, AccountId};
use rand::Rng;

use std::time::Duration;

pub async fn request_sign(
    ctx: &MultichainTestContext<'_>,
) -> anyhow::Result<([u8; 32], Account, CryptoHash)> {
    let worker = &ctx.nodes.ctx().worker;
    let sk = SecretKey::from_seed(KeyType::SECP256K1, "seed");
    let account_id = AccountId::try_from("acc_mc.test.near".to_string())?;
    // same account is used multiple times, we are creating it if it doesn't already exist
    let account = match worker.view_account(&account_id).await.is_ok() {
        true => Account::from_secret_key(account_id, sk, worker),
        false => worker.create_tla(account_id, sk).await?.unwrap(),
    };
    // let payload = rand::thread_rng().gen();
    // let payload: [u8; 32] = [5u8; 32];
    // let payload: Vec<u8> = (0..32).into_iter().collect();
    let mut payload = [0u8; 32];
    for i in 0..32 {
        payload[i] = i as u8;
    }

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
    Ok((payload.into(), account, tx_hash))
}

pub async fn single_signature_production(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
    execution_index: i32,
) -> anyhow::Result<()> {
    let (payload, account, tx_hash) = request_sign(ctx).await?;
    let (signature_big_r, signature_s) = wait_for::signature_responded(ctx, tx_hash).await?;

    let mpc_pk: AffinePoint = state.public_key.clone().into_affine_point();

    let derivation_epsilon = kdf::derive_epsilon(account.id(), "test");

    check_signature_cait_sith(
        &signature_big_r,
        &signature_s,
        &payload,
        &derivation_epsilon,
        &mpc_pk,
        execution_index,
    );

    check_signature_ethers(
        &signature_big_r,
        &signature_s,
        &payload,
        &derivation_epsilon,
        &mpc_pk,
    );

    Ok(())
}

fn check_signature_cait_sith(
    signature_big_r: &AffinePoint,
    signature_s: &Scalar,
    payload: &[u8; 32],
    derivation_epsilon: &Scalar,
    mpc_pk: &AffinePoint,
    execution_index: i32,
) {
    let signature = cait_sith::FullSignature::<Secp256k1> {
        big_r: *signature_big_r,
        s: *signature_s,
    };

    let user_pk = kdf::derive_key(*mpc_pk, *derivation_epsilon);

    let sig = Signature::from_scalars(signature_big_r.x(), signature_s).unwrap();

    println!(
        "Expected Public Key {:?}",
        VerifyingKey::from_affine(user_pk)
    );
    for i in 0u8..=3 {
        let recovery_id = RecoveryId::from_byte(i).unwrap();
        let res = VerifyingKey::recover_from_prehash(payload, &sig, recovery_id);
        println!(
            "Execution index: {}, v? : {}, res: {:?}",
            execution_index, i, res
        );
    }

    let payload2: [u8; 32] = rand::thread_rng().gen();

    assert!(signature.verify(&user_pk, &Scalar::from_bytes(payload)));
    assert_eq!(
        signature.verify(&user_pk, &Scalar::from_bytes(&payload2)),
        false
    );
}

fn check_signature_ethers(
    signature_big_r: &AffinePoint,
    signature_s: &Scalar,
    payload: &[u8; 32],
    derivation_epsilon: &Scalar,
    mpc_pk: &AffinePoint,
) {
    let chain_id = 1; // 1 for Ethereum mainnet

    let r = ethers_core::types::U256::from_little_endian(signature_big_r.x().as_slice());
    let s = ethers_core::types::U256::from_little_endian(signature_s.to_bytes().as_slice());
    let v = (signature_big_r.y_is_odd().unwrap_u8() + chain_id * 2 + 35) as u64;

    let signature = ethers_core::types::Signature { r, s, v };

    let user_pk_affine_point = kdf::derive_key(*mpc_pk, *derivation_epsilon);
    let user_pk = ethers_core::k256::PublicKey::from_affine(user_pk_affine_point).unwrap();
    let user_pk = ecdsa::VerifyingKey::from(&user_pk);
    let user_eth_address: ethers_core::types::H160 =
        ethers_core::utils::public_key_to_address(&user_pk);

    // TODO: fix signature check
    // assert!(signature.verify(*payload, user_eth_address).is_ok());
}

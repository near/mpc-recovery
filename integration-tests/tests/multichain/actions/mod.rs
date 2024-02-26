pub mod wait_for;

use crate::MultichainTestContext;

use cait_sith::FullSignature;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::ops::{Invert, Reduce};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::ProjectivePoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_contract::RunningContractState;
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::ScalarExt;
use near_crypto::InMemorySigner;
use near_jsonrpc_client::methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest;
use near_lake_primitives::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_workspaces::Account;
use rand::Rng;
use secp256k1::XOnlyPublicKey;

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

#[tokio::test]
async fn test_proposition() {
    // let big_r = "043f8fdd413b470a3333beaddf39dcad0850563262f52f8c8b4e7cdb512b92ce7f1ede039a3fb68707ee58aed75f0def763a82308937f62d83f0da5db66033222f";
    let big_r = "044bf886afee5a6844a25fa6831a01715e990d3d9e96b792a9da91cfbecbf8477cea57097a3db9fc1d4822afade3d1c4e6d66e99568147304ae34bcfa609d90a16";
    // let s = "79e3c20191b1b32f5177f12346de442acd46bab29b07c46470cbcc8b2930e7bf";
    let s = "1f871c67139f617409067ac8a7150481e3a5e2d8a9207ffdaad82098654e95cb";
    // let mpc_key = "032628FCF372DCF6F36FFD478A2C33D99B61D599B0539481F33CA8E165CA8D15DB";
    let mpc_key = "02F2B55346FD5E4BFF1F06522561BDCD024CEA25D98A091197ACC04E22B3004DB2";

    // Create payload
    let mut payload = [0u8; 32];
    for i in 0..32 {
        payload[i] = i as u8;
    }
    let mut payload_rev = payload.clone();
    payload_rev.reverse();

    let mut hashed: [u8; 32] = [
        99, 13, 205, 41, 102, 196, 51, 102, 145, 18, 84, 72, 187, 178, 91, 79, 244, 18, 164, 156,
        115, 45, 178, 200, 171, 193, 184, 88, 27, 215, 16, 221,
    ];
    let msg_hash = k256::Scalar::from_bytes(&hashed);
    hashed.reverse();

    // Derive and convert user pk
    let mpc_pk = hex::decode(mpc_key).unwrap();
    let mpc_pk = EncodedPoint::from_bytes(mpc_pk).unwrap();
    let mpc_pk = AffinePoint::from_encoded_point(&mpc_pk).unwrap();
    let account_id = "acc_mc.test.near".parse().unwrap();
    let derivation_epsilon: k256::Scalar = kdf::derive_epsilon(&account_id, "test");
    let user_pk: AffinePoint = kdf::derive_key(mpc_pk.clone(), derivation_epsilon);
    let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
        0 => secp256k1::Parity::Even,
        1 => secp256k1::Parity::Odd,
        _ => unreachable!(),
    };
    let user_pk_x = x_coordinate::<k256::Secp256k1>(&user_pk);
    let user_pk_x: XOnlyPublicKey = XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
    let user_pk_x: secp256k1::PublicKey =
        secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
    let user_address_from_pk = public_key_to_address(&user_pk_x.into());

    let mpc_pk_x = x_coordinate::<k256::Secp256k1>(&mpc_pk);
    let mpc_pk_x: XOnlyPublicKey = XOnlyPublicKey::from_slice(&mpc_pk_x.to_bytes()).unwrap();
    let mpc_pk_parity = match mpc_pk.y_is_odd().unwrap_u8() {
        0 => secp256k1::Parity::Even,
        1 => secp256k1::Parity::Odd,
        _ => unreachable!(),
    };
    let mpc_pk_x: secp256k1::PublicKey =
        secp256k1::PublicKey::from_x_only_public_key(mpc_pk_x, mpc_pk_parity);
    let mpc_pk_addr = public_key_to_address(&mpc_pk_x.into());

    // Prepare R ans s signature values
    let big_r = hex::decode(big_r).unwrap();
    let big_r = EncodedPoint::from_bytes(big_r).unwrap();
    let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();
    let big_r_y_parity = big_r.y_is_odd().unwrap_u8() as i32;
    assert!(big_r_y_parity == 0 || big_r_y_parity == 1);

    let s = hex::decode(s).unwrap();
    let s = k256::Scalar::from_uint_unchecked(k256::U256::from_be_slice(s.as_slice()));
    let r = x_coordinate::<k256::Secp256k1>(&big_r);

    println!("R: {big_r:#?}");
    println!("r: {r:#?}");
    println!("y parity: {}", big_r_y_parity);
    println!("s: {s:#?}");

    // Check signature using cait-sith tooling
    let signature = cait_sith::FullSignature::<Secp256k1> { big_r, s };
    let is_signature_valid_for_user_pk = signature.verify(&user_pk, &msg_hash);
    // let is_signature_valid_for_mpc_pk = signature.verify(&mpc_pk, &msg_hash);
    // let another_user_pk = kdf::derive_key(mpc_pk.clone(), derivation_epsilon + k256::Scalar::ONE);
    // let is_signature_valid_for_another_user_pk = signature.verify(&another_user_pk, &msg_hash);
    assert!(is_signature_valid_for_user_pk);
    // assert_eq!(is_signature_valid_for_mpc_pk, false);
    // assert_eq!(is_signature_valid_for_another_user_pk, false);

    // Check signature using ecdsa tooling
    let ecdsa_signature: ecdsa::Signature<Secp256k1> =
        ecdsa::Signature::from_scalars(r, s).unwrap();
    let k256_sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
    let user_pk_k256: k256::elliptic_curve::PublicKey<Secp256k1> =
        k256::PublicKey::from_affine(user_pk).unwrap();
    let ecdsa_verify_result = verify(
        &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
        &hashed,
        &k256_sig,
    );
    println!("ecdsa_verify_result[1st]: {ecdsa_verify_result:?}");
    assert!(ecdsa_verify_result.is_ok());
    let ecdsa_verify_result = ecdsa::signature::Verifier::verify(
        &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
        &hashed,
        &ecdsa_signature,
    );
    println!("ecdsa_verify_result[2nd]: {ecdsa_verify_result:?}");
    // use k256::signature::Verifier;
    // let verify_key = k256::ecdsa::VerifyingKey::from(&user_pk_k256);
    // let ecdsa_verify_result = verify_key.verify(&hashed, &k256_sig);

    // Check signature using etheres tooling
    let ethers_r = ethers_core::types::U256::from_big_endian(r.to_bytes().as_slice());
    let ethers_s = ethers_core::types::U256::from_big_endian(s.to_bytes().as_slice());
    // let chain_id = 1;
    // let ethers_v = (big_r_y_parity + chain_id * 2 + 35) as u64;
    let ethers_v = big_r_y_parity as u64;

    let signature = ethers_core::types::Signature {
        r: ethers_r,
        s: ethers_s,
        v: ethers_v,
    };

    let verifying_user_pk = ecdsa::VerifyingKey::from(&user_pk_k256);
    let user_address_ethers: ethers_core::types::H160 =
        ethers_core::utils::public_key_to_address(&verifying_user_pk);
    // assert!(signature.verify(payload, user_address_ethers).is_ok()); // TODO: fix

    // Check if recovered address is the same as the user address
    let signature_for_recovery: [u8; 64] = {
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r.to_bytes()); // TODO: we need to take r, not R
        signature[32..].copy_from_slice(&s.to_bytes());
        signature
    };
    // let ecdsa_signature_bytes = ecdsa_signature.to_bytes();
    // let ecdsa_signature_bytes = k256_sig.to_bytes();
    let recovered_from_signature_address_web3 =
        web3::signing::recover(&hashed, &signature_for_recovery, big_r_y_parity).unwrap();
    // assert_eq!(user_address_from_pk, recovered_from_signature_address_web3); // TODO: fix

    let recovered_from_signature_address_ethers = signature.recover(hashed).unwrap();

    println!("                      {mpc_pk_addr:#?}");
    println!("user_address_from_pk: {user_address_from_pk:#?}");
    println!("user_address_ethers:  {user_address_ethers:#?}");
    println!(
        "recovered_from_signature_address_ethers: {recovered_from_signature_address_ethers:#?}"
    );
    println!("recovered_from_signature_address_web3:   {recovered_from_signature_address_web3:#?}");
}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}

pub fn public_key_to_address(public_key: &secp256k1::PublicKey) -> web3::types::Address {
    let public_key = public_key.serialize_uncompressed();

    debug_assert_eq!(public_key[0], 0x04);
    let hash: [u8; 32] = web3::signing::keccak256(&public_key[1..]);

    web3::types::Address::from_slice(&hash[12..])
}

fn verify(
    key: &VerifyingKey,
    msg: &[u8],
    sig: &k256::ecdsa::Signature,
) -> Result<(), &'static str> {
    let q = ProjectivePoint::<Secp256k1>::from(key.as_affine());
    let z = ecdsa::hazmat::bits2field::<Secp256k1>(msg).unwrap();

    // &k256::FieldBytes::from_slice(&k256::Scalar::from_bytes(msg).to_bytes()),
    verify_prehashed(&q, &z, sig)
}

fn verify_prehashed(
    q: &ProjectivePoint<Secp256k1>,
    z: &k256::FieldBytes,
    sig: &k256::ecdsa::Signature,
) -> Result<(), &'static str> {
    // let z: Scalar = Scalar::reduce_bytes(z);
    let z =
        <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(z);
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let reproduced = lincomb(&ProjectivePoint::<Secp256k1>::generator(), &u1, q, &u2).to_affine();
    let x = reproduced.x();

    println!("------------- verify_prehashed[beg] -------------");
    println!("z: {z:#?}");
    // println!("r: {r:#?}");
    // println!("s: {s:#?}");
    println!("s_inv {s_inv:#?}");
    println!("u1 {u1:#?}");
    println!("u2 {u2:#?}");
    println!("reproduced {reproduced:#?}");
    println!("reproduced_x {x:#?}");
    println!("------------- verify_prehashed[end] -------------");

    let reduced =
        <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &x,
        );

    println!("reduced {reduced:#?}");

    if *r == reduced {
        Ok(())
    } else {
        Err("error")
    }
}

fn lincomb(
    x: &ProjectivePoint<Secp256k1>,
    k: &Scalar,
    y: &ProjectivePoint<Secp256k1>,
    l: &Scalar,
) -> ProjectivePoint<Secp256k1> {
    (*x * k) + (*y * l)
}

pub mod actions;

use crate::MultichainTestContext;
use crate::{multichain::actions::request_sign, with_multichain_nodes};
use actions::wait_for;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::AffinePoint;
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use secp256k1::XOnlyPublicKey;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(account.id(), account.secret_key())
                .await?;

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
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            // TODO: add test that checks #triples in datastore
            // for account_id in state_0.participants.keys() {
            //     let triple_storage = ctx.nodes.triple_storage(account_id.to_string()).await?;
            //     // This errs out with
            //     // Err(GcpError(BadRequest(Object {"error": Object {"code": Number(400), "message": String("Payload isn't valid for request."), "status": String("INVALID_ARGUMENT")}})))
            //     let _load_res = triple_storage.load().await;
            //     //print!("result is: {:?}", load_res);
            //     //assert_eq!(load_res.len(), 6);
            // }
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            // for i in 0..5 {
            //     actions::single_signature_production(&ctx, &state_0, i).await?;
            // }
            Ok(())
        })
    })
    .await
}

// TODO: working ethereum example for referance
// use std::str::FromStr;

// use web3::{
//     ethabi::ethereum_types::U256,
//     signing::SecretKey,
//     types::{Address, TransactionParameters},
// };

// #[test(tokio::test)]
// async fn test_ecsign_experiment() -> Result<(), Box<dyn std::error::Error>> {
//     let transport = web3::transports::Http::new("https://rpc2.sepolia.org")?;
//     let web3 = web3::Web3::new(transport);

//     let to = Address::from_str("0xa3286628134bad128faeef82f44e99aa64085c93").unwrap();

//     let prvk =
//         SecretKey::from_str("9ea65c28a56227218ae206bacfa424be4da742791d93cb396d0ff5da3cee3736")
//             .unwrap();

//     let tx_object = TransactionParameters {
//         to: Some(to),
//         value: U256::one(),
//         ..Default::default()
//     };

//     let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;

//     let result = web3
//         .eth()
//         .send_raw_transaction(signed.raw_transaction)
//         .await?;

//     println!("Tx succeeded with hash: {}", result);

//     Ok(())
// }

async fn _do_sign(public_key: &String, ctx: &MultichainTestContext<'_>) -> anyhow::Result<()> {
    let (payload, account, tx_hash) = request_sign(&ctx).await?;
    let (signature_big_r, signature_s) = wait_for::signature_responded(&ctx, tx_hash).await?;

    let sig_r = hex::encode(
        k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&signature_big_r, false)
            .as_bytes(),
    );
    let sig_s = hex::encode(signature_s.to_bytes());

    println!("ACCOUNT SK: {:?}", account.secret_key());
    println!("ACCOUNT PK: {:?}", account.secret_key().public_key());
    // println!("SIGNATURE: {:#?}", (signature_big_r, signature_s));
    println!("SIGNATURE: {:#?}", (sig_r, sig_s));

    let mpc_pk: AffinePoint = public_key.clone().into_affine_point();
    let derivation_epsilon: k256::Scalar = kdf::derive_epsilon(account.id(), "test");
    let user_pk: AffinePoint = kdf::derive_key(mpc_pk, derivation_epsilon);
    let y_parity = match user_pk.y_is_odd().unwrap_u8() {
        0 => secp256k1::Parity::Even,
        1 => secp256k1::Parity::Odd,
        _ => unreachable!(),
    };
    let user_pk = x_coordinate::<k256::Secp256k1>(&user_pk);
    // let user_pk = ethers_core::types::U256::from_little_endian(user_pk.x().as_slice());
    let user_pk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&user_pk.to_bytes()).unwrap();
    let user_pk: secp256k1::PublicKey =
        secp256k1::PublicKey::from_x_only_public_key(user_pk, y_parity);
    let user_address = public_key_to_address(&user_pk.into());
    println!("  USER ADDR: {:?}", user_address);

    let r = x_coordinate::<k256::Secp256k1>(&signature_big_r);
    let signature_for_recovery: [u8; 64] = {
        let mut signature = [0u8; 64];
        // signature[..32].copy_from_slice(&signature_big_r.to_bytes()); // TODO: we need to take r, not R
        signature[..32].copy_from_slice(&r.to_bytes());
        signature[32..].copy_from_slice(&signature_s.to_bytes());
        signature
    };

    let recovery_id: i32 = signature_big_r.y_is_odd().unwrap_u8() as i32; // TODO: should it be 0/1 or 27/28, or formula?
    let recovered_address =
        web3::signing::recover(&payload, &signature_for_recovery, recovery_id).unwrap();
    println!("  RECV ADDR: {:?}", recovered_address);

    Ok(())
}

#[test(tokio::test)]
async fn test_pk_recovery() -> anyhow::Result<()> {
    with_multichain_nodes(2, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 2);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            // for _ in 0..2 {
            // println!("state 0 pk: {:?}", state_0.public_key);
            _do_sign(&state_0.public_key, &ctx).await?;
            // }

            // println!("{user_address:?} == {recovered_address:?}");
            // assert_eq!(user_address, recovered_address);
            Ok(())
        })
    })
    .await
}

pub fn public_key_to_address(public_key: &secp256k1::PublicKey) -> web3::types::Address {
    let public_key = public_key.serialize_uncompressed();

    debug_assert_eq!(public_key[0], 0x04);
    let hash = web3::signing::keccak256(&public_key[1..]);

    web3::types::Address::from_slice(&hash[12..])
}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}

use crate::{account, check, key, token, with_nodes};
use hyper::StatusCode;
use mpc_recovery::{
    msg::{NewAccountResponse, SignRequest, SignResponse},
    utils::sign_request_digest,
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_crypto::PublicKey;
use std::{str::FromStr, time::Duration};
use test_log::test;

#[test(tokio::test)]
async fn test_invalid_token() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_secret_key = key::random_sk();
            let user_public_key = user_secret_key.public_key().to_string();
            let oidc_token = token::valid_random();
            let invalid_oidc_token = token::invalid();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    invalid_oidc_token.clone(),
                )
                .await?;
            assert_eq!(status_code, StatusCode::UNAUTHORIZED);
            assert!(matches!(new_acc_response, NewAccountResponse::Err { .. }));

            // Check that the service is still available
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    create_account_options: _,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if acc_id == account_id.to_string()
            ));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            let recovery_pk = ctx
                .leader_node
                .recovery_pk(oidc_token.clone(), user_secret_key.clone())
                .await?;

            let new_user_public_key = key::random_pk();

            let (status_code, sign_response) = ctx
                .leader_node
                .add_key(
                    account_id.clone(),
                    token::invalid(),
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                )
                .await?;
            assert_eq!(status_code, StatusCode::UNAUTHORIZED);
            assert!(matches!(sign_response, SignResponse::Err { .. }));

            // Check that the service is still available
            let (status_code, sign_response) = ctx
                .leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token,
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                )
                .await?;

            assert_eq!(status_code, StatusCode::OK);
            let SignResponse::Ok { .. } = sign_response else {
                anyhow::bail!("failed to get a signature from mpc-recovery");
            };

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_malformed_account_id() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let malformed_account_id = account::malformed();
            let user_secret_key = key::random_sk();
            let user_public_key = user_secret_key.public_key().to_string();
            let oidc_token = token::valid_random();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account_with_helper(
                    malformed_account_id.clone(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?;
            assert_eq!(status_code, StatusCode::BAD_REQUEST);
            assert!(matches!(new_acc_response, NewAccountResponse::Err { .. }));

            let account_id = account::random(ctx.worker)?;

            // Check that the service is still available
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    create_account_options: _,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if acc_id == account_id.to_string()
            ));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            Ok(())
        })
    })
    .await
}

// TODO: uncomment once we can malformed payloads again

// #[tokio::test]
// async fn test_malformed_public_key() -> anyhow::Result<()> {
//     with_nodes(1, |ctx| {
//         Box::pin(async move {
//             let account_id = account::random(ctx.worker)?;
//             let malformed_public_key = key::malformed();
//             let oidc_token = token::valid_random();
//             let user_public_key = key::random();

//             let create_account_options = CreateAccountOptions {
//                 full_access_keys: Some(vec![user_public_key.clone().parse().unwrap()]),
//                 limited_access_keys: None,
//                 contract_bytes: None,
//             };

//             // Check that the service is still available
//             let (status_code, new_acc_response) = ctx
//                 .leader_node
//                 .new_account(NewAccountRequest {
//                     near_account_id: account_id.to_string(),
//                     create_account_options,
//                     oidc_token: oidc_token.clone(),
//                 })
//                 .await?;
//             assert_eq!(status_code, StatusCode::OK);
//             assert!(matches!(new_acc_response, NewAccountResponse::Ok {
//                     create_account_options: _,
//                     user_recovery_public_key: _,
//                     near_account_id: acc_id,
//                 } if acc_id == account_id.to_string()
//             ));

//             tokio::time::sleep(Duration::from_millis(2000)).await;

//             check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

//             let (status_code, add_key_response) = ctx
//                 .leader_node
//                 .add_key(AddKeyRequest {
//                     near_account_id: Some(account_id.to_string()),
//                     oidc_token: oidc_token.clone(),
//                     public_key: malformed_public_key.clone(),
//                 })
//                 .await?;
//             assert_eq!(status_code, StatusCode::BAD_REQUEST);
//             assert!(matches!(add_key_response, AddKeyResponse::Err { .. }));

//             // Check that the service is still available
//             let new_user_public_key = key::random();

//             let (status_code, add_key_response) = ctx
//                 .leader_node
//                 .add_key(AddKeyRequest {
//                     near_account_id: Some(account_id.to_string()),
//                     oidc_token,
//                     create_account_options: CreateAccountOptions {
//                         full_access_keys: Some(vec![new_user_public_key.parse()?]),
//                         limited_access_keys: None,
//                         contract_bytes: None,
//                     },
//                 })
//                 .await?;

//             assert_eq!(status_code, StatusCode::OK);

//             let AddKeyResponse::Ok {
//                 full_access_keys,
//                 limited_access_keys,
//                 near_account_id,
//             } = add_key_response;
//             assert_eq!(full_access_keys, vec![new_user_public_key]);
//             assert_eq!(limited_access_keys, Vec::<String>::new());
//             assert_eq!(near_account_id, account_id.to_string());

//             tokio::time::sleep(Duration::from_millis(2000)).await;

//             check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

//             Ok(())
//         })
//     })
//     .await
// }

#[test(tokio::test)]
async fn test_add_key_to_non_existing_account() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let oidc_token = token::valid_random();
            let user_secret_key = key::random_sk();
            let user_public_key = user_secret_key.public_key().to_string();
            let recovery_pk = key::random_pk();

            let add_key_delegate_action = ctx.leader_node.get_add_key_delegate_action(
                account_id.clone(),
                PublicKey::from_str(&user_public_key)?,
                PublicKey::from_str(&recovery_pk)?,
                1, // random number
                1, // random number
            )?;

            let digest = sign_request_digest(add_key_delegate_action.clone(), oidc_token.clone())?;
            let frp_signature = match user_secret_key.sign(&digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => return Err(anyhow::anyhow!("Wrong signature type")),
            };

            let sign_request = SignRequest {
                delegate_action: add_key_delegate_action.clone(),
                oidc_token: oidc_token.clone(),
                frp_signature,
                frp_public_key: user_public_key,
            };

            let (status_code, sign_response) = ctx.leader_node.sign(sign_request).await?;

            // Sign responce should now fail, since MPC recovery service is no aware if the account exist
            match sign_response {
                SignResponse::Ok { .. } => {}
                _ => anyhow::bail!(
                    "Unexpected error returned during sign call {:?}",
                    sign_response
                ),
            }
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::no_account(&ctx, &account_id).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_reject_new_pk_set() -> anyhow::Result<()> {
    with_nodes(2, |ctx| {
        Box::pin(async move {
            let mut new_pk_set = ctx.pk_set.clone();
            new_pk_set[1] = ExpandedKeyPair::create().public_key;
            // Signer node is already initialized with a pk set, so it should reject different pk set
            let (status_code, result) = ctx.signer_nodes[0]
                .accept_pk_set(mpc_recovery::msg::AcceptNodePublicKeysRequest {
                    public_keys: new_pk_set,
                })
                .await?;
            assert_eq!(status_code, StatusCode::BAD_REQUEST);
            assert!(matches!(result, Err(_)));

            Ok(())
        })
    })
    .await
}

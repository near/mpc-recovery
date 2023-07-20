use crate::{account, check, key, token, with_nodes, MpcCheck};
use hyper::StatusCode;
use mpc_recovery::msg::NewAccountResponse;
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

            ctx.leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    invalid_oidc_token.clone(),
                )
                .await?
                .assert_unauthorized()?;

            // Check that the service is still available
            let new_acc_response = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?
                .assert_ok()?;

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
                .recovery_pk(
                    oidc_token.clone(),
                    user_secret_key.clone(),
                    user_secret_key.clone().public_key(),
                )
                .await?;

            let new_user_public_key = key::random_pk();

            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    token::invalid(),
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                )
                .await?
                .assert_unauthorized()?;

            // Check that the service is still available
            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token,
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                )
                .await?
                .assert_ok()?;

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

            ctx.leader_node
                .new_account_with_helper(
                    malformed_account_id.clone(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?
                .assert_bad_request()?;

            let account_id = account::random(ctx.worker)?;

            // Check that the service is still available
            let new_acc_response = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone())?,
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?
                .assert_ok()?;

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

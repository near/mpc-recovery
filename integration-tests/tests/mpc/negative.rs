use crate::{account, check, key, token, with_nodes, MpcCheck};
use ed25519_dalek::{PublicKey as PublicKeyEd25519, Signature, Verifier};
use hyper::StatusCode;
use mpc_recovery::{
    msg::{ClaimOidcRequest, MpcPkRequest, NewAccountResponse},
    utils::{claim_oidc_request_digest, claim_oidc_response_digest, oidc_digest, sign_digest},
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_crypto::PublicKey;
use std::{str::FromStr, time::Duration};
use test_log::test;

#[test(tokio::test)]
async fn negative_front_running_protection() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            // Preparing user credentials
            let account_id = account::random(ctx.worker)?;
            let user_secret_key =
                near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
            let user_public_key = user_secret_key.public_key();
            let oidc_token = token::valid_random();
            let wrong_oidc_token = token::valid_random();

            // Create account
            ctx.leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    user_public_key.clone(),
                    None,
                    user_secret_key.clone(),
                    oidc_token.clone(),
                )
                .await?
                .assert_ok()?;

            // Making a sign request with unclaimed OIDC token
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
                    oidc_token.clone(),
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                    user_public_key.clone(),
                )
                .await?
                .assert_unauthorized_contains("was not claimed")?;

            // Get MPC public key
            let mpc_pk: PublicKeyEd25519 = ctx
                .leader_node
                .get_mpc_pk(MpcPkRequest {})
                .await?
                .assert_ok()?
                .try_into()?;

            // Prepare the oidc claiming request
            let oidc_token_hash = oidc_digest(&oidc_token);
            let wrong_oidc_token_hash = oidc_digest(&wrong_oidc_token);

            let request_digest =
                claim_oidc_request_digest(oidc_token_hash, user_public_key.clone()).unwrap();
            let wrong_digest =
                claim_oidc_request_digest(wrong_oidc_token_hash, user_public_key.clone()).unwrap();

            let request_digest_signature = sign_digest(&request_digest, &user_secret_key)?;

            let wrong_request_digest_signature = match user_secret_key.sign(&wrong_digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => anyhow::bail!("Wrong signature type"),
            };

            let oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.clone().to_string(),
                frp_signature: request_digest_signature,
            };

            let bad_oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.clone().to_string(),
                frp_signature: wrong_request_digest_signature,
            };

            // Make the claiming request with wrong signature
            ctx.leader_node
                .claim_oidc(bad_oidc_request.clone())
                .await?
                .assert_bad_request_contains("failed to verify signature")?;

            // Making the claiming request with correct signature
            let mpc_signature: Signature = ctx
                .leader_node
                .claim_oidc(oidc_request.clone())
                .await?
                .assert_ok()?
                .try_into()?;

            // Making the same claiming request should fail
            ctx.leader_node
                .claim_oidc(oidc_request.clone())
                .await?
                .assert_bad_request_contains("already claimed")?;

            // Verify signature with wrong digest
            let wrong_response_digest = claim_oidc_response_digest(bad_oidc_request.frp_signature)?;
            if mpc_pk
                .verify(&wrong_response_digest, &mpc_signature)
                .is_ok()
            {
                return Err(anyhow::anyhow!(
                    "Signature verification should fail with wrong digest"
                ));
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_invalid_token() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_secret_key = key::random_sk();
            let user_public_key = user_secret_key.public_key();
            let oidc_token = token::valid_random();
            let invalid_oidc_token = token::invalid();

            // Claim OIDC token
            ctx.leader_node
                .claim_oidc_with_helper(
                    oidc_token.clone(),
                    user_public_key.clone(),
                    user_secret_key.clone(),
                )
                .await?;

            // Claim invalid OIDC token to get proper errors
            ctx.leader_node
                .claim_oidc_with_helper(
                    invalid_oidc_token.clone(),
                    user_public_key.clone(),
                    user_secret_key.clone(),
                )
                .await?;

            // Try to create an account with invalid token
            ctx.leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    user_public_key.clone(),
                    None,
                    user_secret_key.clone(),
                    invalid_oidc_token.clone(),
                )
                .await?
                .assert_unauthorized()?;

            // Try to create an account with valid token
            let new_acc_response = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    user_public_key.clone(),
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

            check::access_key_exists(&ctx, &account_id, &user_public_key.to_string()).await?;

            let recovery_pk = ctx
                .leader_node
                .recovery_pk(
                    oidc_token.clone(),
                    user_secret_key.clone(),
                    user_secret_key.clone().public_key(),
                )
                .await?;

            let new_user_public_key = key::random_pk();

            // Try to add a key with invalid token
            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    invalid_oidc_token.clone(),
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                    user_public_key.clone(),
                )
                .await?
                .assert_unauthorized()?;

            // Try to add a key with valid token
            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token,
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                    user_public_key.clone(),
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

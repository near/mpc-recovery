use crate::mpc::{fetch_recovery_pk, register_account};
use crate::{account, check, key, token, with_nodes, MpcCheck};

use ed25519_dalek::{PublicKey as PublicKeyEd25519, Signature, Verifier};
use hyper::StatusCode;
use mpc_recovery::{
    msg::{ClaimOidcRequest, MpcPkRequest, NewAccountResponse, UserCredentialsResponse},
    utils::{claim_oidc_request_digest, claim_oidc_response_digest, oidc_digest, sign_digest},
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_crypto::PublicKey;
use near_primitives::{
    account::AccessKey,
    delegate_action::DelegateAction,
    transaction::{
        Action, AddKeyAction, CreateAccountAction, DeleteAccountAction, DeleteKeyAction,
        DeployContractAction, FunctionCallAction, StakeAction, TransferAction,
    },
};
use std::{str::FromStr, time::Duration};
use test_log::test;
use workspaces::AccountId;

#[test(tokio::test)]
async fn whitlisted_actions_test() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            // Preparing user credentials
            let account_id = account::random(ctx.worker)?;
            let user_secret_key =
                near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
            let user_public_key = user_secret_key.public_key();
            let oidc_token = token::valid_random();

            // Claim OIDC token
            ctx.leader_node
                .claim_oidc_with_helper(&oidc_token, &user_public_key, &user_secret_key)
                .await?;

            // Create account with claimed OIDC token
            ctx.leader_node
                .new_account_with_helper(
                    &account_id,
                    &user_public_key,
                    None,
                    &user_secret_key,
                    &oidc_token,
                )
                .await?
                .assert_ok()?;

            // Performing whitelisted actions
            let whitelisted_actions = vec![ActionType::AddKey, ActionType::DeleteKey];

            for whitelisted_action in whitelisted_actions {
                ctx.leader_node
                    .perform_delegate_action_with_helper(
                        &get_stub_delegate_action(whitelisted_action)?,
                        &oidc_token,
                        &user_secret_key,
                        &user_public_key,
                    )
                    .await?
                    .assert_ok()?;
            }

            // Performing blacklisted actions
            let blacklisted_actions = vec![
                ActionType::CreateAccount,
                ActionType::DeployContract,
                ActionType::FunctionCall,
                ActionType::Transfer,
                ActionType::Stake,
                ActionType::DeleteAccount,
            ];

            for blacklisted_action in blacklisted_actions {
                ctx.leader_node
                    .perform_delegate_action_with_helper(
                        &get_stub_delegate_action(blacklisted_action)?,
                        &oidc_token,
                        &user_secret_key,
                        &user_public_key,
                    )
                    .await?
                    .assert_bad_request_contains("action can not be performed")?;
            }

            // Client should not be able to delete their recovery key
            let recovery_pk = match ctx
                .leader_node
                .user_credentials_with_helper(
                    &oidc_token,
                    &user_secret_key,
                    &user_secret_key.public_key(),
                )
                .await?
                .assert_ok()?
            {
                UserCredentialsResponse::Ok { recovery_pk } => PublicKey::from_str(&recovery_pk)?,
                UserCredentialsResponse::Err { msg } => {
                    return Err(anyhow::anyhow!("error response: {}", msg))
                }
            };

            ctx.leader_node
                .delete_key_with_helper(
                    &account_id,
                    &oidc_token,
                    &recovery_pk,
                    &recovery_pk,
                    &user_secret_key,
                    &user_public_key,
                )
                .await?
                .assert_bad_request_contains("Recovery key can not be deleted")?;

            tokio::time::sleep(Duration::from_millis(2000)).await;
            check::access_key_exists(&ctx, &account_id, &recovery_pk).await?;

            // Deletion of the regular key should work
            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            ctx.leader_node
                .delete_key_with_helper(
                    &account_id,
                    &oidc_token,
                    &user_public_key,
                    &recovery_pk,
                    &user_secret_key,
                    &user_public_key,
                )
                .await?
                .assert_ok()?;

            tokio::time::sleep(Duration::from_millis(2000)).await;
            check::access_key_does_not_exists(&ctx, &account_id, &user_public_key.to_string())
                .await?;

            Ok(())
        })
    })
    .await
}

pub enum ActionType {
    CreateAccount,
    DeployContract,
    FunctionCall,
    Transfer,
    Stake,
    AddKey,
    DeleteKey,
    DeleteAccount,
}

fn get_stub_delegate_action(action_type: ActionType) -> anyhow::Result<DelegateAction> {
    let action: Action = match action_type {
        ActionType::CreateAccount => Action::CreateAccount(CreateAccountAction {}),
        ActionType::DeployContract => Action::DeployContract(DeployContractAction { code: vec![] }),
        ActionType::FunctionCall => Action::FunctionCall(FunctionCallAction {
            method_name: "test".to_string(),
            args: vec![],
            gas: 0,
            deposit: 0,
        }),
        ActionType::Transfer => Action::Transfer(TransferAction { deposit: 0 }),
        ActionType::Stake => Action::Stake(StakeAction {
            stake: 0,
            public_key: key::random_sk().public_key(),
        }),
        ActionType::AddKey => Action::AddKey(AddKeyAction {
            public_key: key::random_sk().public_key(),
            access_key: AccessKey::full_access(),
        }),
        ActionType::DeleteKey => Action::DeleteKey(DeleteKeyAction {
            public_key: key::random_sk().public_key(),
        }),
        ActionType::DeleteAccount => Action::DeleteAccount(DeleteAccountAction {
            beneficiary_id: AccountId::from_str("test.near").unwrap(),
        }),
    };
    Ok(DelegateAction {
        sender_id: AccountId::from_str("test.near").unwrap(),
        receiver_id: AccountId::from_str("test.near").unwrap(),
        actions: vec![action.try_into()?],
        nonce: 1,
        max_block_height: 1,
        public_key: key::random_sk().public_key(),
    })
}

#[test(tokio::test)]
async fn negative_front_running_protection() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            // Preparing user credentials
            let account_id = account::random(ctx.worker)?;
            let user_secret_key =
                near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
            let user_public_key = user_secret_key.public_key();
            let oidc_token_1 = token::valid_random();
            let oidc_token_2 = token::valid_random();
            let wrong_oidc_token = token::valid_random();

            // Create account before claiming OIDC token
            // This part of the test is commented since account creation is not atomic (known issue)
            // Relayer is wasting a token even if account was not created
            // ctx.leader_node
            //     .new_account_with_helper(
            //         account_id.to_string(),
            //         user_public_key.clone(),
            //         None,
            //         user_secret_key.clone(),
            //         oidc_token_1.clone(),
            //     )
            //     .await?
            //     .assert_unauthorized_contains("was not claimed")?;

            // Get user recovery PK before claiming OIDC token
            ctx.leader_node
                .user_credentials_with_helper(&oidc_token_1, &user_secret_key, &user_public_key)
                .await?
                .assert_unauthorized_contains("was not claimed")?;

            register_account(
                &ctx,
                &account_id,
                &user_secret_key,
                &user_public_key,
                &oidc_token_1,
                None,
            )
            .await?;

            // Making a sign request with unclaimed OIDC token
            let recovery_pk = fetch_recovery_pk(&ctx, &user_secret_key, &oidc_token_1).await?;

            let new_user_public_key = key::random_pk();

            ctx.leader_node
                .add_key_with_helper(
                    &account_id,
                    &oidc_token_2,
                    &new_user_public_key,
                    &recovery_pk,
                    &user_secret_key,
                    &user_public_key,
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
            let oidc_token_hash = oidc_digest(&oidc_token_2);
            let wrong_oidc_token_hash = oidc_digest(&wrong_oidc_token);

            let request_digest =
                claim_oidc_request_digest(oidc_token_hash, &user_public_key).unwrap();
            let wrong_digest =
                claim_oidc_request_digest(wrong_oidc_token_hash, &user_public_key).unwrap();

            let request_digest_signature = sign_digest(&request_digest, &user_secret_key)?;

            let wrong_request_digest_signature = match user_secret_key.sign(&wrong_digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => anyhow::bail!("Wrong signature type"),
            };

            let oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.to_string(),
                frp_signature: request_digest_signature,
            };

            let bad_oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.to_string(),
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

            // Making the same claiming request should NOT fail
            ctx.leader_node
                .claim_oidc(oidc_request.clone())
                .await?
                .assert_ok()?;

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

            // It should not be possible to make the claiming with another key
            let new_oidc_token = token::valid_random();
            let user_sk = key::random_sk();
            let user_pk = user_sk.public_key();
            let atacker_sk = key::random_sk();
            let atacker_pk = atacker_sk.public_key();

            // User claims the token
            ctx.leader_node
                .claim_oidc_with_helper(&new_oidc_token, &user_pk, &user_sk)
                .await?
                .assert_ok()?;

            // Attacker tries to claim the token
            ctx.leader_node
                .claim_oidc_with_helper(&new_oidc_token, &atacker_pk, &atacker_sk)
                .await?
                .assert_bad_request_contains("already claimed with another key")?;

            // Sign request with claimed token but wrong key should fail
            ctx.leader_node
                .add_key_with_helper(
                    &account_id,
                    &new_oidc_token,
                    &new_user_public_key,
                    &recovery_pk,
                    &atacker_sk,
                    &atacker_pk,
                )
                .await?
                .assert_unauthorized_contains("was claimed with another key")?;

            // User Credentials request with claimed token but wrong key should fail
            ctx.leader_node
                .user_credentials_with_helper(&new_oidc_token, &atacker_sk, &atacker_pk)
                .await?
                .assert_unauthorized_contains("was claimed with another key")?;

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
                .claim_oidc_with_helper(&oidc_token, &user_public_key, &user_secret_key)
                .await?;

            // Claim invalid OIDC token to get proper errors
            ctx.leader_node
                .claim_oidc_with_helper(&invalid_oidc_token, &user_public_key, &user_secret_key)
                .await?;

            // Try to create an account with invalid token
            ctx.leader_node
                .new_account_with_helper(
                    &account_id,
                    &user_public_key,
                    None,
                    &user_secret_key,
                    &invalid_oidc_token,
                )
                .await?
                .assert_unauthorized()?;

            // Try to create an account with valid token
            let new_acc_response = ctx
                .leader_node
                .new_account_with_helper(
                    &account_id,
                    &user_public_key,
                    None,
                    &user_secret_key,
                    &oidc_token,
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

            let recovery_pk = match ctx
                .leader_node
                .user_credentials_with_helper(&oidc_token, &user_secret_key, &user_public_key)
                .await?
                .assert_ok()?
            {
                UserCredentialsResponse::Ok { recovery_pk } => PublicKey::from_str(&recovery_pk)?,
                UserCredentialsResponse::Err { msg } => anyhow::bail!("error response: {}", msg),
            };

            let new_user_public_key = key::random_pk();

            // Try to add a key with invalid token
            ctx.leader_node
                .add_key_with_helper(
                    &account_id,
                    &invalid_oidc_token,
                    &new_user_public_key,
                    &recovery_pk,
                    &user_secret_key,
                    &user_public_key,
                )
                .await?
                .assert_unauthorized()?;

            // Try to add a key with valid token
            ctx.leader_node
                .add_key_with_helper(
                    &account_id,
                    &oidc_token,
                    &new_user_public_key,
                    &recovery_pk,
                    &user_secret_key,
                    &user_public_key,
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
            let user_public_key = user_secret_key.public_key();
            let oidc_token = token::valid_random();

            ctx.leader_node
                .claim_oidc_with_helper(&oidc_token, &user_public_key, &user_secret_key)
                .await?;

            ctx.leader_node
                .new_account_with_helper(
                    &malformed_account_id,
                    &user_public_key,
                    None,
                    &user_secret_key,
                    &oidc_token,
                )
                .await?
                .assert_bad_request()?;

            let account_id = account::random(ctx.worker)?;
            let account_id_repr = account_id.to_string();

            // Check that the service is still available
            let new_acc_response = ctx
                .leader_node
                .new_account_with_helper(
                    &account_id_repr,
                    &user_public_key,
                    None,
                    &user_secret_key,
                    &oidc_token,
                )
                .await?
                .assert_ok()?;

            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    create_account_options: _,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if acc_id == account_id_repr
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

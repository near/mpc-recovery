use crate::cases::{fetch_recovery_pk, register_account};
use crate::{account, check, key, with_nodes, MpcCheck};
use anyhow::Context;
use ed25519_dalek::{PublicKey as PublicKeyEd25519, Signature, Verifier};
use hyper::StatusCode;
use integration_tests_fastauth::util;
use mpc_recovery::sign_node::oidc::OidcToken;
use mpc_recovery::utils::user_credentials_request_digest;
use mpc_recovery::{
    msg::{ClaimOidcRequest, MpcPkRequest, NewAccountResponse, UserCredentialsResponse},
    utils::{claim_oidc_request_digest, claim_oidc_response_digest, sign_digest},
};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use near_primitives::{
    account::AccessKey,
    delegate_action::DelegateAction,
    transaction::{
        Action, AddKeyAction, CreateAccountAction, DeleteAccountAction, DeleteKeyAction,
        DeployContractAction, FunctionCallAction, StakeAction, TransferAction,
    },
    types::AccountId,
};
use std::{str::FromStr, time::Duration};
use test_log::test;

#[test(tokio::test)]
async fn whitlisted_actions_test() -> anyhow::Result<()> {
    with_nodes(3, |ctx| async move {
        // Preparing user credentials
        let account_id = account::random(&ctx.worker)?;
        let user_secret_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
        let user_public_key = user_secret_key.public_key();
        let oidc_token = OidcToken::random_valid();

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
                .sign_with_helper(
                    &get_stub_delegate_action(whitelisted_action)?,
                    &oidc_token,
                    &user_secret_key,
                    &user_public_key,
                )
                .await?
                .assert_ok()?;
        }

        // Performing blacklisted actions
        let blacklisted_actions = vec![ActionType::DeleteAccount];

        for blacklisted_action in blacklisted_actions {
            ctx.leader_node
                .sign_with_helper(
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
            UserCredentialsResponse::Ok { recovery_pk } => recovery_pk,
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
            .assert_bad_request_contains("recovery key can not be deleted")?;

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
        check::access_key_does_not_exists(&ctx, &account_id, &user_public_key.to_string()).await?;

        Ok(())
    })
    .await
}

pub enum ActionType {
    _CreateAccount,
    _DeployContract,
    _FunctionCall,
    _Transfer,
    _Stake,
    AddKey,
    DeleteKey,
    DeleteAccount,
}

fn get_stub_delegate_action(action_type: ActionType) -> anyhow::Result<DelegateAction> {
    let action: Action = match action_type {
        ActionType::_CreateAccount => Action::CreateAccount(CreateAccountAction {}),
        ActionType::_DeployContract => {
            Action::DeployContract(DeployContractAction { code: vec![] })
        }
        ActionType::_FunctionCall => Action::FunctionCall(FunctionCallAction {
            method_name: "test".to_string(),
            args: vec![],
            gas: 0,
            deposit: 0,
        }),
        ActionType::_Transfer => Action::Transfer(TransferAction { deposit: 0 }),
        ActionType::_Stake => Action::Stake(StakeAction {
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
    with_nodes(3, |ctx| async move {
        // Preparing user credentials
        let account_id = account::random(&ctx.worker)?;
        let user_secret_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
        let user_public_key = user_secret_key.public_key();
        let oidc_token_1 = OidcToken::random_valid();
        let oidc_token_2 = OidcToken::random_valid();
        let wrong_oidc_token = OidcToken::random_valid();

        // Create account before claiming OIDC token
        ctx.leader_node
            .new_account_with_helper(
                &account_id,
                &user_public_key,
                None,
                &user_secret_key,
                &oidc_token_1,
            )
            .await?
            .assert_unauthorized_contains("was not claimed")?;

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
        let oidc_token_hash = oidc_token_2.digest_hash();
        let wrong_oidc_token_hash = wrong_oidc_token.digest_hash();

        let request_digest = claim_oidc_request_digest(&oidc_token_hash, &user_public_key).unwrap();
        let wrong_digest =
            claim_oidc_request_digest(&wrong_oidc_token_hash, &user_public_key).unwrap();

        let request_digest_signature = sign_digest(&request_digest, &user_secret_key)?;

        let wrong_request_digest_signature = match user_secret_key.sign(&wrong_digest) {
            near_crypto::Signature::ED25519(k) => k,
            _ => anyhow::bail!("Wrong signature type"),
        };

        let oidc_request = ClaimOidcRequest {
            oidc_token_hash: oidc_token_hash.clone(),
            frp_public_key: user_public_key.clone(),
            frp_signature: request_digest_signature,
        };

        let bad_oidc_request = ClaimOidcRequest {
            oidc_token_hash,
            frp_public_key: user_public_key,
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
        let new_oidc_token = OidcToken::random_valid();
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
    .await
}

#[test(tokio::test)]
async fn test_invalid_token() -> anyhow::Result<()> {
    with_nodes(1, |ctx| async move {
        let account_id = account::random(&ctx.worker)?;
        let user_secret_key = key::random_sk();
        let user_public_key = user_secret_key.public_key();
        let oidc_token = OidcToken::random_valid();
        let invalid_oidc_token = OidcToken::invalid();

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
            } if acc_id.as_str() == account_id.as_str()
        ));

        tokio::time::sleep(Duration::from_millis(2000)).await;

        check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

        let recovery_pk = match ctx
            .leader_node
            .user_credentials_with_helper(&oidc_token, &user_secret_key, &user_public_key)
            .await?
            .assert_ok()?
        {
            UserCredentialsResponse::Ok { recovery_pk } => recovery_pk,
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
    .await
}

#[test(tokio::test)]
async fn test_reject_new_pk_set() -> anyhow::Result<()> {
    with_nodes(2, |ctx| async move {
        let mut new_pk_set = ctx.pk_set.clone();
        new_pk_set[1] = ExpandedKeyPair::create().public_key;
        // Signer node is already initialized with a pk set, so it should reject different pk set
        let (status_code, result) = ctx.signer_nodes[0]
            .accept_pk_set(mpc_recovery::msg::AcceptNodePublicKeysRequest {
                public_keys: new_pk_set,
            })
            .await?;
        assert_eq!(status_code, StatusCode::BAD_REQUEST);
        assert!(result.is_err());

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_malformed_raw_create_account() -> anyhow::Result<()> {
    let user_oidc = OidcToken::random_valid();
    let (user_sk, user_pk) = key::random();
    let digest = user_credentials_request_digest(&user_oidc, &user_pk)?;
    let near_crypto::Signature::ED25519(frp_signature) = user_sk.sign(&digest) else {
        anyhow::bail!("Wrong signature type");
    };

    let template_new_account = serde_json::json!({
        "near_account_id": "groot",
        "create_account_options": {
            "full_access_keys": Some(vec![&user_pk]),
            "limited_access_keys": serde_json::Value::Null,
            "contract_bytes": serde_json::Value::Null,
        },
        "oidc_token": user_oidc,
        "user_credentials_frp_signature": hex::encode(frp_signature),
        "frp_public_key": user_pk,
    });

    let malformed_cases = {
        let mut invalid_account_req = template_new_account.clone();
        invalid_account_req["near_account_id"] = account::malformed().into();

        let mut invalid_user_key_req = template_new_account.clone();
        let malformed_key = key::malformed_pk();
        invalid_user_key_req["create_account_options"]["full_access_keys"] =
            malformed_key.clone().into();
        invalid_user_key_req["frp_public_key"] = malformed_key.into();

        let mut invalid_oidc_token_req = template_new_account.clone();
        invalid_oidc_token_req["oidc_token"] = serde_json::to_value(OidcToken::invalid())?;

        let mut invalid_frp_signature_req = template_new_account.clone();
        // create invalid sig by having the first 16 bytes of the signature be 0:
        let mut invalid_sig = frp_signature.to_bytes();
        invalid_sig[0..16].copy_from_slice(&[0; 16]);
        invalid_frp_signature_req["user_credentials_frp_signature"] = serde_json::to_value(
            hex::encode(ed25519_dalek::Signature::from_bytes(&invalid_sig)?),
        )?;

        [
            (
                invalid_account_req,
                (StatusCode::UNPROCESSABLE_ENTITY, "Failed to deserialize the JSON body into the target type: near_account_id: invalid value:")),
            (
                invalid_user_key_req,
                (StatusCode::UNPROCESSABLE_ENTITY, "Failed to deserialize the JSON body into the target type: create_account_options.full_access_keys")
            ),
            (
                invalid_oidc_token_req,
                (StatusCode::UNAUTHORIZED, "failed to verify oidc token"),
            ),
            (
                invalid_frp_signature_req,
                (StatusCode::BAD_REQUEST, "failed to verify signature: Public key"),
            )
        ]
    };

    with_nodes(1, |ctx| async move {
        ctx.leader_node
            .claim_oidc_with_helper(&user_oidc, &user_pk, &user_sk)
            .await?;

        for (case_idx, (invalid_req, (expected_status_code, expected_msg))) in
            malformed_cases.into_iter().enumerate()
        {
            let (code, msg): (StatusCode, serde_json::Value) =
                util::post(
                    format!("{}/new_account", ctx.leader_node.address),
                    invalid_req,
                )
                .await
                .context("failed to send request")?;

            assert_eq!(
                code, expected_status_code,
                "wrong status code [case={case_idx}]:\n   expected: `{expected_msg}`\n     actual: `{msg}`"
            );
            assert!(
                msg.to_string().contains(expected_msg),
                "wrong error message [case={case_idx}]: `{expected_msg}` not in `{msg}`",
            );
        }

        // Check that the service is still available
        let account_id = account::random(&ctx.worker)?;
        let new_acc_response = ctx
            .leader_node
            .new_account_with_helper(
                &account_id,
                &user_pk,
                None,
                &user_sk,
                &user_oidc,
            )
            .await?
            .assert_ok()?;

        assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                create_account_options: _,
                user_recovery_public_key: _,
                near_account_id,
            } if near_account_id.as_str() == account_id.as_str()
        ));

        tokio::time::sleep(Duration::from_millis(2000)).await;
        check::access_key_exists(&ctx, &account_id, &user_pk).await?;

        Ok(())
    })
    .await
}

#[test(tokio::test)]
async fn test_account_creation_should_work_on_second_attempt() -> anyhow::Result<()> {
    with_nodes(2, |ctx| async move {
        let account_id = account::random(&ctx.worker)?;
        let user_secret_key = key::random_sk();
        let user_public_key = user_secret_key.public_key();
        let oidc_token = OidcToken::random_valid();

        ctx.leader_node
            .new_account_with_helper(
                &account_id,
                &user_public_key,
                None,
                &user_secret_key,
                &oidc_token,
            )
            .await?
            .assert_unauthorized_contains("was not claimed")?;

        register_account(
            &ctx,
            &account_id,
            &user_secret_key,
            &user_public_key,
            &oidc_token,
            None,
        )
        .await?;

        Ok(())
    })
    .await
}

#[test(tokio::test)]
async fn test_creation_of_two_account_with_the_same_oidc_should_not_be_possible(
) -> anyhow::Result<()> {
    with_nodes(2, |ctx| async move {
        let account_id = account::random(&ctx.worker)?;
        let account_id_2 = account::random(&ctx.worker)?;
        let user_secret_key = key::random_sk();
        let user_public_key = user_secret_key.public_key();
        let oidc_token = OidcToken::random_valid();

        ctx.leader_node
            .claim_oidc_with_helper(&oidc_token, &user_public_key, &user_secret_key)
            .await?
            .assert_ok()?;

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

        ctx.leader_node
            .new_account_with_helper(
                &account_id_2,
                &user_public_key,
                None,
                &user_secret_key,
                &oidc_token,
            )
            .await?
            .assert_dependency_error_contains("You can only register 1 account per oauth_token")?;

        Ok(())
    })
    .await
}

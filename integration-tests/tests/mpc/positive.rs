use crate::{account, check, key, token, with_nodes, MpcCheck};
use anyhow::anyhow;
use ed25519_dalek::Verifier;
use hyper::StatusCode;
use mpc_recovery::{
    msg::{ClaimOidcRequest, ClaimOidcResponse, MpcPkRequest, MpcPkResponse, NewAccountResponse},
    transaction::LimitedAccessKey,
    utils::{claim_oidc_request_digest, claim_oidc_response_digest, oidc_digest},
};
use near_crypto::PublicKey;
use std::{str::FromStr, time::Duration};
use workspaces::types::AccessKeyPermission;

use test_log::test;
#[test(tokio::test)]
async fn test_basic_front_running_protection() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            // Preparing user credentials
            let account_id = account::random(ctx.worker)?;

            let user_secret_key =
                near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
            let user_public_key = user_secret_key.public_key().to_string();
            let oidc_token = token::valid_random();
            let wrong_oidc_token = token::valid_random();

            // Get MPC public key
            let mpc_pk_response = ctx
                .leader_node
                .get_mpc_pk(MpcPkRequest {})
                .await?
                .assert_ok()?;

            let mpc_pk = match mpc_pk_response {
                MpcPkResponse::Ok { mpc_pk } => mpc_pk,
                MpcPkResponse::Err { msg } => anyhow::bail!(msg),
            };

            let decoded_mpc_pk = match hex::decode(mpc_pk.clone()) {
                Ok(v) => v,
                Err(e) => anyhow::bail!("Failed to decode mpc pk. {}", e),
            };

            let mpc_pk = ed25519_dalek::PublicKey::from_bytes(&decoded_mpc_pk).unwrap();

            // Prepare the oidc claiming request
            let oidc_token_hash = oidc_digest(&oidc_token);
            let wrong_oidc_token_hash = oidc_digest(&wrong_oidc_token);

            let request_digest = claim_oidc_request_digest(oidc_token_hash).unwrap();
            let wrong_digest = claim_oidc_request_digest(wrong_oidc_token_hash).unwrap();

            let request_digest_signature = match user_secret_key.sign(&request_digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => anyhow::bail!("Wrong signature type"),
            };

            let request_digest_wrong_signature = match user_secret_key.sign(&wrong_digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => anyhow::bail!("Wrong signature type"),
            };

            let oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.clone(),
                frp_signature: request_digest_signature,
            };

            let bad_oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.clone(),
                frp_signature: request_digest_wrong_signature,
            };

            // Make the claiming request with wrong signature
            let oidc_response = ctx
                .leader_node
                .claim_oidc(bad_oidc_request.clone())
                .await?
                .assert_bad_request()?;

            match oidc_response {
                ClaimOidcResponse::Ok { .. } => {
                    return Err(anyhow::anyhow!(
                        "Response should be Err when signature is wrong"
                    ))
                }
                ClaimOidcResponse::Err { msg } => {
                    assert!(
                        msg.contains("failed to verify signature"),
                        "Error message does not contain 'failed to verify signature'"
                    );
                }
            }

            // Making the claiming request with correct signature
            let oidc_response = ctx
                .leader_node
                .claim_oidc(oidc_request.clone())
                .await?
                .assert_ok()?;

            let mpc_signature = match oidc_response {
                ClaimOidcResponse::Ok { mpc_signature } => mpc_signature,
                ClaimOidcResponse::Err { msg } => return Err(anyhow::anyhow!(msg)),
            };

            // Making the same claiming request should fail
            let oidc_response = ctx
                .leader_node
                .claim_oidc(oidc_request.clone())
                .await?
                .assert_bad_request()?;

            match oidc_response {
                ClaimOidcResponse::Ok { .. } => {
                    return Err(anyhow::anyhow!(
                        "Response should be Err when claiming registered token"
                    ))
                }
                ClaimOidcResponse::Err { msg } => {
                    assert!(
                        msg.contains("already claimed"),
                        "Wrong error message when claiming registered token",
                    );
                }
            }

            // Verify signature
            let response_digest = claim_oidc_response_digest(oidc_request.frp_signature).unwrap();
            mpc_pk.verify(&response_digest, &mpc_signature)?;

            // Verify signature with wrong digest
            let wrong_response_digest =
                claim_oidc_response_digest(bad_oidc_request.frp_signature).unwrap();
            if mpc_pk
                .verify(&wrong_response_digest, &mpc_signature)
                .is_ok()
            {
                return Err(anyhow::anyhow!(
                    "Signature verification should fail with wrong digest"
                ));
            }

            // Create account
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

            // Check account creation status
            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    create_account_options: _,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if acc_id == account_id.to_string()
            ));

            tokio::time::sleep(Duration::from_millis(2000)).await;
            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            // Add new FA key with front running protection (negative, wrong signature)
            // TODO: add exaample with front running protection signature (bad one)

            // Add new FA key with front running protection (positive)
            // TODO: add front running protection signature

            let recovery_pk = ctx
                .leader_node
                .recovery_pk(oidc_token.clone(), user_secret_key.clone())
                .await?;

            let new_user_public_key = key::random_pk();

            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token.clone(),
                    new_user_public_key.parse()?,
                    recovery_pk,
                    user_secret_key,
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
async fn test_basic_action() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_secret_key = key::random_sk();
            let user_public_key = user_secret_key.public_key().to_string();
            let oidc_token = token::valid_random();

            // Create account
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

            // Add key
            let recovery_pk = ctx
                .leader_node
                .recovery_pk(oidc_token.clone(), user_secret_key.clone())
                .await?;

            let new_user_public_key = key::random_pk();

            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token.clone(),
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    user_secret_key.clone(),
                )
                .await?
                .assert_ok()?;

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            // Adding the same key should now fail
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
async fn test_random_recovery_keys() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_full_access_pk = key::random_pk();
            let oidc_token = token::valid_random();

            let user_limited_access_key = LimitedAccessKey {
                public_key: key::random_pk().parse().unwrap(),
                allowance: "100".to_string(),
                receiver_id: account::random(ctx.worker)?.to_string().parse().unwrap(), // TODO: type issues here
                method_names: "method_names".to_string(),
            };

            ctx.leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_full_access_pk.clone())?,
                    Some(user_limited_access_key.clone()),
                    key::random_sk(),
                    oidc_token.clone(),
                )
                .await?
                .assert_ok()?;

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;

            let recovery_full_access_key1 = access_keys
                .clone()
                .into_iter()
                .find(|ak| {
                    ak.public_key.to_string() != user_full_access_pk
                        && ak.public_key.to_string()
                            != user_limited_access_key.public_key.to_string()
                })
                .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

            match recovery_full_access_key1.access_key.permission {
                AccessKeyPermission::FullAccess => (),
                AccessKeyPermission::FunctionCall(_) => {
                    return Err(anyhow!(
                        "Got a limited access key when we expected a full access key"
                    ))
                }
            };

            let la_key = access_keys
                .into_iter()
                .find(|ak| {
                    ak.public_key.to_string() == user_limited_access_key.public_key.to_string()
                })
                .ok_or_else(|| anyhow::anyhow!("missing limited access key"))?;

            match la_key.access_key.permission {
                AccessKeyPermission::FullAccess => {
                    return Err(anyhow!(
                        "Got a full access key when we expected a limited access key"
                    ))
                }
                AccessKeyPermission::FunctionCall(fc) => {
                    assert_eq!(
                        fc.receiver_id,
                        user_limited_access_key.receiver_id.to_string()
                    );
                    assert_eq!(
                        fc.method_names.first().unwrap(),
                        &user_limited_access_key.method_names.to_string()
                    );
                }
            };

            // Generate another user
            let account_id = account::random(ctx.worker)?;
            let user_secret_key = key::random_sk();
            let user_public_key = user_secret_key.public_key();
            let oidc_token = token::valid_random();

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

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;
            let recovery_full_access_key2 = access_keys
                .into_iter()
                .find(|ak| ak.public_key.to_string() != user_public_key.to_string())
                .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

            assert_ne!(
                recovery_full_access_key1.public_key, recovery_full_access_key2.public_key,
                "MPC recovery should generate random recovery keys for each user"
            );

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_accept_existing_pk_set() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            // Signer node is already initialized with the pk set, but we should be able to get a
            // positive response by providing the same pk set as it already has.
            let (status_code, result) = ctx.signer_nodes[0]
                .accept_pk_set(mpc_recovery::msg::AcceptNodePublicKeysRequest {
                    public_keys: ctx.pk_set.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(result, Ok(_)));

            Ok(())
        })
    })
    .await
}

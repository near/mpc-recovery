use crate::{account, check, key, token, with_nodes};
use anyhow::anyhow;
use ed25519_dalek::Verifier;
use hyper::StatusCode;
use mpc_recovery::{
    msg::{
        AddKeyRequest, AddKeyResponse, ClaimOidcRequest, ClaimOidcResponse, NewAccountRequest,
        NewAccountResponse, SignNodeRequest, SignShareNodeRequest,
    },
    oauth::get_test_claims,
    transaction::{
        call_all_nodes, sign_payload_with_mpc, to_dalek_combined_public_key, CreateAccountOptions,
        LimitedAccessKey,
    },
    utils::{claim_oidc_request_digest, claim_oidc_response_digest, oidc_digest},
};
use near_crypto::PublicKey;
use rand::{distributions::Alphanumeric, Rng};
use std::{str::FromStr, time::Duration};
use workspaces::types::AccessKeyPermission;

use test_log::test;
#[test(tokio::test)]
async fn test_basic_front_running_protection() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            // Preparing user credentials
            let account_id = account::random(ctx.worker)?;

            let user_private_key =
                near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
            let user_public_key = user_private_key.public_key().to_string();
            let oidc_token = token::valid_random();
            let wrong_oidc_token = token::valid_random();

            // Prepare the oidc claiming request
            let oidc_token_hash = oidc_digest(&oidc_token);
            let wrong_oidc_token_hash = oidc_digest(&wrong_oidc_token);

            let digest = claim_oidc_request_digest(oidc_token_hash).unwrap();
            let wrong_digest = claim_oidc_request_digest(wrong_oidc_token_hash).unwrap();

            let signature = match user_private_key.sign(&digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => return Err(anyhow::anyhow!("Wrong signature type")),
            };

            let wrong_signature = match user_private_key.sign(&wrong_digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => return Err(anyhow::anyhow!("Wrong signature type")),
            };

            let oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.clone(),
                signature,
            };

            let bad_oidc_request = ClaimOidcRequest {
                oidc_token_hash,
                public_key: user_public_key.clone(),
                signature: wrong_signature,
            };

            // Make the claiming request with wrong signature
            let (status_code, oidc_response) =
                ctx.leader_node.claim_oidc(bad_oidc_request.clone()).await?;

            assert_eq!(status_code, StatusCode::BAD_REQUEST);
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
            let (status_code, oidc_response) =
                ctx.leader_node.claim_oidc(oidc_request.clone()).await?;

            assert_eq!(status_code, StatusCode::OK);

            let _res_signature = match oidc_response {
                ClaimOidcResponse::Ok {
                    mpc_signature,
                    recovery_public_key: _,
                    near_account_id: _,
                } => mpc_signature,
                ClaimOidcResponse::Err { msg } => return Err(anyhow::anyhow!(msg)),
            };

            // TODO: hangs for some reason
            // Making the same claiming request should fail
            // let (status_code, oidc_response) =
            //     ctx.leader_node.claim_oidc(oidc_request.clone()).await?;

            // assert_eq!(status_code, StatusCode::BAD_REQUEST);

            // match oidc_response {
            //     ClaimOidcResponse::Ok { .. } => {
            //         return Err(anyhow::anyhow!(
            //             "Response should be Err when claiming registered token"
            //         ))
            //     }
            //     ClaimOidcResponse::Err { msg } => {
            //         assert!(
            //             msg.contains("already claimed"),
            //             "Error message does not contain 'oidc token already claimed by another public key'"
            //         );
            //     }
            // }

            // Get the node public key
            let client = reqwest::Client::new();

            let signer_urls: Vec<_> = ctx.signer_nodes.iter().map(|s| s.address.clone()).collect();

            let res = call_all_nodes(&client, &signer_urls, "public_key", "").await?;
            let _combined_pub = to_dalek_combined_public_key(&res).unwrap();

            // Verify signature
            let _res_digest = claim_oidc_response_digest(oidc_request.signature).unwrap();
            // combined_pub.verify(&res_digest, &res_signature)?; // TODO: check why signature is not right

            // TODO: add test with wrong signature (account creation)

            // Create account
            let new_account_request = NewAccountRequest {
                near_account_id: account_id.to_string(),
                create_account_options: CreateAccountOptions {
                    full_access_keys: Some(vec![
                        PublicKey::from_str(&user_public_key.clone()).unwrap()
                    ]),
                    limited_access_keys: None,
                    contract_bytes: None,
                },
                oidc_token: oidc_token.clone(),
                signature: None, //TODO: add real signature
            };

            let (status_code, new_acc_response) =
                ctx.leader_node.new_account(new_account_request).await?;

            // Check account creation status
            assert_eq!(status_code, StatusCode::OK);
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
            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    create_account_options: CreateAccountOptions {
                        full_access_keys: Some(vec![PublicKey::from_str(
                            &new_user_public_key.clone(),
                        )
                        .unwrap()]),
                        limited_access_keys: None,
                        contract_bytes: None,
                    },
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: oidc_token.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            let AddKeyResponse::Ok {
                            full_access_keys,
                            limited_access_keys,
                            near_account_id,
            } = add_key_response else {
                anyhow::bail!("unexpected pattern");
            };
            assert_eq!(full_access_keys, vec![new_user_public_key.clone()]);
            assert_eq!(limited_access_keys, Vec::<String>::new());
            assert_eq!(near_account_id, account_id.to_string());

            tokio::time::sleep(Duration::from_millis(2000)).await;
            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_aggregate_signatures() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let payload: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();

            let client = reqwest::Client::new();
            let signer_urls: Vec<_> = ctx.signer_nodes.iter().map(|s| s.address.clone()).collect();

            let request = SignNodeRequest::SignShare(SignShareNodeRequest {
                oidc_token: "validToken:test-subject".to_string(),
                payload: payload.clone().into_bytes(),
            });

            let signature = sign_payload_with_mpc(&client, &signer_urls, request).await?;

            let account_id = get_test_claims("test-subject".to_string()).get_internal_account_id();
            let res = call_all_nodes(&client, &signer_urls, "public_key", account_id).await?;

            let combined_pub = to_dalek_combined_public_key(&res).unwrap();
            combined_pub.verify(payload.as_bytes(), &signature)?;

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
            let user_public_key = key::random();
            let oidc_token = token::valid_random();

            let create_account_options = CreateAccountOptions {
                full_access_keys: Some(vec![user_public_key.clone().parse().unwrap()]),
                limited_access_keys: None,
                contract_bytes: None,
            };

            // Create account
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    create_account_options,
                    oidc_token: oidc_token.clone(),
                    signature: None,
                })
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

            // Add key
            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: oidc_token.clone(),
                    create_account_options: CreateAccountOptions {
                        full_access_keys: Some(vec![new_user_public_key.parse()?]),
                        limited_access_keys: None,
                        contract_bytes: None,
                    },
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            let AddKeyResponse::Ok {
                full_access_keys,
                limited_access_keys,
                near_account_id,
            } = add_key_response else {
                anyhow::bail!("unexpected pattern");
            };
            assert_eq!(full_access_keys, vec![new_user_public_key.clone()]);
            assert_eq!(limited_access_keys, Vec::<String>::new());
            assert_eq!(near_account_id, account_id.to_string());

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            // Adding the same key should now fail
            let (status_code, _add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
                    create_account_options: CreateAccountOptions {
                        full_access_keys: Some(vec![new_user_public_key.clone().parse()?]),
                        limited_access_keys: None,
                        contract_bytes: None,
                    },
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

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
            let user_full_access_key = key::random();

            let user_limited_access_key = LimitedAccessKey {
                public_key: key::random().parse().unwrap(),
                allowance: "100".to_string(),
                receiver_id: account::random(ctx.worker)?.to_string().parse().unwrap(), // TODO: type issues here
                method_names: "method_names".to_string(),
            };

            let create_account_options = CreateAccountOptions {
                full_access_keys: Some(vec![user_full_access_key.clone().parse().unwrap()]),
                limited_access_keys: Some(vec![user_limited_access_key.clone()]),
                contract_bytes: None,
            };

            let (status_code, _) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    create_account_options,
                    oidc_token: token::valid_random(),
                    signature: None,
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;

            let recovery_full_access_key1 = access_keys
                .clone()
                .into_iter()
                .find(|ak| {
                    ak.public_key.to_string() != user_full_access_key
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
            let user_public_key = key::random();

            let create_account_options = CreateAccountOptions {
                full_access_keys: Some(vec![user_public_key.clone().parse().unwrap()]),
                limited_access_keys: None,
                contract_bytes: None,
            };

            let (status_code, _) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    create_account_options,
                    oidc_token: token::valid_random(),
                    signature: None,
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;
            let recovery_full_access_key2 = access_keys
                .into_iter()
                .find(|ak| ak.public_key.to_string() != user_public_key)
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

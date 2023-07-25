use crate::{
    account, check, key,
    mpc::{add_pk_and_check_validity, fetch_recovery_pk, new_random_account},
    token, with_nodes, MpcCheck,
};

use std::{collections::HashMap, str::FromStr, time::Duration};

use anyhow::anyhow;
use hyper::StatusCode;
use near_crypto::PublicKey;
use workspaces::types::AccessKeyPermission;

use mpc_recovery::{
    gcp::value::{FromValue, IntoValue},
    msg::{NewAccountResponse, UserCredentialsResponse},
    sign_node::user_credentials::EncryptedUserCredentials,
    transaction::LimitedAccessKey,
};

use test_log::test;
#[test(tokio::test)]
async fn test_basic_front_running_protection() -> anyhow::Result<()> {
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
                .claim_oidc_with_helper(
                    oidc_token.clone(),
                    user_public_key.clone(),
                    user_secret_key.clone(),
                )
                .await?;

            // Create account
            let new_acc_response = ctx
                .leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    PublicKey::from_str(&user_public_key.clone().to_string())?,
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
            check::access_key_exists(&ctx, &account_id, &user_public_key.to_string()).await?;

            // Add new FA key with front running protection (negative, wrong signature)
            // TODO: add exaample with front running protection signature (bad one)

            // Add new FA key with front running protection (positive)
            // TODO: add front running protection signature

            // Get recovery PK with proper FRP signature
            let recovery_pk = match ctx
                .leader_node
                .user_credentials_with_helper(
                    oidc_token.clone(),
                    user_secret_key.clone(),
                    user_secret_key.clone().public_key(),
                )
                .await?
                .assert_ok()?
            {
                UserCredentialsResponse::Ok { recovery_pk } => PublicKey::from_str(&recovery_pk)?,
                UserCredentialsResponse::Err { msg } => {
                    return Err(anyhow::anyhow!("error response: {}", msg))
                }
            };

            // Add key with bad FRP signature should fail
            let new_user_public_key = key::random_pk();

            let bad_user_sk = key::random_sk();

            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token.clone(),
                    new_user_public_key.parse()?,
                    recovery_pk.clone(),
                    bad_user_sk.clone(),
                    user_public_key.clone(),
                )
                .await?
                .assert_unauthorized()?;

            // Add key with proper FRP signature should succeed
            ctx.leader_node
                .add_key(
                    account_id.clone(),
                    oidc_token.clone(),
                    new_user_public_key.parse()?,
                    recovery_pk,
                    user_secret_key,
                    user_public_key,
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
            let (account_id, user_secret_key, user_public_key, oidc_token) =
                new_random_account(&ctx).await?;
            tokio::time::sleep(Duration::from_millis(2000)).await;
            check::access_key_exists(&ctx, &account_id, &user_public_key.clone().to_string())
                .await?;

            // Add key
            let recovery_pk = fetch_recovery_pk(&ctx, &user_secret_key, oidc_token.clone()).await?;
            let new_user_public_key = add_pk_and_check_validity(
                &ctx,
                &account_id,
                &user_secret_key,
                &user_public_key,
                oidc_token.clone(),
                &recovery_pk,
                None,
            )
            .await?;

            // Adding the same key should now fail
            add_pk_and_check_validity(
                &ctx,
                &account_id,
                &user_secret_key,
                &user_public_key,
                oidc_token.clone(),
                &recovery_pk,
                Some(new_user_public_key),
            )
            .await?;

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
            let user_full_access_sk = key::random_sk();
            let user_full_access_pk = user_full_access_sk.public_key();
            let oidc_token = token::valid_random();

            ctx.leader_node
                .claim_oidc_with_helper(
                    oidc_token.clone(),
                    user_full_access_pk.clone(),
                    user_full_access_sk.clone(),
                )
                .await?;

            let user_limited_access_key = LimitedAccessKey {
                public_key: key::random_pk().parse().unwrap(),
                allowance: "100".to_string(),
                receiver_id: account::random(ctx.worker)?.to_string().parse().unwrap(), // TODO: type issues here
                method_names: "method_names".to_string(),
            };

            ctx.leader_node
                .new_account_with_helper(
                    account_id.clone().to_string(),
                    user_full_access_pk.clone(),
                    Some(user_limited_access_key.clone()),
                    user_full_access_sk.clone(),
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
                    ak.public_key.to_string() != user_full_access_pk.to_string()
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
                .claim_oidc_with_helper(
                    oidc_token.clone(),
                    user_public_key.clone(),
                    user_secret_key.clone(),
                )
                .await?;

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

#[test(tokio::test)]
async fn test_rotate_node_keys() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let (account_id, user_sk, user_pk, oidc_token) = new_random_account(&ctx).await?;
            tokio::time::sleep(Duration::from_millis(2000)).await;
            check::access_key_exists(&ctx, &account_id, &user_pk.to_string())
                .await?;

            // Add key
            let recovery_pk = fetch_recovery_pk(&ctx, &user_sk, oidc_token.clone()).await?;
            add_pk_and_check_validity(
                &ctx,
                &account_id,
                &user_sk,
                &user_pk,
                oidc_token.clone(),
                &recovery_pk,
                None,
            )
            .await?;

            // Fetch current entities to be compared later.
            let gcp_service = ctx.gcp_service().await?;
            let old_entities = gcp_service
                .fetch_entities::<mpc_recovery::sign_node::user_credentials::EncryptedUserCredentials>()
                .await
                .unwrap()
                .into_iter()
                .map(|entity| {
                    let entity = entity.entity.unwrap();
                    (entity.key.as_ref().unwrap().path.as_ref().unwrap()[0].name.as_ref().unwrap().clone(), entity)
                })
                .collect::<HashMap<_, _>>();

            // Generate a new set of ciphers to rotate out each node:
            let mpc_recovery::GenerateResult { secrets, .. } = mpc_recovery::generate(3);

            let mut ciphers = HashMap::new();
            // Rotate out with new the cipher.
            for ((_sk_share, new_cipher), sign_node) in secrets.iter().zip(ctx.signer_nodes) {
                let cipher_pair = sign_node.run_rotate_node_key(new_cipher).await?;
                ciphers.insert(sign_node.node_id, cipher_pair);
            }

            let mut new_entities = gcp_service
                .fetch_entities::<mpc_recovery::sign_node::user_credentials::EncryptedUserCredentials>()
                .await
                .unwrap()
                .into_iter()
                .map(|entity| {
                    let entity = entity.entity.unwrap();
                    (entity.key.as_ref().unwrap().path.as_ref().unwrap()[0].name.as_ref().unwrap().clone(), entity)
                })
                .collect::<HashMap<_, _>>();

            // Check whether node-key rotation was successful or not
            assert_eq!(old_entities.len(), new_entities.len());
            for (path, old_entity) in old_entities.into_iter() {
                let node_id = path.split('/').next().unwrap().parse::<usize>()?;
                let (old_cipher, new_cipher) = ciphers.get(&node_id).unwrap();

                let old_cred = EncryptedUserCredentials::from_value(old_entity.into_value())?;
                let new_entity = new_entities.remove(&path).unwrap();
                let new_cred = EncryptedUserCredentials::from_value(new_entity.into_value())?;

                // Once rotated, the key pairs should not be equal as they use different cipher keys:
                assert_ne!(old_cred.encrypted_key_pair, new_cred.encrypted_key_pair);

                // Make sure that the actual key pairs are still the same after cipher rotation:
                let old_key_pair = old_cred
                    .decrypt_key_pair(old_cipher)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let new_key_pair = new_cred
                    .decrypt_key_pair(new_cipher)
                    .map_err(|e| anyhow::anyhow!(e))?;
                assert_eq!(old_key_pair.public_key, new_key_pair.public_key);
            }

            Ok(())
        })
    })
    .await
}

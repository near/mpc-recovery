use std::collections::HashMap;

use crate::mpc::{add_pk_and_check_validity, fetch_recovery_pk, new_random_account};
use crate::{account, key, with_nodes, MpcCheck, TestContext};

use futures::stream::FuturesUnordered;
use hyper::StatusCode;
use workspaces::types::AccessKeyPermission;

use mpc_recovery::{
    gcp::value::{FromValue, IntoValue},
    sign_node::user_credentials::EncryptedUserCredentials,
    transaction::LimitedAccessKey,
};

use test_log::test;
#[test(tokio::test)]
async fn test_basic_front_running_protection() -> anyhow::Result<()> {
    with_nodes(3, |ctx| async move {
        let (account_id, user_secret_key, oidc_token) = new_random_account(&ctx, None).await?;

        // Get recovery PK with proper FRP signature
        let recovery_pk = fetch_recovery_pk(&ctx, &user_secret_key, &oidc_token).await?;

        // Add key with bad FRP signature should fail
        let new_user_public_key = key::random_pk();
        let bad_user_sk = key::random_sk();
        ctx.leader_node
            .add_key_with_helper(
                &account_id,
                &oidc_token,
                &new_user_public_key,
                &recovery_pk,
                &bad_user_sk,
                &user_secret_key.public_key(),
            )
            .await?
            .assert_unauthorized()?;

        // Add key with proper FRP signature should succeed
        add_pk_and_check_validity(
            &ctx,
            &account_id,
            &user_secret_key,
            &oidc_token,
            &recovery_pk,
            Some(new_user_public_key),
        )
        .await?;

        Ok(())
    })
    .await
}

#[test(tokio::test)]
async fn test_basic_action() -> anyhow::Result<()> {
    with_nodes(3, |ctx| async move { basic_action(&ctx).await }).await
}

#[test(tokio::test)]
async fn test_random_recovery_keys() -> anyhow::Result<()> {
    with_nodes(3, |ctx| async move {
        let user_limited_access_key = LimitedAccessKey {
            public_key: key::random_pk(),
            allowance: "100".to_string(),
            receiver_id: account::random(&ctx.worker)?,
            method_names: "method_names".to_string(),
        };

        let (account_id, user_full_access_sk, _) =
            new_random_account(&ctx, Some(user_limited_access_key.clone())).await?;
        let user_full_access_pk = user_full_access_sk.public_key();
        let access_keys = ctx.worker.view_access_keys(&account_id).await?;

        let recovery_full_access_key1 = access_keys
            .clone()
            .into_iter()
            .find(|ak| {
                ak.public_key.key_data() != user_full_access_pk.key_data()
                    && ak.public_key.key_data() != user_limited_access_key.public_key.key_data()
            })
            .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

        match recovery_full_access_key1.access_key.permission {
            AccessKeyPermission::FullAccess => (),
            AccessKeyPermission::FunctionCall(_) => {
                anyhow::bail!("Got a limited access key when we expected a full access key")
            }
        };

        let la_key = access_keys
            .into_iter()
            .find(|ak| ak.public_key.key_data() == user_limited_access_key.public_key.key_data())
            .ok_or_else(|| anyhow::anyhow!("missing limited access key"))?;

        match la_key.access_key.permission {
            AccessKeyPermission::FullAccess => {
                anyhow::bail!("Got a full access key when we expected a limited access key")
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
        let (account_id, user_secret_key, _) =
            new_random_account(&ctx, Some(user_limited_access_key.clone())).await?;
        let user_public_key = user_secret_key.public_key();

        let access_keys = ctx.worker.view_access_keys(&account_id).await?;
        let recovery_full_access_key2 = access_keys
            .into_iter()
            .find(|ak| ak.public_key.key_data() != user_public_key.key_data())
            .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

        assert_ne!(
            recovery_full_access_key1.public_key, recovery_full_access_key2.public_key,
            "MPC recovery should generate random recovery keys for each user"
        );

        Ok(())
    })
    .await
}

#[test(tokio::test)]
async fn test_accept_existing_pk_set() -> anyhow::Result<()> {
    with_nodes(1, |ctx| async move {
        // Signer node is already initialized with the pk set, but we should be able to get a
        // positive response by providing the same pk set as it already has.
        let (status_code, result) = ctx.signer_nodes[0]
            .accept_pk_set(mpc_recovery::msg::AcceptNodePublicKeysRequest {
                public_keys: ctx.pk_set.clone(),
            })
            .await?;
        assert_eq!(status_code, StatusCode::OK);
        assert!(result.is_ok());

        Ok(())
    })
    .await
}

#[test(tokio::test)]
async fn test_rotate_node_keys() -> anyhow::Result<()> {
    with_nodes(3, |ctx| async move {
        let (account_id, user_sk, oidc_token) = new_random_account(&ctx, None).await?;

        // Add key
        let recovery_pk = fetch_recovery_pk(&ctx, &user_sk, &oidc_token).await?;
        add_pk_and_check_validity(&ctx, &account_id, &user_sk, &oidc_token, &recovery_pk, None)
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
                (
                    entity.key.as_ref().unwrap().path.as_ref().unwrap()[0]
                        .name
                        .as_ref()
                        .unwrap()
                        .clone(),
                    entity,
                )
            })
            .collect::<HashMap<_, _>>();

        // Generate a new set of ciphers to rotate out each node:
        let mut counter = 0;
        let mpc_recovery::GenerateResult { secrets, .. } = loop {
            let result = mpc_recovery::generate(3);
            let all_diff = result
                .secrets
                .iter()
                .zip(ctx.signer_nodes.iter())
                .all(|((_, new_cipher), signer_node)| signer_node.cipher_key != *new_cipher);

            if all_diff {
                break result;
            }

            counter += 1;
            if counter == 5 {
                panic!("Failed to generate a new set of ciphers after 5 tries");
            }
        };

        let mut ciphers = HashMap::new();
        // Rotate out with new the cipher.
        for ((_sk_share, new_cipher), sign_node) in secrets.iter().zip(ctx.signer_nodes) {
            let cipher_pair = sign_node.run_rotate_node_key(new_cipher).await?;
            ciphers.insert(sign_node.node_id, cipher_pair);
        }

        // Sleep a little so that the entities are updated in the datastore.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let mut new_entities = gcp_service
            .fetch_entities::<mpc_recovery::sign_node::user_credentials::EncryptedUserCredentials>()
            .await
            .unwrap()
            .into_iter()
            .map(|entity| {
                let entity = entity.entity.unwrap();
                (
                    entity.key.as_ref().unwrap().path.as_ref().unwrap()[0]
                        .name
                        .as_ref()
                        .unwrap()
                        .clone(),
                    entity,
                )
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
    .await
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 8))]
async fn test_stress_network() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let ctx = std::sync::Arc::new(ctx);
            let tasks = (0..30)
                .map(|_| {
                    let ctx = ctx.clone();
                    tokio::spawn(async move { basic_action(&ctx).await })
                })
                .collect::<FuturesUnordered<_>>();

            let result = futures::future::join_all(tasks)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;
            tracing::debug!("{:#?}", result);
            Ok(())
        })
    })
    .await
}

async fn basic_action(ctx: &TestContext) -> anyhow::Result<()> {
    let (account_id, user_secret_key, oidc_token) = new_random_account(ctx, None).await?;

    // Add key
    let recovery_pk = fetch_recovery_pk(ctx, &user_secret_key, &oidc_token).await?;
    let new_user_public_key = add_pk_and_check_validity(
        ctx,
        &account_id,
        &user_secret_key,
        &oidc_token,
        &recovery_pk,
        None,
    )
    .await?;

    // Adding the same key should now fail
    add_pk_and_check_validity(
        ctx,
        &account_id,
        &user_secret_key,
        &oidc_token,
        &recovery_pk,
        Some(new_user_public_key),
    )
    .await?;

    Ok(())
}

use crate::{account, check, key, token, with_nodes};
use ed25519_dalek::Verifier;
use hyper::StatusCode;
use mpc_recovery::{
    msg::{AddKeyRequest, AddKeyResponse, NewAccountRequest, NewAccountResponse},
    oauth::get_test_claims,
    transaction::{call, sign, to_dalek_combined_public_key},
};
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;

#[tokio::test]
async fn test_trio() -> anyhow::Result<()> {
    with_nodes(4, |ctx| {
        Box::pin(async move {
            let payload: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();

            // TODO integrate this better with testing
            let client = reqwest::Client::new();
            let signer_urls: Vec<_> = ctx
                .signer_nodes
                .iter()
                .map(|s| s.local_address.clone())
                .collect();

            let signature = sign(
                &client,
                &signer_urls,
                "validToken:test-subject".to_string(),
                payload.clone().into(),
            )
            .await?;

            let account_id = get_test_claims("test-subject".to_string()).get_internal_account_id();
            let res = call(&client, &signer_urls, "public_key", account_id).await?;

            let combined_pub = to_dalek_combined_public_key(&res).unwrap();
            combined_pub.verify(payload.as_bytes(), &signature)?;

            Ok(())
        })
    })
    .await
}

// TODO: write a test with real token
#[tokio::test]
async fn test_basic_action() -> anyhow::Result<()> {
    with_nodes(4, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();
            let oidc_token = token::valid_random();

            // Create account
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    oidc_token: oidc_token.clone(),
                    public_key: user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    user_public_key: user_pk,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if user_pk == user_public_key && acc_id == account_id.to_string()
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
                    public_key: new_user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(
                add_key_response,
                AddKeyResponse::Ok {
                    user_public_key: new_pk,
                    near_account_id: acc_id,
                } if new_pk == new_user_public_key && acc_id == account_id.to_string()
            ));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            // Adding the same key should now fail
            let (status_code, _add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
                    public_key: new_user_public_key.clone(),
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

#[tokio::test]
async fn test_random_recovery_keys() -> anyhow::Result<()> {
    with_nodes(4, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();

            let (status_code, _) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    oidc_token: token::valid_random(),
                    public_key: user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;
            let recovery_access_key1 = access_keys
                .into_iter()
                .find(|ak| ak.public_key.to_string() != user_public_key)
                .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

            // Generate another user
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();

            let (status_code, _) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    oidc_token: token::valid_random(),
                    public_key: user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;
            let recovery_access_key2 = access_keys
                .into_iter()
                .find(|ak| ak.public_key.to_string() != user_public_key)
                .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

            assert_ne!(
                recovery_access_key1.public_key, recovery_access_key2.public_key,
                "MPC recovery should generate random recovery keys for each user"
            );

            Ok(())
        })
    })
    .await
}

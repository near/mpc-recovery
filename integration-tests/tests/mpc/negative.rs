use crate::{account, check, key, token, with_nodes};
use hyper::StatusCode;
use mpc_recovery::msg::{AddKeyRequest, AddKeyResponse, NewAccountRequest, NewAccountResponse};
use std::time::Duration;

#[tokio::test]
async fn test_invalid_token() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();
            let oidc_token = token::valid_random();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    limited_public_key: None,
                    oidc_token: token::invalid(),
                    public_key: user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::UNAUTHORIZED);
            assert!(matches!(new_acc_response, NewAccountResponse::Err { .. }));

            // Check that the service is still available
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    limited_public_key: None,
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

            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: token::invalid(),
                    public_key: new_user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::UNAUTHORIZED);
            assert!(matches!(add_key_response, AddKeyResponse::Err { .. }));

            // Check that the service is still available
            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
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

            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn test_malformed_account_id() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let malformed_account_id = account::malformed();
            let user_public_key = key::random();
            let oidc_token = token::valid_random();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: malformed_account_id.to_string(),
                    limited_public_key: None,
                    oidc_token: oidc_token.clone(),
                    public_key: user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::BAD_REQUEST);
            assert!(matches!(new_acc_response, NewAccountResponse::Err { .. }));

            let account_id = account::random(ctx.worker)?;

            // Check that the service is still available
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    limited_public_key: None,
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

            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(malformed_account_id.to_string()),
                    oidc_token: oidc_token.clone(),
                    public_key: new_user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::BAD_REQUEST);
            assert!(matches!(add_key_response, AddKeyResponse::Err { .. }));

            // Check that the service is still available
            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
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

            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn test_malformed_public_key() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let malformed_public_key = key::malformed();
            let oidc_token = token::valid_random();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    limited_public_key: None,
                    oidc_token: oidc_token.clone(),
                    public_key: malformed_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::BAD_REQUEST);
            assert!(matches!(new_acc_response, NewAccountResponse::Err { .. }));

            let user_public_key = key::random();

            // Check that the service is still available
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    limited_public_key: None,
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

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: oidc_token.clone(),
                    public_key: malformed_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::BAD_REQUEST);
            assert!(matches!(add_key_response, AddKeyResponse::Err { .. }));

            // Check that the service is still available
            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
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

            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn test_add_key_to_non_existing_account() -> anyhow::Result<()> {
    with_nodes(1, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: token::valid_random(),
                    public_key: user_public_key.clone(),
                })
                .await?;

            assert_eq!(status_code, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(matches!(add_key_response, AddKeyResponse::Err { .. }));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::no_account(&ctx, &account_id).await?;

            Ok(())
        })
    })
    .await
}

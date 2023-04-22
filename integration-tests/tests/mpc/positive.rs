use crate::{account, check, key, token, with_nodes};
use hyper::StatusCode;
use mpc_recovery::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse,
};
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;

#[tokio::test]
async fn test_trio() -> anyhow::Result<()> {
    with_nodes(4, 3, 3, |ctx| {
        Box::pin(async move {
            let payload: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            let (status_code, response) = ctx
                .leader_node
                .submit(LeaderRequest {
                    payload: payload.clone(),
                })
                .await?;

            assert_eq!(status_code, StatusCode::OK);
            if let LeaderResponse::Ok { signature } = response {
                assert!(ctx.pk_set.public_key().verify(&signature, payload));
            } else {
                panic!("response was not successful");
            }

            Ok(())
        })
    })
    .await
}

// TODO: write a test with real token
#[tokio::test]
async fn test_basic_action() -> anyhow::Result<()> {
    with_nodes(4, 3, 3, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    oidc_token: token::valid(),
                    public_key: user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: account_id.to_string(),
                    oidc_token: token::valid(),
                    public_key: new_user_public_key.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(add_key_response, AddKeyResponse::Ok));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            Ok(())
        })
    })
    .await
}

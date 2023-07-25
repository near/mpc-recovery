use std::str::FromStr;
use std::time::Duration;

use mpc_recovery::msg::{NewAccountResponse, UserCredentialsResponse};
use near_crypto::{PublicKey, SecretKey};
use workspaces::AccountId;

use crate::{account, check, key, token, MpcCheck, TestContext};

mod negative;
mod positive;

pub async fn new_random_account(
    ctx: &TestContext<'_>,
) -> anyhow::Result<(AccountId, SecretKey, String)> {
    let account_id = account::random(ctx.worker)?;
    let user_secret_key = key::random_sk();
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
            account_id.to_string(),
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
    check::access_key_exists(ctx, &account_id, &user_public_key).await?;

    Ok((account_id, user_secret_key, oidc_token))
}

pub async fn fetch_recovery_pk(
    ctx: &TestContext<'_>,
    user_sk: &SecretKey,
    user_oidc: String,
) -> anyhow::Result<PublicKey> {
    let recovery_pk = match ctx
        .leader_node
        .user_credentials_with_helper(user_oidc.clone(), user_sk.clone(), user_sk.public_key())
        .await?
        .assert_ok()?
    {
        UserCredentialsResponse::Ok { recovery_pk } => PublicKey::from_str(&recovery_pk)?,
        UserCredentialsResponse::Err { msg } => anyhow::bail!("error response: {}", msg),
    };
    Ok(recovery_pk)
}

/// Add a new random public key or a supplied public key.
pub async fn add_pk_and_check_validity(
    ctx: &TestContext<'_>,
    user_id: &AccountId,
    user_sk: &SecretKey,
    user_oidc: String,
    user_recovery_pk: &PublicKey,
    pk_to_add: Option<PublicKey>,
) -> anyhow::Result<PublicKey> {
    let new_user_pk = pk_to_add.unwrap_or_else(key::random_pk);
    ctx.leader_node
        .add_key(
            user_id.clone(),
            user_oidc,
            new_user_pk.clone(),
            user_recovery_pk.clone(),
            user_sk.clone(),
            user_sk.public_key(),
        )
        .await?
        .assert_ok()?;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    check::access_key_exists(ctx, user_id, &new_user_pk).await?;
    Ok(new_user_pk)
}

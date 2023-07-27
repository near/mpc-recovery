use std::str::FromStr;
use std::time::Duration;

use mpc_recovery::msg::{NewAccountResponse, UserCredentialsResponse};
use mpc_recovery::transaction::LimitedAccessKey;
use near_crypto::{PublicKey, SecretKey};
use workspaces::AccountId;

use crate::{account, check, key, token, MpcCheck, TestContext};

mod negative;
mod positive;

pub async fn register_account(
    ctx: &TestContext<'_>,
    user_id: &AccountId,
    user_sk: &SecretKey,
    user_pk: &PublicKey,
    user_oidc: &str,
    user_lak: Option<LimitedAccessKey>,
) -> anyhow::Result<()> {
    // Claim OIDC token
    ctx.leader_node
        .claim_oidc_with_helper(user_oidc, user_pk, user_sk)
        .await?;

    // Create account
    let new_acc_response = ctx
        .leader_node
        .new_account_with_helper(user_id, user_pk, user_lak, user_sk, user_oidc)
        .await?
        .assert_ok()?;

    assert!(matches!(new_acc_response, NewAccountResponse::Ok {
            create_account_options: _,
            user_recovery_public_key: _,
            near_account_id: acc_id,
        } if acc_id == user_id.to_string()
    ));

    tokio::time::sleep(Duration::from_millis(2000)).await;
    check::access_key_exists(ctx, user_id, user_pk).await?;

    Ok(())
}

pub async fn new_random_account(
    ctx: &TestContext<'_>,
    user_lak: Option<LimitedAccessKey>,
) -> anyhow::Result<(AccountId, SecretKey, String)> {
    let account_id = account::random(ctx.worker)?;
    let user_secret_key = key::random_sk();
    let user_public_key = user_secret_key.public_key();
    let oidc_token = token::valid_random();

    register_account(
        ctx,
        &account_id,
        &user_secret_key,
        &user_public_key,
        &oidc_token,
        user_lak,
    )
    .await?;
    Ok((account_id, user_secret_key, oidc_token))
}

pub async fn fetch_recovery_pk(
    ctx: &TestContext<'_>,
    user_sk: &SecretKey,
    user_oidc: &str,
) -> anyhow::Result<PublicKey> {
    let recovery_pk = match ctx
        .leader_node
        .user_credentials_with_helper(user_oidc, user_sk, &user_sk.public_key())
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
    user_oidc: &str,
    user_recovery_pk: &PublicKey,
    pk_to_add: Option<PublicKey>,
) -> anyhow::Result<PublicKey> {
    let new_user_pk = pk_to_add.unwrap_or_else(key::random_pk);
    ctx.leader_node
        .add_key_with_helper(
            user_id,
            user_oidc,
            &new_user_pk,
            user_recovery_pk,
            user_sk,
            &user_sk.public_key(),
        )
        .await?
        .assert_ok()?;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    check::access_key_exists(ctx, user_id, &new_user_pk).await?;
    Ok(new_user_pk)
}

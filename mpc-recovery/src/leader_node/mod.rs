use crate::key_recovery::get_user_recovery_pk;
use crate::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse, SigShareRequest,
};
use crate::oauth::{IdTokenClaims, OAuthTokenVerifier, UniversalTokenVerifier};
use crate::primitives::InternalAccountId;
use crate::relayer::error::RelayerError;
use crate::relayer::msg::RegisterAccountRequest;
use crate::relayer::NearRpcAndRelayerClient;
use crate::sign_node::aggregate_signer::{Reveal, SignedCommitment};
use crate::transaction::{
    self, get_add_key_delegate_action, get_create_account_delegate_action,
    get_signed_delegated_action,
};
use crate::{nar, NodeId};
use anyhow::{anyhow, Context};
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use ed25519_dalek::Signature;
use futures::future;
use futures::future::FutureExt;
use futures::stream::FuturesUnordered;
use hyper::client::ResponseFuture;
use hyper::{Body, Client, Method, Request};
use multi_party_eddsa::protocols::{self, aggsig, Signature};
use near_crypto::{ParseKeyError, PublicKey, SecretKey};
use near_primitives::account::id::ParseAccountError;
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionStatus;
use rand::{distributions::Alphanumeric, Rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

pub struct Config {
    pub id: NodeId,
    pub port: u16,
    pub sign_nodes: Vec<String>,
    pub near_rpc: String,
    pub relayer_url: String,
    pub near_root_account: String,
    pub account_creator_id: AccountId,
    // TODO: temporary solution
    pub account_creator_sk: SecretKey,
    pub account_lookup_url: String,
    pub pagoda_firebase_audience_id: String,
}

pub async fn run(config: Config) {
    let Config {
        id,
        port,
        sign_nodes,
        near_rpc,
        relayer_url,
        near_root_account,
        account_creator_id,
        account_creator_sk,
        account_lookup_url,
        pagoda_firebase_audience_id,
    } = config;
    let _span = tracing::debug_span!("run", id, port);
    tracing::debug!(?sign_nodes, "running a leader node");

    let client = NearRpcAndRelayerClient::connect(&near_rpc, relayer_url);
    // FIXME: We don't have a token for ourselves, but are still forced to allocate allowance.
    // Using randomly generated tokens ensures the uniqueness of tokens on the relayer side.
    let fake_oauth_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    client
        .register_account(RegisterAccountRequest {
            account_id: account_creator_id.clone(),
            allowance: 300_000_000_000_000,
            oauth_token: fake_oauth_token,
        })
        .await
        .unwrap();

    let state = LeaderState {
        id,
        sign_nodes,
        client,
        reqwest_client: reqwest::Client::new(),
        near_root_account: near_root_account.parse().unwrap(),
        account_creator_id,
        account_creator_sk,
        account_lookup_url,
        pagoda_firebase_audience_id,
    };

    //TODO: not secure, allow only for testnet, whitelist endpoint etc. for mainnet
    let cors_layer = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        .route("/submit", post(submit::<UniversalTokenVerifier>))
        .route("/new_account", post(new_account::<UniversalTokenVerifier>))
        .route("/add_key", post(add_key::<UniversalTokenVerifier>))
        .layer(Extension(state))
        .layer(cors_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Clone)]
struct LeaderState {
    id: NodeId,
    sign_nodes: Vec<String>,
    client: NearRpcAndRelayerClient,
    reqwest_client: reqwest::Client,
    near_root_account: AccountId,
    account_creator_id: AccountId,
    // TODO: temporary solution
    account_creator_sk: SecretKey,
    account_lookup_url: String,
    pagoda_firebase_audience_id: String,
}

#[derive(thiserror::Error, Debug)]
enum NewAccountError {
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(String, ParseKeyError),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("relayer error: {0}")]
    RelayerError(#[from] RelayerError),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
async fn process_new_account<T: OAuthTokenVerifier>(
    state: LeaderState,
    request: NewAccountRequest,
) -> Result<NewAccountResponse, NewAccountError> {
    // Create a transaction to create new NEAR account
    let new_user_account_pk: PublicKey = request
        .public_key
        .parse()
        .map_err(|e| NewAccountError::MalformedPublicKey(request.public_key, e))?;
    let new_user_account_id: AccountId = request
        .near_account_id
        .parse()
        .map_err(|e| NewAccountError::MalformedAccountId(request.near_account_id, e))?;
    let oidc_token_claims =
        T::verify_token(&request.oidc_token, &state.pagoda_firebase_audience_id)
            .await
            .map_err(NewAccountError::OidcVerificationFailed)?;
    let internal_acc_id = get_internal_account_id(oidc_token_claims);

    state
        .client
        .register_account(RegisterAccountRequest {
            account_id: new_user_account_id.clone(),
            allowance: 300_000_000_000_000,
            oauth_token: request.oidc_token,
        })
        .await?;

    nar::retry(|| async {
        // Get nonce and recent block hash
        let (_hash, block_height, nonce) = state
            .client
            .access_key(
                state.account_creator_id.clone(),
                state.account_creator_sk.public_key(),
            )
            .await?;

        let delegate_action = get_create_account_delegate_action(
            state.account_creator_id.clone(),
            state.account_creator_sk.public_key(),
            new_user_account_id.clone(),
            get_user_recovery_pk(internal_acc_id.clone()),
            new_user_account_pk.clone(),
            state.near_root_account.clone(),
            nonce,
            block_height + 100,
        )?;
        let signed_delegate_action = get_signed_delegated_action(
            &state.reqwest_client,
            &state.sign_nodes,
            delegate_action,
            state.account_creator_id.clone(),
        )
        .await?;

        // Send delegate action to relayer
        let result = state.client.send_meta_tx(signed_delegate_action).await;
        if let Err(err) = &result {
            let err_str = format!("{:?}", err);
            state
                .client
                .invalidate_cache_if_tx_failed(
                    &(
                        state.account_creator_id.clone(),
                        state.account_creator_sk.public_key(),
                    ),
                    &err_str,
                )
                .await;
        }
        let response = result?;

        // TODO: Probably need to check more fields
        if matches!(response.status, FinalExecutionStatus::SuccessValue(_)) {
            Ok(NewAccountResponse::Ok)
        } else {
            Err(anyhow::anyhow!("transaction failed with {:?}", response.status).into())
        }
    })
    .await
}

fn get_internal_account_id(claims: IdTokenClaims) -> InternalAccountId {
    format!("{}:{}", claims.iss, claims.sub)
}

mod response {
    use crate::msg::AddKeyResponse;
    use crate::msg::NewAccountResponse;
    use axum::Json;
    use hyper::StatusCode;

    pub fn new_acc_bad_request(msg: String) -> (StatusCode, Json<NewAccountResponse>) {
        (StatusCode::BAD_REQUEST, Json(NewAccountResponse::err(msg)))
    }

    pub fn new_acc_unauthorized(msg: String) -> (StatusCode, Json<NewAccountResponse>) {
        (StatusCode::UNAUTHORIZED, Json(NewAccountResponse::err(msg)))
    }

    pub fn new_acc_internal_error(msg: String) -> (StatusCode, Json<NewAccountResponse>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(NewAccountResponse::err(msg)),
        )
    }

    pub fn add_key_bad_request(msg: String) -> (StatusCode, Json<AddKeyResponse>) {
        (StatusCode::BAD_REQUEST, Json(AddKeyResponse::err(msg)))
    }

    pub fn add_key_unauthorized(msg: String) -> (StatusCode, Json<AddKeyResponse>) {
        (StatusCode::UNAUTHORIZED, Json(AddKeyResponse::err(msg)))
    }

    pub fn add_key_internal_error(msg: String) -> (StatusCode, Json<AddKeyResponse>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AddKeyResponse::err(msg)),
        )
    }
}

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn new_account<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<NewAccountRequest>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        near_account_id = hex::encode(request.near_account_id.clone()),
        public_key = hex::encode(request.public_key.clone()),
        iodc_token = format!("{:.5}...", request.oidc_token),
        "new_account request"
    );

    match process_new_account::<T>(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(ref e @ NewAccountError::MalformedPublicKey(ref pk, _)) => {
            tracing::error!(err = ?e);
            response::new_acc_bad_request(format!("bad public_key: {}", pk))
        }
        Err(ref e @ NewAccountError::MalformedAccountId(ref account_id, _)) => {
            tracing::error!(err = ?e);
            response::new_acc_bad_request(format!("bad near_account_id: {}", account_id))
        }
        Err(ref e @ NewAccountError::OidcVerificationFailed(ref err_msg)) => {
            tracing::error!(err = ?e);
            response::new_acc_unauthorized(format!("failed to verify oidc token: {}", err_msg))
        }
        Err(e) => {
            tracing::error!(err = ?e);
            response::new_acc_internal_error(format!("failed to process new account: {}", e))
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum AddKeyError {
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(String, ParseKeyError),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("relayer error: {0}")]
    RelayerError(#[from] RelayerError),
    #[error("failed to find associated account id for pk: {0}")]
    AccountNotFound(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

fn get_acc_id_from_pk(
    public_key: PublicKey,
    account_lookup_url: String,
) -> Result<AccountId, anyhow::Error> {
    let url = format!("{}/publicKey/{}/accounts", account_lookup_url, public_key);
    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send()?.text()?;
    let accounts: Vec<String> = serde_json::from_str(&response)?;
    Ok(accounts
        .first()
        .cloned()
        .unwrap_or_default()
        .parse()
        .unwrap())
}

async fn process_add_key<T: OAuthTokenVerifier>(
    state: LeaderState,
    request: AddKeyRequest,
) -> Result<AddKeyResponse, AddKeyError> {
    let oidc_token_claims =
        T::verify_token(&request.oidc_token, &state.pagoda_firebase_audience_id)
            .await
            .map_err(AddKeyError::OidcVerificationFailed)?;
    let internal_acc_id = get_internal_account_id(oidc_token_claims);
    let user_recovery_pk = get_user_recovery_pk(internal_acc_id.clone());
    let new_public_key: PublicKey = request
        .public_key
        .parse()
        .map_err(|e| AddKeyError::MalformedPublicKey(request.public_key, e))?;

    let user_account_id: AccountId = match &request.near_account_id {
        Some(near_account_id) => near_account_id
            .parse()
            .map_err(|e| AddKeyError::MalformedAccountId(request.near_account_id.unwrap(), e))?,
        None => match get_acc_id_from_pk(user_recovery_pk.clone(), state.account_lookup_url) {
            Ok(near_account_id) => near_account_id,
            Err(e) => {
                tracing::error!(err = ?e);
                return Err(AddKeyError::AccountNotFound(e.to_string()));
            }
        },
    };

    nar::retry(|| async {
        // Get nonce and recent block hash
        let (_hash, block_height, nonce) = state
            .client
            .access_key(user_account_id.clone(), user_recovery_pk.clone())
            .await?;

        // Create a transaction to create a new account
        let max_block_height: u64 = block_height + 100;
        let delegate_action = get_add_key_delegate_action(
            user_account_id.clone(),
            user_recovery_pk.clone(),
            new_public_key.clone(),
            nonce,
            max_block_height,
        )?;
        let signed_delegate_action = get_signed_delegated_action(
            &state.reqwest_client,
            &state.sign_nodes,
            delegate_action,
            user_account_id.clone(),
        )
        .await?;

        let resp = state.client.send_meta_tx(signed_delegate_action).await;
        if let Err(err) = resp {
            let err_str = format!("{:?}", err);
            state
                .client
                .invalidate_cache_if_tx_failed(
                    &(
                        state.account_creator_id.clone(),
                        state.account_creator_sk.public_key(),
                    ),
                    &err_str,
                )
                .await;
            return Err(err.into());
        }
        let resp = resp?;

        // TODO: Probably need to check more fields
        if matches!(resp.status, FinalExecutionStatus::SuccessValue(_)) {
            Ok(AddKeyResponse::Ok)
        } else {
            Err(anyhow::anyhow!("transaction failed with {:?}", resp.status).into())
        }
    })
    .await
}

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn add_key<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<AddKeyRequest>,
) -> (StatusCode, Json<AddKeyResponse>) {
    tracing::info!(
        near_account_id = hex::encode(match &request.near_account_id {
            Some(ref near_account_id) => near_account_id,
            None => "not specified",
        }),
        public_key = hex::encode(&request.public_key),
        iodc_token = format!("{:.5}...", request.oidc_token),
        "add_key request"
    );

    match process_add_key::<T>(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(ref e @ AddKeyError::MalformedPublicKey(ref pk, _)) => {
            tracing::error!(err = ?e);
            response::add_key_bad_request(format!("bad public_key: {}", pk))
        }
        Err(ref e @ AddKeyError::MalformedAccountId(ref account_id, _)) => {
            tracing::error!(err = ?e);
            response::add_key_bad_request(format!("bad near_account_id: {}", account_id))
        }
        Err(ref e @ AddKeyError::OidcVerificationFailed(ref err_msg)) => {
            tracing::error!(err = ?e);
            response::add_key_unauthorized(format!("failed to verify oidc token: {}", err_msg))
        }
        Err(e) => {
            tracing::error!(err = ?e);
            response::add_key_internal_error(format!("failed to process new account: {}", e))
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn submit<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<LeaderRequest>,
) -> (StatusCode, Json<LeaderResponse>) {
    tracing::info!(payload = request.payload, "submit request");

    // TODO: extract access token from payload
    let access_token = "validToken";
    match T::verify_token(access_token, &state.pagoda_firebase_audience_id).await {
        Ok(_) => {
            tracing::info!("access token is valid");
            // continue execution
        }
        Err(_) => {
            tracing::error!("access token verification failed");
            return (StatusCode::UNAUTHORIZED, Json(LeaderResponse::Err));
        }
    }

    match transaction::sign(
        &state.reqwest_client,
        &state.sign_nodes,
        request.payload.clone().into(),
    )
    .await
    {
        Ok(signature) => {
            tracing::debug!(?signature, "replying with full signature");
            (StatusCode::OK, Json(LeaderResponse::Ok { signature }))
        }
        Err(e) => {
            tracing::error!("{}", e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(LeaderResponse::Err))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_acc_id_from_pk_mainnet() {
        let url = "https://api.kitwallet.app".to_string();
        let public_key: PublicKey = "ed25519:2uF6ZUghFFUg3Kta9rW47iiJ3crNzRdaPD2rBPQWEwyc"
            .parse()
            .unwrap();
        let first_account = get_acc_id_from_pk(public_key, url).unwrap();
        assert_eq!(first_account.to_string(), "serhii.near".to_string());
    }

    #[test]
    fn test_get_acc_id_from_pk_testnet() {
        let url = "https://testnet-api.kitwallet.app".to_string();
        let public_key: PublicKey = "ed25519:7WYR7ifUbdVo2soQCvzAHnfdGfDhUhF8Und5CKZYK9b8"
            .parse()
            .unwrap();
        let first_account = get_acc_id_from_pk(public_key, url).unwrap();
        assert_eq!(first_account.to_string(), "serhii.testnet".to_string());
    }
}
pub async fn sign(
    client: &reqwest::Client,
    sign_nodes: &Vec<String>,
    payload: Vec<u8>,
) -> Result<Signature, String> {
    let commit_request = SigShareRequest { payload };

    let commitments: Vec<SignedCommitment> =
        call(client, sign_nodes, "commit", commit_request).await?;

    let reveals: Vec<Reveal> = call(client, sign_nodes, "reveal", commitments).await?;

    let signature_shares: Vec<protocols::Signature> =
        call(client, sign_nodes, "signature_share", reveals).await?;

    Ok(aggsig::add_signature_parts(&signature_shares))
}

/// Call every node with an identical payload and send the response
pub async fn call<Req: Serialize, Res: DeserializeOwned>(
    client: &reqwest::Client,
    sign_nodes: &Vec<String>,
    path: &str,
    request: Req,
) -> Result<Vec<Res>, String> {
    let responses = sign_nodes.iter().map(|sign_node| {
        client
            .post(format!("{}/{}", sign_node, path))
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .then(|r| async move {
                match r {
                    // Flatten all errors to strings
                    Ok(ok) => match ok.json::<Result<Res, String>>().await {
                        Ok(ok) => ok,
                        Err(e) => Err(e.to_string()),
                    },
                    Err(e) => Err(e.to_string()),
                }
            })
    });

    future::join_all(responses).await.into_iter().collect()
}

use crate::gcp::GcpService;
use crate::key_recovery::UserCredentials;
use crate::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse, SigShareRequest, SigShareResponse,
};
use crate::oauth::{IdTokenClaims, OAuthTokenVerifier, UniversalTokenVerifier};
use crate::primitives::InternalAccountId;
use crate::relayer::error::RelayerError;
use crate::relayer::msg::RegisterAccountRequest;
use crate::relayer::NearRpcAndRelayerClient;
use crate::transaction::{
    get_add_key_delegate_action, get_create_account_delegate_action, get_signed_delegated_action,
};
use crate::{nar, NodeId};
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use futures::stream::FuturesUnordered;
use hyper::client::ResponseFuture;
use hyper::{Body, Client, Method, Request};
use near_crypto::{ParseKeyError, PublicKey, SecretKey};
use near_primitives::account::id::ParseAccountError;
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionStatus;
use rand::{distributions::Alphanumeric, Rng};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

pub struct Config {
    pub gcp_service: GcpService,
    pub id: NodeId,
    pub pk_set: PublicKeySet,
    pub sk_share: SecretKeyShare,
    pub port: u16,
    pub sign_nodes: Vec<String>,
    pub near_rpc: String,
    pub relayer_url: String,
    pub near_root_account: String,
    pub account_creator_id: AccountId,
    // TODO: temporary solution
    pub account_creator_sk: SecretKey,
    pub account_lookup_url: String,
}

pub async fn run(config: Config) {
    let Config {
        gcp_service,
        id,
        pk_set,
        sk_share,
        port,
        sign_nodes,
        near_rpc,
        relayer_url,
        near_root_account,
        account_creator_id,
        account_creator_sk,
        account_lookup_url,
    } = config;
    let _span = tracing::debug_span!("run", id, port);
    tracing::debug!(?sign_nodes, "running a leader node");

    if pk_set.public_key_share(id) != sk_share.public_key_share() {
        tracing::error!("provided secret share does not match the node id");
        return;
    }

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
        pk_set,
        sk_share,
        sign_nodes,
        client,
        gcp_service,
        near_root_account: near_root_account.parse().unwrap(),
        account_creator_id,
        account_creator_sk,
        account_lookup_url,
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
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    sign_nodes: Vec<String>,
    client: NearRpcAndRelayerClient,
    gcp_service: GcpService,
    near_root_account: AccountId,
    account_creator_id: AccountId,
    // TODO: temporary solution
    account_creator_sk: SecretKey,
    account_lookup_url: String,
}

async fn parse(response_future: ResponseFuture) -> anyhow::Result<SigShareResponse> {
    let response = response_future.await?;
    let response_body = hyper::body::to_bytes(response.into_body()).await?;
    Ok(serde_json::from_slice(&response_body)?)
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
    let oidc_token_claims = T::verify_token(&request.oidc_token)
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

        let user_secret_key = UserCredentials::random(internal_acc_id.clone());
        let public_key = user_secret_key.public_key();
        state.gcp_service.insert(user_secret_key).await?;

        let delegate_action = get_create_account_delegate_action(
            state.account_creator_id.clone(),
            state.account_creator_sk.public_key(),
            new_user_account_id.clone(),
            public_key,
            new_user_account_pk.clone(),
            state.near_root_account.clone(),
            nonce,
            block_height + 100,
        )?;
        let signed_delegate_action = get_signed_delegated_action(
            delegate_action,
            state.account_creator_id.clone(),
            state.account_creator_sk.clone(),
        );

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
    let oidc_token_claims = T::verify_token(&request.oidc_token)
        .await
        .map_err(AddKeyError::OidcVerificationFailed)?;
    let internal_acc_id = get_internal_account_id(oidc_token_claims);
    let new_public_key: PublicKey = request
        .public_key
        .parse()
        .map_err(|e| AddKeyError::MalformedPublicKey(request.public_key, e))?;
    let user_credentials: UserCredentials = state.gcp_service.get(internal_acc_id.clone()).await?;

    let user_account_id: AccountId = match &request.near_account_id {
        Some(near_account_id) => near_account_id
            .parse()
            .map_err(|e| AddKeyError::MalformedAccountId(request.near_account_id.unwrap(), e))?,
        None => match get_acc_id_from_pk(user_credentials.public_key(), state.account_lookup_url) {
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
            .access_key(user_account_id.clone(), user_credentials.public_key())
            .await?;

        // Create a transaction to create a new account
        let max_block_height: u64 = block_height + 100;
        let delegate_action = get_add_key_delegate_action(
            user_account_id.clone(),
            user_credentials.public_key(),
            new_public_key.clone(),
            nonce,
            max_block_height,
        )?;
        let signed_delegate_action = get_signed_delegated_action(
            delegate_action,
            user_account_id.clone(),
            user_credentials.secret_key.clone(),
        );

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
    match T::verify_token(access_token).await {
        Ok(_) => {
            tracing::info!("access token is valid");
            // continue execution
        }
        Err(_) => {
            tracing::error!("access token verification failed");
            return (StatusCode::UNAUTHORIZED, Json(LeaderResponse::Err));
        }
    }

    let sig_share_request = SigShareRequest {
        payload: request.payload.clone(),
    };
    let payload_json = match serde_json::to_string(&sig_share_request) {
        Ok(payload_json) => payload_json,
        Err(err) => {
            tracing::error!(%err, "failed to convert payload back to json");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(LeaderResponse::Err));
        }
    };

    let response_futures = FuturesUnordered::new();
    for sign_node in state.sign_nodes {
        let req = match Request::builder()
            .method(Method::POST)
            .uri(format!("{}/sign", sign_node))
            .header("content-type", "application/json")
            .body(Body::from(payload_json.clone()))
        {
            Ok(req) => req,
            Err(err) => {
                tracing::error!(%err, "failed to construct a compute request");
                continue;
            }
        };

        let client = Client::new();
        response_futures.push(client.request(req));
    }

    let mut sig_shares = BTreeMap::new();
    sig_shares.insert(state.id, state.sk_share.sign(&request.payload));
    for response_future in response_futures {
        let (node_id, sig_share) = match parse(response_future).await {
            Ok(response) => match response {
                SigShareResponse::Ok { node_id, sig_share } => (node_id, sig_share),
                SigShareResponse::Err => {
                    tracing::error!("Received an error response");
                    continue;
                }
            },
            Err(err) => {
                tracing::error!(%err, "Failed to get response");
                continue;
            }
        };

        if state
            .pk_set
            .public_key_share(node_id)
            .verify(&sig_share, &request.payload)
        {
            match sig_shares.entry(node_id) {
                Entry::Vacant(e) => {
                    tracing::debug!(?sig_share, "received valid signature share");
                    e.insert(sig_share);
                }
                Entry::Occupied(e) if e.get() == &sig_share => {
                    tracing::error!(
                        node_id,
                        sig_share = ?e.get(),
                        "received a duplicate share"
                    );
                }
                Entry::Occupied(e) => {
                    tracing::error!(
                        node_id = node_id,
                        sig_share_1 = ?e.get(),
                        sig_share_2 = ?sig_share,
                        "received two different valid shares for the same node (should be impossible)"
                    );
                }
            }
        } else {
            tracing::error!("received invalid signature",);
        }

        if sig_shares.len() > state.pk_set.threshold() {
            tracing::debug!(
                "received {} valid signature shares, not waiting for the rest",
                sig_shares.len()
            );
            break;
        }
    }

    let sig_shares_num = sig_shares.len();
    tracing::debug!("got {} valid signature shares", sig_shares_num);

    if let Ok(signature) = state.pk_set.combine_signatures(&sig_shares) {
        tracing::debug!(?signature, "replying with full signature");
        (StatusCode::OK, Json(LeaderResponse::Ok { signature }))
    } else {
        tracing::error!(
            "expected to get at least {} shares, but only got {}",
            state.pk_set.threshold() + 1,
            sig_shares_num
        );
        (StatusCode::INTERNAL_SERVER_ERROR, Json(LeaderResponse::Err))
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

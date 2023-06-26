use crate::key_recovery::get_user_recovery_pk;
use crate::msg::{
    AcceptNodePublicKeysRequest, AddKeyRequest, AddKeyResponse, ClaimOidcNodeRequest,
    ClaimOidcRequest, ClaimOidcResponse, NewAccountRequest, NewAccountResponse, SignNodeRequest,
};
use crate::nar;
use crate::oauth::OAuthTokenVerifier;
use crate::relayer::error::RelayerError;
use crate::relayer::msg::RegisterAccountRequest;
use crate::relayer::NearRpcAndRelayerClient;
use crate::transaction::{
    get_add_key_delegate_action, get_create_account_delegate_action,
    get_local_signed_delegated_action, get_mpc_signed_delegated_action, sign_payload_with_mpc,
};
use axum::routing::get;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use curv::elliptic::curves::{Ed25519, Point};
use near_crypto::{ParseKeyError, PublicKey, SecretKey};
use near_primitives::account::id::ParseAccountError;
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionStatus;
use rand::{distributions::Alphanumeric, Rng};
use std::net::SocketAddr;

pub struct Config {
    pub env: String,
    pub port: u16,
    pub sign_nodes: Vec<String>,
    pub near_rpc: String,
    pub relayer_api_key: Option<String>,
    pub relayer_url: String,
    pub near_root_account: String,
    pub account_creator_id: AccountId,
    // TODO: temporary solution
    pub account_creator_sk: SecretKey,
    pub account_lookup_url: String,
    pub pagoda_firebase_audience_id: String,
}

pub async fn run<T: OAuthTokenVerifier + 'static>(config: Config) {
    let Config {
        env,
        port,
        sign_nodes,
        near_rpc,
        relayer_api_key,
        relayer_url,
        near_root_account,
        account_creator_id,
        account_creator_sk,
        account_lookup_url,
        pagoda_firebase_audience_id,
    } = config;
    let _span = tracing::debug_span!("run", env, port);
    tracing::debug!(?sign_nodes, "running a leader node");

    let client = NearRpcAndRelayerClient::connect(&near_rpc, relayer_url, relayer_api_key);
    // FIXME: Internal account id is retrieved from the ID token. We don't have a token for ourselves,
    // but are still forced to allocate allowance.
    // Using randomly generated internal account id ensures the uniqueness of user idenrifier on the relayer side so
    // we can update the allowance on each server run.
    let fake_internal_account_id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    client
        .register_account(RegisterAccountRequest {
            account_id: account_creator_id.clone(),
            allowance: 18_000_000_000_000_000_000, // should be enough to create 700_000+ accs
            oauth_token: fake_internal_account_id,
        })
        .await
        .unwrap();

    let state = LeaderState {
        env,
        sign_nodes,
        client,
        reqwest_client: reqwest::Client::new(),
        near_root_account: near_root_account.parse().unwrap(),
        account_creator_id,
        account_creator_sk,
        account_lookup_url,
        pagoda_firebase_audience_id,
    };

    // Get keys from all sign nodes, and broadcast them out as a set.
    let pk_set = match gather_sign_node_pk_shares(&state).await {
        Ok(pk_set) => pk_set,
        Err(err) => {
            tracing::error!("Unable to gather public keys: {err}");
            return;
        }
    };
    tracing::debug!(?pk_set, "Gathered public keys");
    let messages = match broadcast_pk_set(&state, pk_set).await {
        Ok(messages) => messages,
        Err(err) => {
            tracing::error!("Unable to broadcast public keys: {err}");
            Vec::new()
        }
    };
    tracing::debug!(?messages, "broadcasted public key statuses");

    //TODO: not secure, allow only for testnet, whitelist endpoint etc. for mainnet
    let cors_layer = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/claim_oidc", post(claim_oidc))
        .route("/new_account", post(new_account::<T>))
        .route("/add_key", post(add_key::<T>))
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
    env: String,
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

async fn claim_oidc(
    Extension(state): Extension<LeaderState>,
    Json(claim_oidc_request): Json<ClaimOidcRequest>,
) -> (StatusCode, Json<ClaimOidcResponse>) {
    // Calim OIDC ID Token and get MPC signature from sign nodes
    let sig_share_request = SignNodeRequest::ClaimOidc(ClaimOidcNodeRequest {
        oidc_token_hash: claim_oidc_request.oidc_token_hash,
        public_key: claim_oidc_request.public_key,
        signature: claim_oidc_request.signature,
    });
    let res =
        sign_payload_with_mpc(&state.reqwest_client, &state.sign_nodes, sig_share_request).await;
    // Get user recovery public key from sign nodes (if registered)
    // TODO
    // Get user account id (if registered)
    // TODO
    match res {
        Ok(mpc_signature) => (
            StatusCode::OK,
            Json(ClaimOidcResponse::Ok {
                mpc_signature,
                near_account_id: None,
                recovery_public_key: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ClaimOidcResponse::Err { msg: e.to_string() }),
        ),
    }
}

#[derive(thiserror::Error, Debug)]
enum NewAccountError {
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
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
    let new_user_account_id: AccountId = request
        .near_account_id
        .parse()
        .map_err(|e| NewAccountError::MalformedAccountId(request.near_account_id, e))?;
    let oidc_token_claims =
        T::verify_token(&request.oidc_token, &state.pagoda_firebase_audience_id)
            .await
            .map_err(NewAccountError::OidcVerificationFailed)?;
    let internal_acc_id = oidc_token_claims.get_internal_account_id();

    state
        .client
        .register_account(RegisterAccountRequest {
            account_id: new_user_account_id.clone(),
            allowance: 300_000_000_000_000,
            oauth_token: internal_acc_id.clone(),
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

        let mpc_user_recovery_pk = get_user_recovery_pk(
            &state.reqwest_client,
            &state.sign_nodes,
            internal_acc_id.clone(),
        )
        .await?;

        // Add recovery key to create account options
        let mut new_account_options = request.create_account_options.clone();
        match new_account_options.full_access_keys {
            Some(ref mut keys) => keys.push(mpc_user_recovery_pk.clone()),
            None => new_account_options.full_access_keys = Some(vec![mpc_user_recovery_pk.clone()]),
        }

        let delegate_action = get_create_account_delegate_action(
            state.account_creator_id.clone(),
            state.account_creator_sk.public_key(),
            new_user_account_id.clone(),
            new_account_options.clone(),
            state.near_root_account.clone(),
            nonce,
            block_height + 100,
        )?;
        // We create accounts using the local key
        let signed_delegate_action = get_local_signed_delegated_action(
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
            Ok(NewAccountResponse::Ok {
                create_account_options: new_account_options,
                user_recovery_public_key: mpc_user_recovery_pk.to_string(),
                near_account_id: new_user_account_id.to_string(),
            })
        } else {
            Err(anyhow::anyhow!("transaction failed with {:?}", response.status).into())
        }
    })
    .await
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

#[tracing::instrument(level = "info", skip_all, fields(env = state.env))]
async fn new_account<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<NewAccountRequest>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        near_account_id = request.near_account_id.clone(),
        create_account_options = request.create_account_options.to_string(),
        iodc_token = format!("{:.5}...", request.oidc_token),
        "new_account request"
    );

    match process_new_account::<T>(state, request).await {
        Ok(response) => {
            tracing::debug!("responding with OK");
            (StatusCode::OK, Json(response))
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
#[allow(dead_code)]
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
    tracing::info!(
        url = url,
        public_key = public_key.to_string(),
        "fetching account id from public key"
    );
    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send()?.text()?;
    let accounts: Vec<String> = serde_json::from_str(&response)?;
    tracing::info!(accounts = ?accounts, "fetched accounts");
    match accounts.first() {
        Some(account_id) => {
            tracing::info!(account_id = account_id, "using first account id");
            Ok(account_id.parse()?)
        }
        None => {
            tracing::error!(
                public_key = public_key.to_string(),
                "no account found for pk"
            );
            Err(anyhow::anyhow!("no account found for pk: {}", public_key))
        }
    }
}

async fn process_add_key<T: OAuthTokenVerifier>(
    state: LeaderState,
    request: AddKeyRequest,
) -> Result<AddKeyResponse, AddKeyError> {
    let oidc_token_claims =
        T::verify_token(&request.oidc_token, &state.pagoda_firebase_audience_id)
            .await
            .map_err(AddKeyError::OidcVerificationFailed)?;
    let internal_acc_id = oidc_token_claims.get_internal_account_id();
    let user_recovery_pk = get_user_recovery_pk(
        &state.reqwest_client,
        &state.sign_nodes,
        internal_acc_id.clone(),
    )
    .await?;

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
            request.create_account_options.clone(),
            nonce,
            max_block_height,
        )?;
        // We sign the key recovery using the signing nodes
        let signed_delegate_action = get_mpc_signed_delegated_action(
            &state.reqwest_client,
            &state.sign_nodes,
            request.oidc_token.clone(),
            delegate_action,
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
            Ok(AddKeyResponse::Ok {
                full_access_keys: request
                    .create_account_options
                    .clone()
                    .full_access_keys
                    .unwrap_or_default()
                    .into_iter()
                    .map(|pk| pk.to_string())
                    .collect(),
                limited_access_keys: request
                    .create_account_options
                    .clone()
                    .limited_access_keys
                    .unwrap_or_default()
                    .into_iter()
                    .map(|lak| lak.public_key.to_string())
                    .collect(),
                near_account_id: user_account_id.to_string(),
            })
        } else {
            Err(anyhow::anyhow!("transaction failed with {:?}", resp.status).into())
        }
    })
    .await
}

#[tracing::instrument(level = "info", skip_all, fields(env = state.env))]
async fn add_key<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<AddKeyRequest>,
) -> (StatusCode, Json<AddKeyResponse>) {
    tracing::info!(
        near_account_id = match &request.near_account_id {
            Some(ref near_account_id) => near_account_id,
            None => "not specified",
        },
        create_account_options = request.create_account_options.to_string(),
        iodc_token = format!("{:.5}...", request.oidc_token),
        "add_key request"
    );

    match process_add_key::<T>(state, request).await {
        Ok(response) => {
            tracing::debug!("responding with OK");
            (StatusCode::OK, Json(response))
        }
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
        Err(ref e @ AddKeyError::AccountNotFound(ref err_msg)) => {
            tracing::error!(err = ?e);
            response::add_key_bad_request(format!(
                "failed to recover account_id from pk: {}",
                err_msg
            ))
        }
        Err(e) => {
            tracing::error!(err = ?e);
            response::add_key_internal_error(format!("failed to process new account: {}", e))
        }
    }
}

async fn gather_sign_node_pk_shares(state: &LeaderState) -> anyhow::Result<Vec<Point<Ed25519>>> {
    let fut = nar::retry_every(std::time::Duration::from_secs(1), || async {
        let results: anyhow::Result<Vec<(usize, Point<Ed25519>)>> =
            crate::transaction::call_all_nodes(
                &state.reqwest_client,
                &state.sign_nodes,
                "public_key_node",
                (),
            )
            .await;
        let mut results = match results {
            Ok(results) => results,
            Err(err) => {
                tracing::debug!("failed to gather pk: {err}");
                return Err(err);
            }
        };

        results.sort_by_key(|(index, _)| *index);
        let results: Vec<Point<Ed25519>> =
            results.into_iter().map(|(_index, point)| point).collect();

        anyhow::Result::Ok(results)
    });

    let results = tokio::time::timeout(std::time::Duration::from_secs(60), fut)
        .await
        .map_err(|_| anyhow::anyhow!("timeout gathering sign node pks"))??;
    Ok(results)
}

async fn broadcast_pk_set(
    state: &LeaderState,
    pk_set: Vec<Point<Ed25519>>,
) -> anyhow::Result<Vec<String>> {
    let request = AcceptNodePublicKeysRequest {
        public_keys: pk_set,
    };

    let messages: Vec<String> = crate::transaction::call_all_nodes(
        &state.reqwest_client,
        &state.sign_nodes,
        "accept_pk_set",
        request,
    )
    .await?;

    Ok(messages)
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

    #[test]
    fn test_get_acc_id_from_unexisting_pk_testnet() {
        let url = "https://testnet-api.kitwallet.app".to_string();
        let public_key: PublicKey = "ed25519:2uF6ZUghFFUg3Kta9rW47iiJ3crNzRdaPD2rBPQWEwyc"
            .parse()
            .unwrap();
        match get_acc_id_from_pk(public_key.clone(), url) {
            Ok(_) => panic!("Should not be able to get account id from unexisting pk"),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    format!("no account found for pk: {}", public_key)
                );
            }
        }
    }
}

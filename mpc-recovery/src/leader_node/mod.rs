use crate::gcp::GcpService;
use crate::key_recovery::UserSecretKey;
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
use near_crypto::{PublicKey, SecretKey};
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
}

async fn parse(response_future: ResponseFuture) -> anyhow::Result<SigShareResponse> {
    let response = response_future.await?;
    let response_body = hyper::body::to_bytes(response.into_body()).await?;
    Ok(serde_json::from_slice(&response_body)?)
}

async fn process_new_account(
    state: &LeaderState,
    request: &NewAccountRequest,
    internal_acc_id: InternalAccountId,
) -> anyhow::Result<(StatusCode, Json<NewAccountResponse>)> {
    // Create a transaction to create new NEAR account
    let new_user_account_pk: PublicKey = request.public_key.clone().parse()?;
    let new_user_account_id: AccountId = request.near_account_id.clone().parse()?;

    state
        .client
        .register_account(RegisterAccountRequest {
            account_id: new_user_account_id.clone(),
            allowance: 300_000_000_000_000,
            oauth_token: request.oidc_token.clone(),
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

        let user_secret_key = UserSecretKey::random(internal_acc_id.clone());
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
            Ok((StatusCode::OK, Json(NewAccountResponse::Ok)))
        } else {
            Err(anyhow::anyhow!(
                "transaction failed with {:?}",
                response.status
            ))
        }
    })
    .await
}

pub fn get_internal_account_id(claims: IdTokenClaims) -> InternalAccountId {
    format!("{}:{}", claims.iss, claims.sub)
}

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn new_account<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<NewAccountRequest>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        access_token = format!("{:.5}...", request.oidc_token),
        "new request"
    );

    match T::verify_token(&request.oidc_token).await {
        Ok(claims) => {
            tracing::info!("access token is valid");
            match process_new_account(&state, &request, get_internal_account_id(claims)).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(err = ?e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(NewAccountResponse::Err {
                            msg: format!("failed to process new account: {}", e),
                        }),
                    )
                }
            }
        }
        Err(e) => {
            tracing::error!("access token verification failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(NewAccountResponse::Err {
                    msg: format!("access token verification failed: {}", e),
                }),
            )
        }
    }
}

async fn process_add_key(
    state: &LeaderState,
    request: &AddKeyRequest,
    internal_acc_id: InternalAccountId,
) -> anyhow::Result<(StatusCode, Json<AddKeyResponse>)> {
    let user_account_id: AccountId = request.near_account_id.parse()?;
    let new_public_key: PublicKey = request.public_key.parse()?;
    let user_secret_key: UserSecretKey = state.gcp_service.get(internal_acc_id.clone()).await?;

    nar::retry(|| async {
        // Get nonce and recent block hash
        let (_hash, block_height, nonce) = match state
            .client
            .access_key(user_account_id.clone(), user_secret_key.public_key())
            .await
        {
            Ok(val) => val,
            Err(RelayerError::UnknownAccount(account_id)) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(AddKeyResponse::Err {
                        msg: format!("account {account_id} does not exist"),
                    }),
                ))
            }
            Err(RelayerError::UnknownAccessKey(public_key)) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(AddKeyResponse::Err {
                        msg: format!("public key {public_key} does not exist"),
                    }),
                ))
            }
            Err(RelayerError::Other(e)) => return Err(e),
        };

        // Create a transaction to create a new account
        let max_block_height: u64 = block_height + 100;
        let delegate_action = get_add_key_delegate_action(
            user_account_id.clone(),
            user_secret_key.public_key(),
            new_public_key.clone(),
            nonce,
            max_block_height,
        )?;
        let signed_delegate_action = get_signed_delegated_action(
            delegate_action,
            user_account_id.clone(),
            user_secret_key.secret_key.clone(),
        );

        let result = state.client.send_meta_tx(signed_delegate_action).await;
        if let Err(err) = result {
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
            return Err(err);
        }

        Ok((StatusCode::OK, Json(AddKeyResponse::Ok)))
    })
    .await
}

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn add_key<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<AddKeyRequest>,
) -> (StatusCode, Json<AddKeyResponse>) {
    tracing::info!(
        access_token = format!("{:.5}...", request.oidc_token),
        public_key = hex::encode(&request.public_key),
        "new request"
    );

    match T::verify_token(&request.oidc_token).await {
        Ok(claims) => {
            tracing::info!("access token is valid");
            match process_add_key(&state, &request, get_internal_account_id(claims)).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(err = ?e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(AddKeyResponse::Err {
                            msg: "internal error".to_string(),
                        }),
                    )
                }
            }
        }
        Err(_) => {
            tracing::error!("access token verification failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(AddKeyResponse::Err {
                    msg: "access token verification failed".into(),
                }),
            )
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

use self::aggregate_signer::{NodeInfo, Reveal, SignedCommitment, SigningState};
use crate::msg::SigShareRequest;
use crate::oauth::{OAuthTokenVerifier, UniversalTokenVerifier};
use crate::primitives::InternalAccountId;
use crate::NodeId;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use curv::elliptic::curves::{Ed25519, Point};
use multi_party_eddsa::protocols::{self, ExpandedKeyPair};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod aggregate_signer;
pub mod user_credentials;

#[tracing::instrument(level = "debug", skip(node_key, nodes_public_keys))]
pub async fn run(
    our_index: NodeId,
    nodes_public_keys: Vec<Point<Ed25519>>,
    node_key: ExpandedKeyPair,
    port: u16,
) {
    tracing::debug!("running a sign node");
    let our_index = usize::try_from(our_index).expect("This index is way to big");

    if nodes_public_keys.get(our_index) != Some(&node_key.public_key) {
        tracing::error!("provided secret share does not match the node id");
        return;
    }

    let pagoda_firebase_audience_id = "pagoda-firebase-audience-id".to_string();

    let signing_state = Arc::new(RwLock::new(SigningState::new()));

    let state = SignNodeState {
        node_key,
        signing_state,
        pagoda_firebase_audience_id,
        node_info: NodeInfo {
            nodes_public_keys,
            our_index,
        },
    };

    let app = Router::new()
        .route("/commit", post(commit::<UniversalTokenVerifier>))
        .route("/reveal", post(reveal))
        .route("/signature_share", post(signature_share))
        .route("/public_key", post(public_key))
        .layer(Extension(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Clone)]
struct SignNodeState {
    pagoda_firebase_audience_id: String,
    node_key: ExpandedKeyPair,
    signing_state: Arc<RwLock<SigningState>>,
    node_info: NodeInfo,
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn commit<T: OAuthTokenVerifier>(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<SigShareRequest>,
) -> (StatusCode, Json<Result<SignedCommitment, String>>) {
    // TODO: extract access token from payload
    let access_token = "validToken";
    match T::verify_token(access_token, &state.pagoda_firebase_audience_id).await {
        Ok(_) => {
            tracing::debug!("access token is valid");

            // TODO use seperate signing and node keys + key derivation
            let response = state.signing_state.write().await.get_commitment(
                &state.node_key,
                &state.node_key,
                // TODO Restrict this payload
                request.payload,
            );
            match &response {
                Ok(_) => tracing::debug!("Successful commitment"),
                Err(e) => tracing::error!("Commitment payload failed: {}", e),
            };

            (StatusCode::OK, Json(response))
        }
        Err(_) => {
            const ERR: &str = "access token verification failed";
            tracing::debug!(ERR);
            (StatusCode::UNAUTHORIZED, Json(Err(ERR.to_string())))
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn reveal(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<Vec<SignedCommitment>>,
) -> (StatusCode, Json<Result<Reveal, String>>) {
    match state
        .signing_state
        .write()
        .await
        .get_reveal(state.node_info, request)
    {
        Ok(r) => {
            tracing::debug!("Successful reveal");
            (StatusCode::OK, Json(Ok(r)))
        }
        Err(e) => {
            tracing::error!("Reveal failed: {}", e);
            (StatusCode::BAD_REQUEST, Json(Err(e)))
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn signature_share(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<Vec<Reveal>>,
) -> (StatusCode, Json<Result<protocols::Signature, String>>) {
    match state
        .signing_state
        .write()
        .await
        .get_signature_share(state.node_info, request)
    {
        Ok(r) => {
            tracing::debug!("Successful signature share");
            (StatusCode::OK, Json(Ok(r)))
        }
        Err(e) => {
            tracing::error!("Signature share failed: {}", e);
            (StatusCode::BAD_REQUEST, Json(Err(e)))
        }
    }
}

async fn public_key(
    Extension(state): Extension<SignNodeState>,
    Json(_request): Json<InternalAccountId>,
) -> (StatusCode, Json<Result<Point<Ed25519>, String>>) {
    // TODO lookup correct public key
    (StatusCode::OK, Json(Ok(state.node_key.public_key)))
}

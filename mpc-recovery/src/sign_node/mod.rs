use self::aggregate_signer::{NodeInfo, Reveal, SignedCommitment, SigningState};
use self::user_credentials::UserCredentials;
use crate::gcp::GcpService;
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

#[tracing::instrument(level = "debug", skip(gcp_service, node_key, nodes_public_keys))]
pub async fn run(
    gcp_service: GcpService,
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
        gcp_service,
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
    gcp_service: GcpService,
    pagoda_firebase_audience_id: String,
    node_key: ExpandedKeyPair,
    signing_state: Arc<RwLock<SigningState>>,
    node_info: NodeInfo,
}

#[derive(thiserror::Error, Debug)]
enum CommitError {
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

async fn get_or_generate_user_creds(
    state: &SignNodeState,
    internal_account_id: InternalAccountId,
) -> anyhow::Result<UserCredentials> {
    match state
        .gcp_service
        .get::<_, UserCredentials>(format!(
            "{}/{}",
            state.node_info.our_index, internal_account_id
        ))
        .await
    {
        Ok(Some(user_credentials)) => {
            tracing::debug!(internal_account_id, "found an existing user");
            Ok(user_credentials)
        }
        Ok(None) => {
            let key_pair = ExpandedKeyPair::create();
            tracing::debug!(
                internal_account_id,
                public_key = ?key_pair.public_key,
                "generating credentials for a new user"
            );
            let user_credentials = UserCredentials {
                node_id: state.node_info.our_index,
                internal_account_id,
                key_pair,
            };
            state.gcp_service.insert(user_credentials.clone()).await?;
            Ok(user_credentials)
        }
        Err(e) => Err(e),
    }
}

async fn process_commit<T: OAuthTokenVerifier>(
    state: SignNodeState,
    request: SigShareRequest,
) -> Result<SignedCommitment, CommitError> {
    let oidc_token_claims =
        T::verify_token(&request.oidc_token, &state.pagoda_firebase_audience_id)
            .await
            .map_err(CommitError::OidcVerificationFailed)?;
    let internal_account_id = oidc_token_claims.get_internal_account_id();

    let user_credentials = get_or_generate_user_creds(&state, internal_account_id).await?;

    let response = state
        .signing_state
        .write()
        .await
        .get_commitment(
            &user_credentials.key_pair,
            &state.node_key,
            // TODO Restrict this payload
            request.payload,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(response)
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn commit<T: OAuthTokenVerifier>(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<SigShareRequest>,
) -> (StatusCode, Json<Result<SignedCommitment, String>>) {
    match process_commit::<T>(state, request).await {
        Ok(signed_commitment) => (StatusCode::OK, Json(Ok(signed_commitment))),
        Err(ref e @ CommitError::OidcVerificationFailed(ref err_msg)) => {
            tracing::error!(err = ?e);
            (
                StatusCode::BAD_REQUEST,
                Json(Err(format!("failed to verify oidc token: {}", err_msg))),
            )
        }
        Err(e) => {
            tracing::error!(err = ?e);
            (
                StatusCode::BAD_REQUEST,
                Json(Err(format!("failed to process new account: {}", e))),
            )
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

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn public_key(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<InternalAccountId>,
) -> (StatusCode, Json<Result<Point<Ed25519>, String>>) {
    match get_or_generate_user_creds(&state, request).await {
        Ok(user_credentials) => (
            StatusCode::OK,
            Json(Ok(user_credentials.public_key().clone())),
        ),
        Err(err) => {
            tracing::error!(?err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Err(
                    "failed to fetch/generate a public key for given account".to_string(),
                )),
            )
        }
    }
}

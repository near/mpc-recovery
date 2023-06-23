use self::aggregate_signer::{NodeInfo, Reveal, SignedCommitment, SigningState};
use self::user_credentials::EncryptedUserCredentials;
use crate::gcp::GcpService;
use crate::msg::{AcceptNodePublicKeysRequest, SignNodeRequest};
use crate::oauth::OAuthTokenVerifier;
use crate::primitives::InternalAccountId;
use crate::sign_node::pk_set::SignerNodePkSet;
use crate::utils::claim_oidc_response_digest;
use crate::NodeId;
use aes_gcm::Aes256Gcm;
use axum::routing::get;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use curv::elliptic::curves::{Ed25519, Point};
use multi_party_eddsa::protocols::{self, ExpandedKeyPair};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod aggregate_signer;
pub mod pk_set;
pub mod user_credentials;

pub struct Config {
    pub gcp_service: GcpService,
    pub our_index: NodeId,
    pub node_key: ExpandedKeyPair,
    pub cipher: Aes256Gcm,
    pub port: u16,
    pub pagoda_firebase_audience_id: String,
}

pub async fn run<T: OAuthTokenVerifier + 'static>(config: Config) {
    tracing::debug!("running a sign node");
    let Config {
        gcp_service,
        our_index,
        node_key,
        cipher,
        port,
        pagoda_firebase_audience_id,
    } = config;
    let our_index = usize::try_from(our_index).expect("This index is way to big");

    let pk_set = gcp_service
        .get::<_, SignerNodePkSet>(format!("{}/{}", our_index, pk_set::MAIN_KEY))
        .await
        .unwrap_or_default();

    let signing_state = Arc::new(RwLock::new(SigningState::new()));
    let state = SignNodeState {
        gcp_service,
        node_key,
        cipher,
        signing_state,
        pagoda_firebase_audience_id,
        node_info: NodeInfo::new(our_index, pk_set.map(|set| set.public_keys)),
    };

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/commit", post(commit::<T>))
        .route("/reveal", post(reveal))
        .route("/signature_share", post(signature_share))
        .route("/public_key", post(public_key))
        .route("/public_key_node", post(public_key_node))
        .route("/accept_pk_set", post(accept_pk_set))
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
    cipher: Aes256Gcm,
    signing_state: Arc<RwLock<SigningState>>,
    node_info: NodeInfo,
}

//TODO: extend with new error types for token claiming
#[derive(thiserror::Error, Debug)]
pub enum CommitError {
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

async fn get_or_generate_user_creds(
    state: &SignNodeState,
    internal_account_id: InternalAccountId,
) -> anyhow::Result<EncryptedUserCredentials> {
    match state
        .gcp_service
        .get::<_, EncryptedUserCredentials>(format!(
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
            let user_credentials = EncryptedUserCredentials::random(
                state.node_info.our_index,
                internal_account_id.clone(),
                &state.cipher,
            )?;
            tracing::debug!(
                internal_account_id,
                public_key = ?user_credentials.public_key,
                "generating credentials for a new user"
            );
            state.gcp_service.insert(user_credentials.clone()).await?;
            Ok(user_credentials)
        }
        Err(e) => Err(e),
    }
}

async fn process_commit<T: OAuthTokenVerifier>(
    state: SignNodeState,
    request: SignNodeRequest,
) -> Result<SignedCommitment, CommitError> {
    match request {
        SignNodeRequest::ClaimOidc(request) => {
            // Check ID token hash signature
            // TODO
            // Save info about token in the database
            // TODO
            // Returned signed commitment (signature of the signature)
            // TODO: check if we are getting root key pair properly
            let payload = match claim_oidc_response_digest(request.signature) {
                Ok(payload) => payload,
                Err(e) => return Err(e),
            };
            let response = state
                .signing_state
                .write()
                .await
                .get_commitment(&state.node_key, &state.node_key, payload)
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(response)
        }
        SignNodeRequest::SignShare(request) => {
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
                    &user_credentials.decrypt_key_pair(&state.cipher)?,
                    &state.node_key,
                    // TODO Restrict this payload
                    request.payload,
                )
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(response)
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn commit<T: OAuthTokenVerifier>(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<SignNodeRequest>,
) -> (StatusCode, Json<Result<SignedCommitment, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match process_commit::<T>(state, request).await {
        Ok(signed_commitment) => (StatusCode::OK, Json(Ok(signed_commitment))),
        Err(ref e @ CommitError::OidcVerificationFailed(ref err_msg)) => {
            tracing::error!(err = ?e);
            (
                StatusCode::BAD_REQUEST,
                Json(Err(format!(
                    "signer failed to verify oidc token: {}",
                    err_msg
                ))),
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
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match state
        .signing_state
        .write()
        .await
        .get_reveal(state.node_info, request)
        .await
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
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

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
                Json(Err(format!(
                    "failed to fetch/generate a public key for given account: {}",
                    err,
                ))),
            )
        }
    }
}

// TODO: remove type complexity
#[allow(clippy::type_complexity)]
#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn public_key_node(
    Extension(state): Extension<SignNodeState>,
    Json(_): Json<()>,
) -> (StatusCode, Json<Result<(usize, Point<Ed25519>), String>>) {
    (
        StatusCode::OK,
        Json(Ok((state.node_info.our_index, state.node_key.public_key))),
    )
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn accept_pk_set(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<AcceptNodePublicKeysRequest>,
) -> (StatusCode, Json<Result<String, String>>) {
    let index = state.node_info.our_index;
    if request.public_keys.get(index) != Some(&state.node_key.public_key) {
        tracing::error!("provided secret share does not match the node id");
        return (StatusCode::BAD_REQUEST, Json(Err(format!(
            "Sign node could not accept the public keys: current node index={index} does not match up"))));
    }

    let mut public_keys = state.node_info.nodes_public_keys.write().await;
    if let Some(pk_set) = public_keys.as_ref() {
        if pk_set == &request.public_keys {
            return (
                StatusCode::OK,
                Json(Ok(
                    "This node is already initialized with provided public keys".to_string(),
                )),
            );
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(Err(
                    "This node is already initialized with different public keys".to_string(),
                )),
            );
        }
    }
    tracing::debug!("Setting node public keys => {:?}", request.public_keys);
    public_keys.replace(request.public_keys.clone());
    match state
        .gcp_service
        .insert(SignerNodePkSet {
            node_id: state.node_info.our_index,
            public_keys: request.public_keys,
        })
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(Ok("Successfully set node public keys".to_string())),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Ok("failed to save the keys".to_string())),
        ),
    }
}

/// Validate whether the current state of the sign node is useable or not.
async fn check_if_ready(state: &SignNodeState) -> Result<(), String> {
    let public_keys = state.node_info.nodes_public_keys.read().await;
    if public_keys.is_none() {
        return Err(
            "Sign node is not ready yet: waiting on all public keys from leader node".into(),
        );
    }

    Ok(())
}

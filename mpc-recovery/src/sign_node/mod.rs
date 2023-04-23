use crate::msg::{SigShareRequest, SigShareResponse};
use crate::oauth::{OAuthTokenVerifier, UniversalTokenVerifier};
use crate::NodeId;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use std::net::SocketAddr;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

#[tracing::instrument(level = "debug", skip(pk_set, sk_share))]
pub async fn run(id: NodeId, pk_set: PublicKeySet, sk_share: SecretKeyShare, port: u16) {
    tracing::debug!("running a sign node");

    if pk_set.public_key_share(id) != sk_share.public_key_share() {
        tracing::error!("provided secret share does not match the node id");
        return;
    }

    let pagoda_firebase_audience_id = "pagoda-firebase-audience-id".to_string();

    let state = SignNodeState {
        id,
        sk_share,
        pagoda_firebase_audience_id,
    };

    let app = Router::new()
        .route("/sign", post(sign::<UniversalTokenVerifier>))
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
    id: NodeId,
    sk_share: SecretKeyShare,
    pagoda_firebase_audience_id: String,
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn sign<T: OAuthTokenVerifier>(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<SigShareRequest>,
) -> (StatusCode, Json<SigShareResponse>) {
    tracing::info!(payload = request.payload, "sign request");

    // TODO: extract access token from payload
    let access_token = "validToken";
    match T::verify_token(access_token, &state.pagoda_firebase_audience_id).await {
        Ok(_) => {
            tracing::debug!("access token is valid");
            let response = SigShareResponse::Ok {
                node_id: state.id,
                sig_share: state.sk_share.sign(request.payload),
            };
            (StatusCode::OK, Json(response))
        }
        Err(_) => {
            tracing::debug!("access token verification failed");
            (StatusCode::UNAUTHORIZED, Json(SigShareResponse::Err))
        }
    }
}

use self::error::MpcSignError;
use crate::protocol::{MpcSignMsg, ProtocolState};
use axum::{
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::WithRejection;
use mpc_recovery_common::sign::{MsgRequest, SignNodeState};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc::Sender, RwLock};

mod error;

#[derive(Clone)]
struct AxumState {
    sender: Sender<MpcSignMsg>,
    protocol_state: Arc<RwLock<ProtocolState>>,
}

pub async fn run(
    port: u16,
    sender: Sender<MpcSignMsg>,
    protocol_state: Arc<RwLock<ProtocolState>>,
) -> anyhow::Result<()> {
    tracing::debug!("running a sign node");
    let axum_state = AxumState {
        sender,
        protocol_state,
    };

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("sign node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/msg", post(msg))
        .route("/state", post(state))
        .layer(Extension(axum_state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

#[tracing::instrument(level = "debug", skip_all)]
async fn msg(
    Extension(state): Extension<AxumState>,
    WithRejection(Json(request), _): WithRejection<Json<MsgRequest>, MpcSignError>,
) -> StatusCode {
    tracing::debug!(from = ?request.from, msg_len = request.msg.len(), "sending a message");
    match state
        .sender
        .send(MpcSignMsg::Msg {
            from: request.from,
            data: request.msg,
        })
        .await
    {
        Ok(()) => StatusCode::OK,
        Err(e) => {
            tracing::error!("failed to send a protocol message: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(state): Extension<AxumState>) -> (StatusCode, Json<SignNodeState>) {
    tracing::debug!("fetching state");
    let protocol_state = state.protocol_state.read().await;
    match &*protocol_state {
        ProtocolState::Starting => (
            StatusCode::OK,
            Json(SignNodeState {
                participants: HashMap::new(),
                public_key: None,
            }),
        ),
        ProtocolState::Started { public_key, .. } => (
            StatusCode::OK,
            Json(SignNodeState {
                participants: HashMap::new(),
                public_key: public_key.clone(),
            }),
        ),
        ProtocolState::Generating { participants, .. } => (
            StatusCode::OK,
            Json(SignNodeState {
                participants: participants.clone(),
                public_key: None,
            }),
        ),
        ProtocolState::Running {
            participants,
            public_key,
            ..
        } => (
            StatusCode::OK,
            Json(SignNodeState {
                participants: participants.clone(),
                public_key: Some(public_key.clone()),
            }),
        ),
        ProtocolState::Resharing {
            participants,
            public_key,
            ..
        } => (
            StatusCode::OK,
            Json(SignNodeState {
                participants: participants.clone(),
                public_key: Some(public_key.clone()),
            }),
        ),
    }
}

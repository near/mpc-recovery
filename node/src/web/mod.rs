use self::error::MpcSignError;
use crate::{
    protocol::{MpcSignMsg, ProtocolState},
    util::serde_participant,
};
use axum::{
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::WithRejection;
use cait_sith::protocol::Participant;
use near_crypto::InMemorySigner;
use near_primitives::{
    transaction::{Action, FunctionCallAction},
    types::AccountId,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc::Sender, RwLock};
use url::Url;

mod error;

struct AxumState {
    mpc_contract_id: AccountId,
    rpc_client: near_fetch::Client,
    signer: InMemorySigner,
    sender: Sender<MpcSignMsg>,
    protocol_state: Arc<RwLock<ProtocolState>>,
}

pub async fn run(
    port: u16,
    mpc_contract_id: AccountId,
    rpc_client: near_fetch::Client,
    signer: InMemorySigner,
    sender: Sender<MpcSignMsg>,
    protocol_state: Arc<RwLock<ProtocolState>>,
) -> anyhow::Result<()> {
    tracing::debug!("running a node");
    let axum_state = AxumState {
        mpc_contract_id,
        rpc_client,
        signer,
        sender,
        protocol_state,
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
        .route("/msg", post(msg))
        .route("/join", post(join))
        .layer(Extension(Arc::new(axum_state)));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MsgRequest {
    #[serde(with = "serde_participant")]
    pub from: Participant,
    pub msg: Vec<u8>,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn msg(
    Extension(state): Extension<Arc<AxumState>>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    #[serde(with = "serde_participant")]
    pub id: Participant,
    pub account_id: AccountId,
    pub url: Url,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn join(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Json(request), _): WithRejection<Json<JoinRequest>, MpcSignError>,
) -> StatusCode {
    let protocol_state = state.protocol_state.read().await;
    match &*protocol_state {
        ProtocolState::Running { .. } => {
            let args = serde_json::json!({
                "participant": request
            });
            match state
                .rpc_client
                .send_tx(
                    &state.signer,
                    &state.mpc_contract_id,
                    vec![Action::FunctionCall(FunctionCallAction {
                        method_name: "vote_join".to_string(),
                        args: serde_json::to_vec(&args).unwrap(),
                        gas: 300_000_000_000_000,
                        deposit: 0,
                    })],
                )
                .await
            {
                Ok(_) => {
                    tracing::info!(id = ?request.id, "successfully voted for a node to join");
                    StatusCode::OK
                }
                Err(e) => {
                    tracing::error!(%e, "failed to vote for a new node to join");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }
        _ => {
            tracing::debug!(id = ?request.id, "not ready to accept join requests yet");
            StatusCode::BAD_REQUEST
        }
    }
}

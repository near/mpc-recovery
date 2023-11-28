mod error;

use self::error::MpcSignError;
use crate::protocol::message::SignedMessage;
use crate::protocol::{MpcMessage, NodeState};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::WithRejection;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::{self, Ciphered};
use near_crypto::InMemorySigner;
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc::Sender, RwLock};

struct AxumState {
    mpc_contract_id: AccountId,
    rpc_client: near_fetch::Client,
    signer: InMemorySigner,
    sender: Sender<MpcMessage>,
    protocol_state: Arc<RwLock<NodeState>>,
    cipher_sk: hpke::SecretKey,
}

pub async fn run(
    port: u16,
    mpc_contract_id: AccountId,
    rpc_client: near_fetch::Client,
    signer: InMemorySigner,
    sender: Sender<MpcMessage>,
    cipher_sk: hpke::SecretKey,
    protocol_state: Arc<RwLock<NodeState>>,
) -> anyhow::Result<()> {
    tracing::debug!("running a node");
    let axum_state = AxumState {
        mpc_contract_id,
        rpc_client,
        signer,
        sender,
        protocol_state,
        cipher_sk,
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
        .route("/state", get(state))
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
    pub from: Participant,
    pub msg: Vec<u8>,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn msg(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Json(encrypted), _): WithRejection<Json<Ciphered>, MpcSignError>,
) -> StatusCode {
    tracing::debug!(ciphertext = ?encrypted.text, "received encrypted");
    let message =
        match SignedMessage::decrypt(&state.cipher_sk, &state.protocol_state, encrypted).await {
            Ok(msg) => msg,
            Err(err) => {
                tracing::error!(?err, "failed to decrypt or verify an encrypted message");
                return StatusCode::BAD_REQUEST;
            }
        };

    match state.sender.send(message).await {
        Ok(()) => StatusCode::OK,
        Err(e) => {
            tracing::error!("failed to send an encrypted protocol message: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[tracing::instrument(level = "debug", skip_all)]
async fn join(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Json(participant), _): WithRejection<Json<Participant>, MpcSignError>,
) -> StatusCode {
    let protocol_state = state.protocol_state.read().await;
    match &*protocol_state {
        NodeState::Running { .. } => {
            let args = serde_json::json!({
                "participant": participant
            });
            match state
                .rpc_client
                .send_tx(
                    &state.signer,
                    &state.mpc_contract_id,
                    vec![Action::FunctionCall(FunctionCallAction {
                        method_name: "vote_join".to_string(),
                        args: args.to_string().into_bytes(),
                        gas: 300_000_000_000_000,
                        deposit: 0,
                    })],
                )
                .await
            {
                Ok(_) => {
                    tracing::info!(?participant, "successfully voted for a node to join");
                    StatusCode::OK
                }
                Err(e) => {
                    tracing::error!(%e, "failed to vote for a new node to join");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }
        _ => {
            tracing::debug!(?participant, "not ready to accept join requests yet");
            StatusCode::BAD_REQUEST
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum StateView {
    Running {
        participants: Vec<Participant>,
        triple_count: usize,
        presignature_count: usize,
    },
    NotRunning,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(state): Extension<Arc<AxumState>>) -> (StatusCode, Json<StateView>) {
    tracing::debug!("fetching state");
    let protocol_state = state.protocol_state.read().await;
    match &*protocol_state {
        NodeState::Running(state) => {
            let triple_count = state.triple_manager.read().await.len();
            let presignature_count = state.presignature_manager.read().await.len();

            tracing::debug!("not running, state unavailable");
            (
                StatusCode::OK,
                Json(StateView::Running {
                    participants: state.participants.keys().cloned().collect(),
                    triple_count,
                    presignature_count,
                }),
            )
        }
        _ => {
            tracing::debug!("not running, state unavailable");
            (StatusCode::OK, Json(StateView::NotRunning))
        }
    }
}

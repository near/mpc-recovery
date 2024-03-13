mod error;

use self::error::Error;
use crate::protocol::message::SignedMessage;
use crate::protocol::{ConsensusError, MpcMessage, NodeState};
use crate::web::error::Result;
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
    allowed_participants: Vec<AccountId>,
}

pub async fn run(
    port: u16,
    mpc_contract_id: AccountId,
    rpc_client: near_fetch::Client,
    signer: InMemorySigner,
    sender: Sender<MpcMessage>,
    cipher_sk: hpke::SecretKey,
    protocol_state: Arc<RwLock<NodeState>>,
    allowed_participants: Vec<AccountId>,
) -> anyhow::Result<()> {
    tracing::debug!("running a node");
    let axum_state = AxumState {
        mpc_contract_id,
        rpc_client,
        signer,
        sender,
        protocol_state,
        cipher_sk,
        allowed_participants,
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
    WithRejection(Json(encrypted), _): WithRejection<Json<Ciphered>, Error>,
) -> Result<()> {
    tracing::debug!(ciphertext = ?encrypted.text, "received encrypted");
    let message =
        match SignedMessage::decrypt(&state.cipher_sk, &state.protocol_state, encrypted).await {
            Ok(msg) => msg,
            Err(err) => {
                tracing::error!(?err, "failed to decrypt or verify an encrypted message");
                return Err(err.into());
            }
        };

    if let Err(err) = state.sender.send(message).await {
        tracing::error!(?err, "failed to forward an encrypted protocol message");
        return Err(err.into());
    }
    Ok(())
}

#[tracing::instrument(level = "debug", skip_all)]
async fn join(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Json(account_id), _): WithRejection<Json<AccountId>, Error>,
) -> Result<()> {
    if !state.allowed_participants.contains(&account_id) {
        tracing::error!(?account_id, "is not added to the allow list");
        return Err(Error::Protocol(ConsensusError::AccountIdIsNotInAllowList));
    }
    let protocol_state = state.protocol_state.read().await;
    match &*protocol_state {
        NodeState::Running { .. } => {
            let args = serde_json::json!({
                "candidate_account_id": account_id
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
                    tracing::info!(?account_id, "successfully voted for a node to join");
                    Ok(())
                }
                Err(e) => {
                    tracing::error!(%e, "failed to vote for a new node to join");
                    Err(e)?
                }
            }
        }
        _ => {
            tracing::debug!(?account_id, "not ready to accept join requests yet");
            Err(Error::NotRunning)
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
        triple_mine_count: usize,
        triple_potential_count: usize,
        presignature_count: usize,
        presignature_mine_count: usize,
        presignature_potential_count: usize,
    },
    NotRunning,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(state): Extension<Arc<AxumState>>) -> Result<Json<StateView>> {
    tracing::debug!("fetching state");
    let protocol_state = state.protocol_state.read().await;
    match &*protocol_state {
        NodeState::Running(state) => {
            let triple_manager_read = state.triple_manager.read().await;
            let triple_potential_count = triple_manager_read.potential_len();
            let triple_count = triple_manager_read.len();
            let triple_mine_count = triple_manager_read.my_len();
            let presignature_read = state.presignature_manager.read().await;
            let presignature_count = presignature_read.len();
            let presignature_mine_count = presignature_read.my_len();
            let presignature_potential_count = presignature_read.potential_len();

            tracing::debug!("not running, state unavailable");
            Ok(Json(StateView::Running {
                participants: state.participants.keys().cloned().collect(),
                triple_count,
                triple_mine_count,
                triple_potential_count,
                presignature_count,
                presignature_mine_count,
                presignature_potential_count,
            }))
        }
        _ => {
            tracing::debug!("not running, state unavailable");
            Ok(Json(StateView::NotRunning))
        }
    }
}

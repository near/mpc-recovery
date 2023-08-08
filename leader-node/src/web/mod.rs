use self::error::MpcLeaderError;
use crate::client;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::WithRejection;
use k256::elliptic_curve::group::GroupEncoding;
use mpc_recovery_common::leader::{ConnectRequest, LeaderNodeState};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;

mod error;

#[derive(Clone)]
struct State {
    protocol_state: Arc<RwLock<LeaderNodeState>>,
}

pub async fn run(port: u16, threshold: usize) -> anyhow::Result<()> {
    tracing::debug!("running a leader node");
    // TODO: restore state from persistent storage
    let protocol_state = LeaderNodeState::default();
    let protocol_state = Arc::new(RwLock::new(protocol_state));
    let axum_state = State {
        protocol_state: protocol_state.clone(),
    };

    tokio::spawn(async move {
        tracing::info_span!("cron");
        let client = reqwest::Client::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tracing::info!("updating protocol state");
            let mut protocol_state_guard = protocol_state.write().await;
            let mut protocol_state = std::mem::take(&mut *protocol_state_guard);
            protocol_state = match protocol_state {
                LeaderNodeState::Discovering { joining } => {
                    if joining.len() >= threshold {
                        tracing::debug!("we have enough sign nodes, moving to key generation");
                        LeaderNodeState::Generating {
                            participants: joining,
                            threshold,
                        }
                    } else {
                        tracing::debug!("still discovering");
                        LeaderNodeState::Discovering { joining }
                    }
                }
                LeaderNodeState::Generating {
                    participants,
                    threshold,
                } => {
                    let mut responses = Vec::new();
                    for (_, url) in &participants {
                        match client::state(&client, url.clone()).await {
                            Ok(response) => {
                                tracing::info!("node {} is reachable", url);
                                responses.push(response);
                            }
                            Err(e) => {
                                tracing::warn!("node {} is not reachable: {}", url, e);
                            }
                        }
                    }
                    responses.dedup();
                    if responses.len() == 0 {
                        tracing::warn!("there are no reachable keygen participants");
                        LeaderNodeState::Generating {
                            participants,
                            threshold,
                        }
                    } else if responses.len() == 1 {
                        let consensus = responses.into_iter().next().unwrap();
                        tracing::debug!(?consensus, "keygen participants have a consensus");
                        match consensus.public_key {
                            Some(public_key) => {
                                tracing::info!(
                                    public_key = hex::encode(public_key.to_bytes()),
                                    "key generation has finished successfully"
                                );
                                LeaderNodeState::Running {
                                    participants: consensus.participants,
                                    public_key,
                                    threshold,
                                }
                            }
                            None => {
                                tracing::debug!("still generating");
                                LeaderNodeState::Generating {
                                    participants,
                                    threshold,
                                }
                            }
                        }
                    } else {
                        tracing::warn!("keygen participants have not reached a consensus yet");
                        LeaderNodeState::Generating {
                            participants,
                            threshold,
                        }
                    }
                }
                LeaderNodeState::Running { .. } => {
                    tracing::debug!("still running");
                    protocol_state
                }
                LeaderNodeState::Resharing {
                    old_participants,
                    new_participants,
                    public_key,
                    threshold,
                } => {
                    let mut responses = Vec::new();
                    for (_, url) in &new_participants {
                        match client::state(&client, url.clone()).await {
                            Ok(response) => {
                                tracing::info!("node {} is reachable", url);
                                responses.push(response);
                            }
                            Err(e) => {
                                tracing::warn!("node {} is not reachable: {}", url, e);
                            }
                        }
                    }
                    responses.dedup();
                    if responses.len() == 0 {
                        tracing::warn!("there are no reachable keyshare participants");
                        LeaderNodeState::Resharing {
                            old_participants,
                            new_participants,
                            public_key,
                            threshold,
                        }
                    } else if responses.len() == 1 {
                        let consensus = responses.into_iter().next().unwrap();
                        tracing::info!(?consensus, "keyshare participants have a consensus");
                        if consensus.participants == old_participants {
                            tracing::info!("keyshare has not been completed yet");
                            LeaderNodeState::Resharing {
                                old_participants,
                                new_participants,
                                public_key,
                                threshold,
                            }
                        } else if consensus.participants == new_participants {
                            tracing::info!("keyshare has been completed");
                            LeaderNodeState::Running {
                                participants: new_participants,
                                public_key,
                                threshold,
                            }
                        } else {
                            tracing::error!("unexpected consensus state");
                            LeaderNodeState::Resharing {
                                old_participants,
                                new_participants,
                                public_key,
                                threshold,
                            }
                        }
                    } else {
                        tracing::warn!("keyshare participants have not reached a consensus yet");
                        LeaderNodeState::Resharing {
                            old_participants,
                            new_participants,
                            public_key,
                            threshold,
                        }
                    }
                }
            };
            *protocol_state_guard = protocol_state;
        }
    });

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("leader node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/connect", post(connect))
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
async fn state(Extension(state): Extension<State>) -> (StatusCode, Json<LeaderNodeState>) {
    tracing::debug!("fetching state");
    let protocol_state = state.protocol_state.read().await;
    (StatusCode::OK, Json(protocol_state.clone()))
}

#[tracing::instrument(level = "debug", skip_all)]
async fn connect(
    Extension(state): Extension<State>,
    WithRejection(Json(request), _): WithRejection<Json<ConnectRequest>, MpcLeaderError>,
) -> (StatusCode, Json<LeaderNodeState>) {
    tracing::debug!(
        participant = ?request.participant,
        address = %request.address,
        "connecting"
    );
    let mut protocol_state_guard = state.protocol_state.write().await;
    let mut protocol_state = std::mem::take(&mut *protocol_state_guard);
    protocol_state = match protocol_state {
        LeaderNodeState::Discovering { mut joining } => {
            joining.insert(request.participant, request.address);
            LeaderNodeState::Discovering { joining }
        }
        LeaderNodeState::Running {
            participants,
            public_key,
            threshold,
        } => {
            if participants.contains_key(&request.participant) {
                LeaderNodeState::Running {
                    participants,
                    public_key,
                    threshold,
                }
            } else {
                let mut new_participants = participants.clone();
                new_participants.insert(request.participant, request.address);
                LeaderNodeState::Resharing {
                    old_participants: participants,
                    new_participants,
                    public_key,
                    threshold,
                }
            }
        }
        LeaderNodeState::Generating { .. } | LeaderNodeState::Resharing { .. } => protocol_state,
    };
    *protocol_state_guard = protocol_state.clone();
    (StatusCode::OK, Json(protocol_state))
}

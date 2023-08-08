use self::error::MpcLeaderError;
use crate::client;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::WithRejection;
use mpc_recovery_common::leader::{ConnectRequest, LeaderNodeState};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;

mod error;

#[derive(Clone)]
struct State {
    protocol_state: Arc<RwLock<LeaderNodeState>>,
}

pub async fn run(port: u16, threshold: usize) -> anyhow::Result<()> {
    tracing::debug!("running a leader node");
    let protocol_state = LeaderNodeState {
        participants: HashMap::new(),
        public_key: None,
        threshold,
        joining: HashMap::new(),
    };
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
            if protocol_state.participants.is_empty() {
                tracing::info!("there are no participants yet, trying joining nodes");
                if protocol_state.joining.is_empty() {
                    tracing::info!("no one is pending to join, skipping");
                } else {
                    let mut responses = Vec::new();
                    for (_, url) in &protocol_state.joining {
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
                        tracing::warn!("there are no reachable joining participants");
                    } else if responses.len() == 1 {
                        let consensus = responses.into_iter().next().unwrap();
                        tracing::info!(?consensus, "joining participants have a consensus");
                        let joining = protocol_state
                            .joining
                            .into_iter()
                            .filter(|(p, _)| !consensus.participants.contains_key(p))
                            .collect();
                        protocol_state = LeaderNodeState {
                            participants: consensus.participants,
                            public_key: consensus.public_key,
                            threshold: protocol_state.threshold,
                            joining,
                        };
                    } else {
                        tracing::warn!("joining participants have not reached a consensus yet");
                    }
                }
            } else {
                let mut responses = Vec::new();
                for (_, url) in &protocol_state.participants {
                    match client::state(&client, url.clone()).await {
                        Ok(response) => {
                            responses.push(response);
                        }
                        Err(e) => {
                            tracing::warn!("node {} is not reachable: {}", url, e);
                        }
                    }
                }
                responses.dedup();
                if responses.len() == 0 {
                    tracing::warn!("there are no reachable participants, waiting for them to come back up online");
                } else if responses.len() == 1 {
                    let consensus = responses.into_iter().next().unwrap();
                    tracing::info!(?consensus, "participants have a consensus");
                    let joining = protocol_state
                        .joining
                        .into_iter()
                        .filter(|(p, _)| !consensus.participants.contains_key(p))
                        .collect();
                    protocol_state = LeaderNodeState {
                        participants: consensus.participants,
                        public_key: consensus.public_key,
                        threshold: protocol_state.threshold,
                        joining,
                    };
                } else {
                    tracing::warn!("participants have not reached a consensus yet");
                }
            }
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
async fn connect(
    Extension(state): Extension<State>,
    WithRejection(Json(request), _): WithRejection<Json<ConnectRequest>, MpcLeaderError>,
) -> StatusCode {
    tracing::debug!(
        participant = ?request.participant,
        address = %request.address,
        "connecting"
    );
    let mut protocol_state = state.protocol_state.write().await;
    protocol_state
        .joining
        .insert(request.participant, request.address);
    StatusCode::OK
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(state): Extension<State>) -> (StatusCode, Json<LeaderNodeState>) {
    tracing::debug!("fetching state");
    let protocol_state = state.protocol_state.read().await;
    (StatusCode::OK, Json(protocol_state.clone()))
}

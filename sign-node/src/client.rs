use cait_sith::protocol::Participant;
use mpc_recovery_common::{
    leader::{ConnectRequest, LeaderNodeState},
    sign::MsgRequest,
};
use reqwest::{Client, IntoUrl};
use std::str::Utf8Error;
use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    Retry,
};

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("http request was unsuccessful: {0}")]
    Unsuccessful(String),
    #[error("http client error: {0}")]
    ReqwestClientError(reqwest::Error),
    #[error("http response could not be parsed: {0}")]
    ReqwestBodyError(reqwest::Error),
    #[error("http response body is not valid utf-8: {0}")]
    MalformedResponse(Utf8Error),
}

pub async fn message<U: IntoUrl>(
    client: &Client,
    url: U,
    from: Participant,
    msg: Vec<u8>,
) -> Result<(), SendError> {
    let mut url = url.into_url().unwrap();
    url.set_path("msg");
    let request = MsgRequest { from, msg };
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| SendError::ReqwestClientError(e))?;
        let status = response.status();
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| SendError::ReqwestBodyError(e))?;
        let response_str =
            std::str::from_utf8(&response_bytes).map_err(|e| SendError::MalformedResponse(e))?;
        if status.is_success() {
            Ok(())
        } else {
            tracing::error!(
                "failed to send a message to {} with code {}: {}",
                url,
                status,
                response_str
            );
            Err(SendError::Unsuccessful(response_str.into()))
        }
    };

    let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
    Retry::spawn(retry_strategy, action).await
}

pub async fn connect<U: IntoUrl>(
    client: &Client,
    url: U,
    me: Participant,
    my_address: U,
) -> Result<LeaderNodeState, SendError> {
    let mut url = url.into_url().unwrap();
    url.set_path("connect");
    let my_address = my_address.into_url().unwrap();
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&ConnectRequest {
                participant: me,
                address: my_address.clone(),
            })
            .send()
            .await
            .map_err(|e| SendError::ReqwestClientError(e))?;
        let status = response.status();
        if status.is_success() {
            let response = response
                .json()
                .await
                .map_err(|e| SendError::ReqwestBodyError(e))?;
            Ok(response)
        } else {
            let response_bytes = response
                .bytes()
                .await
                .map_err(|e| SendError::ReqwestBodyError(e))?;
            let response_str = std::str::from_utf8(&response_bytes)
                .map_err(|e| SendError::MalformedResponse(e))?;
            tracing::error!("failed to connect to {}: {}", url, response_str);
            Err(SendError::Unsuccessful(response_str.into()))
        }
    };

    let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
    Retry::spawn(retry_strategy, action).await
}

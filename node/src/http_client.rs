use crate::protocol::MpcMessage;
use crate::web::JoinRequest;
use cait_sith::protocol::Participant;
use near_primitives::types::AccountId;
use reqwest::{Client, IntoUrl};
use std::str::Utf8Error;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

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
    message: MpcMessage,
) -> Result<(), SendError> {
    let mut url = url.into_url().unwrap();
    url.set_path("msg");
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&message)
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

pub async fn join<U: IntoUrl>(
    client: &Client,
    url: U,
    me: Participant,
    my_account: &AccountId,
    my_address: U,
) -> Result<(), SendError> {
    let mut url = url.into_url().unwrap();
    url.set_path("connect");
    let my_address = my_address.into_url().unwrap();
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&JoinRequest {
                id: me,
                account_id: my_account.clone(),
                url: my_address.clone(),
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

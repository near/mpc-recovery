use crate::protocol::MpcMessage;
use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use reqwest::{Client, IntoUrl};
use std::str::Utf8Error;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("http request was unsuccessful: {0}")]
    Unsuccessful(String),
    #[error("serialization unsuccessful: {0}")]
    DataConversionError(serde_json::Error),
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
            .map_err(SendError::ReqwestClientError)?;
        let status = response.status();
        let response_bytes = response
            .bytes()
            .await
            .map_err(SendError::ReqwestBodyError)?;
        let response_str =
            std::str::from_utf8(&response_bytes).map_err(SendError::MalformedResponse)?;
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

pub async fn message_encrypted<U: IntoUrl>(
    cipher_pk: &hpke::PublicKey,
    client: &Client,
    url: U,
    message: MpcMessage,
) -> Result<(), SendError> {
    let message = serde_json::to_vec(&message).map_err(SendError::DataConversionError)?;
    let message = cipher_pk.encrypt(&message, b"");

    let mut url = url.into_url().unwrap();
    url.set_path("msg-encrypted");
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&message)
            .send()
            .await
            .map_err(SendError::ReqwestClientError)?;
        let status = response.status();
        let response_bytes = response
            .bytes()
            .await
            .map_err(SendError::ReqwestBodyError)?;
        let response_str =
            std::str::from_utf8(&response_bytes).map_err(SendError::MalformedResponse)?;
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
    participant: &Participant,
) -> Result<(), SendError> {
    let mut url = url.into_url().unwrap();
    url.set_path("join");
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&participant)
            .send()
            .await
            .map_err(SendError::ReqwestClientError)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let response_bytes = response
                .bytes()
                .await
                .map_err(SendError::ReqwestBodyError)?;
            let response_str =
                std::str::from_utf8(&response_bytes).map_err(SendError::MalformedResponse)?;
            tracing::error!("failed to connect to {}: {}", url, response_str);
            Err(SendError::Unsuccessful(response_str.into()))
        }
    };

    let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
    Retry::spawn(retry_strategy, action).await
}

use mpc_recovery_common::sign::SignNodeState;
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

pub async fn state<U: IntoUrl>(client: &Client, url: U) -> Result<SignNodeState, SendError> {
    let mut url = url.into_url().unwrap();
    url.set_path("state");
    let action = || async {
        let response = client
            .post(url.clone())
            .send()
            .await
            .map_err(|e| SendError::ReqwestClientError(e))?;
        let status = response.status();
        if status.is_success() {
            let response: SignNodeState = response
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
            tracing::error!("failed to get state from {}: {}", url, response_str);
            Err(SendError::Unsuccessful(response_str.into()))
        }
    };

    let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
    Retry::spawn(retry_strategy, action).await
}

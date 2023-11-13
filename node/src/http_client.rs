use crate::protocol::message::EncryptedMessage;
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
    participant: Participant,
    cipher_pk: &hpke::PublicKey,
    sign_sk: &near_crypto::SecretKey,
    client: &Client,
    url: U,
    message: MpcMessage,
) -> Result<(), SendError> {
    let message = serde_json::to_vec(&message).map_err(SendError::DataConversionError)?;
    let sig = sign_sk.sign(&message);
    let cipher = cipher_pk.encrypt(&message, b"");
    tracing::debug!(?participant, ciphertext = ?cipher.text, "sending encrypted");
    let message = EncryptedMessage {
        cipher,
        sig,
        from: participant,
    };

    let mut url = url.into_url().unwrap();
    url.set_path("msg-private");
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

#[cfg(test)]
mod tests {
    use crate::protocol::message::GeneratingMessage;
    use crate::protocol::MpcMessage;

    #[test]
    fn test_sending_encrypted_message() {
        let associated_data = b"";
        let (sk, pk) = mpc_keys::hpke::generate();
        let starting_message = MpcMessage::Generating(GeneratingMessage {
            from: cait_sith::protocol::Participant::from(0),
            data: vec![],
        });

        let message = serde_json::to_vec(&starting_message).unwrap();
        let message = pk.encrypt(&message, associated_data);

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = sk.decrypt(&cipher, associated_data);
        let message: MpcMessage = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }
}

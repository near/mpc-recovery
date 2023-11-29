use crate::protocol::message::SignedMessage;
use crate::protocol::MpcMessage;
use crate::protocol::ParticipantInfo;
use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use reqwest::{Client, IntoUrl};
use std::collections::VecDeque;
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
    #[error("encryption error: {0}")]
    EncryptionError(String),
}

async fn send_encrypted<U: IntoUrl>(
    from: Participant,
    cipher_pk: &hpke::PublicKey,
    sign_sk: &near_crypto::SecretKey,
    client: &Client,
    url: U,
    message: &MpcMessage,
) -> Result<(), SendError> {
    let encrypted = SignedMessage::encrypt(message, from, sign_sk, cipher_pk)
        .map_err(|err| SendError::EncryptionError(err.to_string()))?;
    tracing::debug!(?from, ciphertext = ?encrypted.text, "sending encrypted");

    let _span = tracing::info_span!("message_request");
    let mut url = url.into_url().unwrap();
    url.set_path("msg");
    tracing::debug!(%url, "making http request");
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&encrypted)
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

pub async fn join<U: IntoUrl>(client: &Client, url: U, me: &Participant) -> Result<(), SendError> {
    let _span = tracing::info_span!("join_request", ?me);
    let mut url = url.into_url().unwrap();
    url.set_path("join");
    tracing::debug!(%url, "making http request");
    let action = || async {
        let response = client
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&me)
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

// TODO: add in retry logic either in struct or at call site.
// TODO: add check for participant list to see if the messages to be sent are still valid.
#[derive(Default)]
pub struct MessageQueue {
    deque: VecDeque<(ParticipantInfo, MpcMessage)>,
}

impl MessageQueue {
    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn push(&mut self, info: ParticipantInfo, msg: MpcMessage) {
        self.deque.push_back((info, msg));
    }

    pub async fn send_encrypted(
        &mut self,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        client: &Client,
    ) -> Result<(), SendError> {
        while let Some((info, msg)) = self.deque.front() {
            let result =
                send_encrypted(from, &info.cipher_pk, sign_sk, client, &info.url, msg).await;

            match result {
                Ok(()) => {
                    let _ = self.deque.pop_front();
                }
                Err(err) => {
                    tracing::warn!(?err, "failed to send encrypted message");
                    return Err(err);
                }
            }
        }

        Ok(())
    }
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
        let message = pk.encrypt(&message, associated_data).unwrap();

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = sk.decrypt(&cipher, associated_data).unwrap();
        let message: MpcMessage = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }
}

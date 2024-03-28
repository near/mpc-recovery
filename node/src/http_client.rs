use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
use crate::protocol::message::SignedMessage;
use crate::protocol::MpcMessage;
use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use reqwest::{Client, IntoUrl};
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::Utf8Error;
use std::time::{Duration, Instant};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

// 5 minutes max to wait for this message to be sent by defaults
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("http request was unsuccessful: {0}")]
    Unsuccessful(String),
    #[error("serialization unsuccessful: {0}")]
    DataConversionError(serde_json::Error),
    #[error("http client error: {0}")]
    ReqwestClientError(#[from] reqwest::Error),
    #[error("http response could not be parsed: {0}")]
    ReqwestBodyError(reqwest::Error),
    #[error("http response body is not valid utf-8: {0}")]
    MalformedResponse(Utf8Error),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("http request timeout: {0}")]
    Timeout(String),
    #[error("participant is not alive: {0}")]
    ParticipantNotAlive(String),
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

    let _span = tracing::info_span!("message_request");
    let mut url = url.into_url()?;
    url.set_path("msg");
    tracing::debug!(?from, to = %url, "making http request: sending encrypted message");
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

// TODO: add in retry logic either in struct or at call site.
// TODO: add check for participant list to see if the messages to be sent are still valid.
#[derive(Default)]
pub struct MessageQueue {
    deque: VecDeque<(ParticipantInfo, MpcMessage, Instant)>,
    seen_counts: HashSet<String>,
}

impl MessageQueue {
    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn push(&mut self, info: ParticipantInfo, msg: MpcMessage) {
        self.deque.push_back((info, msg, Instant::now()));
    }

    pub async fn send_encrypted(
        &mut self,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        client: &Client,
        participants: &Participants,
    ) -> Vec<SendError> {
        let mut failed = VecDeque::new();
        let mut errors = Vec::new();
        let mut participant_counter = HashMap::new();
        while let Some((info, msg, instant)) = self.deque.pop_front() {
            let account_id = info.account_id.clone();
            if !participants.contains_key(&Participant::from(info.id)) {
                if instant.elapsed() > message_type_to_timeout(&msg) {
                    errors.push(SendError::Timeout(format!(
                        "message has timed out on offline node: {info:?}",
                    )));
                    continue;
                }
                let counter = participant_counter.entry(info.id).or_insert(0);
                *counter += 1;
                failed.push_back((info, msg, instant));
                continue;
            }

            let start = Instant::now();
            crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                .with_label_values(&[&account_id.as_ref()])
                .inc();
            if let Err(err) =
                send_encrypted(from, &info.cipher_pk, sign_sk, client, &info.url, &msg).await
            {
                crate::metrics::NUM_SEND_ENCRYPTED_FAILURE
                    .with_label_values(&[&account_id.as_ref()])
                    .inc();
                crate::metrics::FAILED_SEND_ENCRYPTED_LATENCY
                    .with_label_values(&[&account_id.as_ref()])
                    .observe(start.elapsed().as_millis() as f64);
                if instant.elapsed() > message_type_to_timeout(&msg) {
                    errors.push(SendError::Timeout(format!(
                        "message has timed out: {err:?}"
                    )));
                    continue;
                }

                failed.push_back((info, msg, instant));
                errors.push(err);
            } else {
                crate::metrics::SEND_ENCRYPTED_LATENCY
                .with_label_values(&[&account_id.as_ref()])
                .observe(start.elapsed().as_millis() as f64);
            }
        }
        // only add the participant count if it hasn't been seen before.
        let counts = format!("{participant_counter:?}");
        if !participant_counter.is_empty() && self.seen_counts.insert(counts.clone()) {
            errors.push(SendError::ParticipantNotAlive(format!(
                "participants not responding: {counts:?}",
            )));
        }

        // Add back the failed attempts for next time.
        self.deque = failed;
        errors
    }
}

fn message_type_to_timeout(msg: &MpcMessage) -> Duration {
    match msg {
        MpcMessage::Generating(_) => MESSAGE_TIMEOUT,
        MpcMessage::Resharing(_) => MESSAGE_TIMEOUT,
        MpcMessage::Triple(_) => crate::util::get_triple_timeout(),
        MpcMessage::Presignature(_) => crate::types::PROTOCOL_PRESIG_TIMEOUT,
        MpcMessage::Signature(_) => crate::types::PROTOCOL_SIGNATURE_TIMEOUT,
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

use hyper::StatusCode;
use near_crypto::PublicKey;
use near_primitives::types::AccountId;

#[derive(thiserror::Error, Debug)]
pub enum RelayerError {
    #[error("unknown account `{0}`")]
    UnknownAccount(AccountId),
    #[error("unknown key `{0}`")]
    UnknownAccessKey(PublicKey),
    #[error(transparent)]
    DataConversionFailure(anyhow::Error),
    #[error(transparent)]
    NetworkFailure(anyhow::Error),
    #[error("{1}")]
    RequestFailure(StatusCode, String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

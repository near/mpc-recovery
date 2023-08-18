use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::Response;
use curv::elliptic::curves::{Ed25519, Point};
use curv::BigInt;
use near_crypto::{ParseKeyError, PublicKey};
use near_primitives::account::id::ParseAccountError;

use crate::relayer::error::RelayerError;
use crate::sign_node::oidc::OidcDigest;

// TODO: maybe want to flatten out the error types to be ErrorCode + ErrorData
/// This enum error type serves as one true source of all errors in mpc-recovery
/// crate. It is used to unify all errors that can happen in the application.
#[derive(Debug, thiserror::Error)]
pub enum MpcError {
    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),
    #[error(transparent)]
    SignNodeRejection(#[from] SignNodeError),
    #[error(transparent)]
    LeaderNodeRejection(#[from] LeaderNodeError),
}

impl MpcError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::JsonExtractorRejection(json_rejection) => json_rejection.status(),
            Self::LeaderNodeRejection(error) => error.code(),
            Self::SignNodeRejection(error) => error.code(),
        }
    }
}

// We implement `IntoResponse` so MpcError can be used as a response
impl axum::response::IntoResponse for MpcError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
            Self::LeaderNodeRejection(error) => (error.code(), error.to_string()),
            Self::SignNodeRejection(error) => (error.code(), error.to_string()),
        };

        (status, axum::Json(message)).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LeaderNodeError {
    #[error("client error: {0}")]
    ClientError(String, StatusCode),
    #[error("server error: {0}")]
    ServerError(String),
    #[error("{0}")]
    DataConversionFailure(anyhow::Error),
    #[error("aggregate signing failed: {0}")]
    AggregateSigningFailed(#[from] AggregateSigningError),
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("relayer error: {0}")]
    RelayerError(#[from] RelayerError),
    #[error("recovery key can not be deleted: {0}")]
    RecoveryKeyCanNotBeDeleted(PublicKey),
    #[error("failed to retrieve recovery pk, check digest signature: {0}")]
    FailedToRetrieveRecoveryPk(anyhow::Error),
    #[error("timeout gathering sign node pks")]
    TimeoutGatheringPublicKeys,
    #[error("network error: {0}")]
    NetworkRejection(#[from] reqwest::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl LeaderNodeError {
    pub fn code(&self) -> StatusCode {
        match self {
            LeaderNodeError::ClientError(_, code) => *code,
            LeaderNodeError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LeaderNodeError::DataConversionFailure(_) => StatusCode::BAD_REQUEST,
            LeaderNodeError::AggregateSigningFailed(err) => err.code(),
            LeaderNodeError::SignatureVerificationFailed(_) => StatusCode::BAD_REQUEST,
            LeaderNodeError::OidcVerificationFailed(_) => StatusCode::BAD_REQUEST,
            LeaderNodeError::MalformedAccountId(_, _) => StatusCode::BAD_REQUEST,
            LeaderNodeError::RelayerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LeaderNodeError::TimeoutGatheringPublicKeys => StatusCode::INTERNAL_SERVER_ERROR,
            LeaderNodeError::RecoveryKeyCanNotBeDeleted(_) => StatusCode::BAD_REQUEST,
            LeaderNodeError::FailedToRetrieveRecoveryPk(_) => StatusCode::UNAUTHORIZED,
            LeaderNodeError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LeaderNodeError::NetworkRejection(err) => {
                err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignNodeError {
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(String, ParseKeyError),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("oidc token {0:?} already claimed with another key")]
    OidcTokenAlreadyClaimed(OidcDigest),
    #[error("oidc token {0:?} was claimed with another key")]
    OidcTokenClaimedWithAnotherKey(OidcDigest),
    #[error("oidc token {0:?} was not claimed")]
    OidcTokenNotClaimed(OidcDigest),
    #[error("aggregate signing failed: {0}")]
    AggregateSigningFailed(#[from] AggregateSigningError),
    #[error("This kind of action can not be performed")]
    UnsupportedAction,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl SignNodeError {
    pub fn code(&self) -> StatusCode {
        match self {
            // TODO: this case was not speicifically handled before. Check if it is the right code
            Self::MalformedAccountId(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MalformedPublicKey(_, _) => StatusCode::BAD_REQUEST,
            Self::SignatureVerificationFailed(_) => StatusCode::BAD_REQUEST,
            Self::OidcVerificationFailed(_) => StatusCode::BAD_REQUEST,
            Self::OidcTokenAlreadyClaimed(_) => StatusCode::UNAUTHORIZED,
            Self::OidcTokenClaimedWithAnotherKey(_) => StatusCode::UNAUTHORIZED,
            Self::OidcTokenNotClaimed(_) => StatusCode::UNAUTHORIZED,
            Self::AggregateSigningFailed(err) => err.code(),
            Self::UnsupportedAction => StatusCode::BAD_REQUEST,
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AggregateSigningError {
    #[error("invalid number of commitments: trying to fetch id={0} in {1} commitments")]
    InvalidCommitmentNumbers(usize, usize),
    #[error("invalid number of reveals: trying to fetch id={0} in {1} reveals")]
    InvalidRevealNumbers(usize, usize),
    #[error("commitment not found: {0}")]
    CommitmentNotFound(String),
    #[error("reveal not found: {0}")]
    RevealNotFound(String),
    #[error("in a commitment r={0:?}, blind={1}; expected {2} but found {3}")]
    InvalidCommitment(Point<Ed25519>, BigInt, BigInt, BigInt),
    #[error("no node public keys available to sign")]
    NodeKeysUnavailable,
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("{0}")]
    DataConversionFailure(anyhow::Error),
}

impl AggregateSigningError {
    pub fn code(&self) -> StatusCode {
        match self {
            Self::InvalidCommitmentNumbers(_, _) => StatusCode::BAD_REQUEST,
            Self::InvalidRevealNumbers(_, _) => StatusCode::BAD_REQUEST,
            Self::CommitmentNotFound(_) => StatusCode::BAD_REQUEST,
            Self::RevealNotFound(_) => StatusCode::BAD_REQUEST,
            Self::InvalidCommitment(_, _, _, _) => StatusCode::BAD_REQUEST,
            Self::NodeKeysUnavailable => StatusCode::BAD_REQUEST,
            Self::SignatureVerificationFailed(_) => StatusCode::BAD_REQUEST,
            Self::DataConversionFailure(_) => StatusCode::BAD_REQUEST,
        }
    }
}

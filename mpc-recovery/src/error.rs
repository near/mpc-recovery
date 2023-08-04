use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use near_crypto::ParseKeyError;
use near_primitives::account::id::ParseAccountError;

use crate::key_recovery::NodeRecoveryError;
use crate::sign_node::oidc::OidcDigest;

/// This enum error type serves as one true source of all futures in mpc-recovery
/// crate. It is used to unify all errors that can happen in the application.
#[derive(Debug, thiserror::Error)]
pub enum MpcError {
    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),
}

// We implement `IntoResponse` so ApiError can be used as a response
impl axum::response::IntoResponse for MpcError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            Self::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
        };

        (status, axum::Json(message)).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UserCredentialsError {
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("failed to fetch recovery key: {0}")]
    RecoveryKeyError(#[from] NodeRecoveryError),
}

#[derive(Debug, thiserror::Error)]
pub enum CommitRequestError {
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
    #[error("This kind of action can not be performed")]
    UnsupportedAction,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl CommitRequestError {
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
            Self::UnsupportedAction => StatusCode::BAD_REQUEST,
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyRequestError {
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(near_crypto::PublicKey, ParseKeyError),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("oidc token {0:?} was not claimed")]
    OidcTokenNotClaimed(OidcDigest),
    #[error("oidc token {0:?} was claimed with another key")]
    OidcTokenClaimedWithAnotherKey(OidcDigest),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl PublicKeyRequestError {
    pub fn code(&self) -> StatusCode {
        match self {
            Self::MalformedPublicKey(_, _) => StatusCode::BAD_REQUEST,
            Self::SignatureVerificationFailed(_) => StatusCode::BAD_REQUEST,
            Self::OidcVerificationFailed(_) => StatusCode::BAD_REQUEST,
            Self::OidcTokenNotClaimed(_) => StatusCode::UNAUTHORIZED,
            Self::OidcTokenClaimedWithAnotherKey(_) => StatusCode::UNAUTHORIZED,
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

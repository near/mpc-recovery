use axum::extract::rejection::JsonRejection;
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
            MpcError::JsonExtractorRejection(json_rejection) => {
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
pub enum CommitError {
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(String, ParseKeyError),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
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

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyRequestError {
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(near_crypto::PublicKey, ParseKeyError),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("oidc token {0:?} was not claimed")]
    OidcTokenNotClaimed(OidcDigest),
    #[error("oidc token {0:?} was claimed with another key")]
    OidcTokenClaimedWithAnotherKey(OidcDigest),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

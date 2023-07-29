use axum::extract::rejection::JsonRejection;

/// This enum error type serves as one true source of all futures in mpc-recovery
/// crate. It is used to unify all errors that can happen in the application.
#[derive(Debug, thiserror::Error)]
pub enum MpcError {
    // The `#[from]` attribute generates `From<JsonRejection> for MpcError`
    // implementation. See `thiserror` docs for more information
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

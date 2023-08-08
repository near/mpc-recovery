use axum::extract::rejection::JsonRejection;

/// This enum error type serves as one true source of all futures in leader-node
/// crate. It is used to unify all errors that can happen in the application.
#[derive(Debug, thiserror::Error)]
pub enum MpcLeaderError {
    // The `#[from]` attribute generates `From<JsonRejection> for MpcError`
    // implementation. See `thiserror` docs for more information
    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),
}

// We implement `IntoResponse` so MpcLeaderError can be used as a response
impl axum::response::IntoResponse for MpcLeaderError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            MpcLeaderError::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
        };

        (status, axum::Json(message)).into_response()
    }
}

use axum::extract::rejection::JsonRejection;

/// This enum error type serves as one true source of all futures in sign-node
/// crate. It is used to unify all errors that can happen in the application.
#[derive(Debug, thiserror::Error)]
pub enum MpcSignError {
    // The `#[from]` attribute generates `From<JsonRejection> for MpcError`
    // implementation. See `thiserror` docs for more information
    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),
}

// We implement `IntoResponse` so MpcSignError can be used as a response
impl axum::response::IntoResponse for MpcSignError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            MpcSignError::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
        };

        (status, axum::Json(message)).into_response()
    }
}

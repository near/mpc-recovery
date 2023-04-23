#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("expected property `{0}` was missing")]
    MissingProperty(String),
    #[error("expected property type `{expected}`, got `{got}`")]
    UnexpectedPropertyType { expected: String, got: String },
}

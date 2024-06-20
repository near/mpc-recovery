#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("expected property `{0}` was missing")]
    MissingProperty(String),
    #[error("expected property type `{expected}`, got `{got}`")]
    UnexpectedPropertyType { expected: String, got: String },
    #[error("property `{0}` is malfored")]
    MalformedProperty(String),
    #[error("parsing integar from string erred out: `{0}`")]
    ParseInt(String),
}

#[derive(thiserror::Error, Debug)]
pub enum SecretStorageError {
    #[error("GCP error: {0}")]
    GcpError(#[from] google_secretmanager1::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum DatastoreStorageError {
    #[error("GCP error: {0}")]
    GcpError(#[from] google_datastore1::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("datastore value conversion error: {0}")]
    ConvertError(ConvertError),
    #[error("fetch_entities error: `{0}`")]
    FetchEntitiesError(String),
    #[error("could not find entity: {0}")]
    EntityNotFound(String),
}

impl From<ConvertError> for DatastoreStorageError {
    fn from(err: ConvertError) -> Self {
        DatastoreStorageError::ConvertError(err)
    }
}

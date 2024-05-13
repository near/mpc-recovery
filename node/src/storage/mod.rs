pub mod secret_storage;
pub mod triple_storage;

/// Configures storage.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "storage_options")]
pub struct Options {
    /// env used to suffix datastore table names to differentiate among environments.
    #[clap(long, env("MPC_RECOVERY_ENV"))]
    pub env: String,
    /// GCP project ID.
    #[clap(long, env("MPC_RECOVERY_GCP_PROJECT_ID"))]
    pub gcp_project_id: String,
    /// GCP Secret Manager ID that will be used to load/store the node's secret key share.
    #[clap(long, env("MPC_RECOVERY_SK_SHARE_SECRET_ID"), requires_all=["gcp_project_id"])]
    pub sk_share_secret_id: Option<String>,
    /// Mostly for integration tests.
    /// GCP Datastore URL that will be used to load/store the node's triples and presignatures.
    #[arg(long, env("MPC_RECOVERY_GCP_DATASTORE_URL"))]
    pub gcp_datastore_url: Option<String>,
    #[arg(long, env("MPC_RECOVERY_SK_SHARE_LOCAL_PATH"))]
    pub sk_share_local_path: Option<String>,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = vec![
            "--env".to_string(),
            self.env,
            "--gcp-project-id".to_string(),
            self.gcp_project_id,
        ];
        if let Some(sk_share_secret_id) = self.sk_share_secret_id {
            opts.extend(vec!["--sk-share-secret-id".to_string(), sk_share_secret_id]);
        }
        if let Some(gcp_datastore_url) = self.gcp_datastore_url {
            opts.extend(vec!["--gcp-datastore-url".to_string(), gcp_datastore_url]);
        }
        if let Some(sk_share_local_path) = self.sk_share_local_path {
            opts.extend(vec![
                "--sk-share-local-path".to_string(),
                sk_share_local_path,
            ]);
        }

        opts
    }
}

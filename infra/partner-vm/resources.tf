terraform {
  backend "gcs" {
    bucket = "<your-tf-state-gcs-bucket>" # Example: terraform-multichain-state-bucket
    prefix = "<your-multichain-prefix>" # Example: state/multichain-vm
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

# These data blocks grab the values from your GCP secret manager, please adjust secret names as desired
data "google_secret_manager_secret_version" "account_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = "multichain-account-sk-dev-${count.index}"
  project = var.project_id
}

data "google_secret_manager_secret_version" "cipher_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = "multichain-cipher-sk-dev-${count.index}"
  project = var.project_id
}

data "google_secret_manager_secret_version" "sk_share_secret_id" {
  count   = length(var.node_configs)
  secret  = "multichain-sk-share-dev-${count.index}"
  project = var.project_id
}

# This is the AWS access key and secret key for our public S3 bucket with Lake data
data "google_secret_manager_secret_version" "aws_access_key_secret_id" {
  secret = "multichain-indexer-aws-access-key"
}

data "google_secret_manager_secret_version" "aws_secret_key_secret_id" {
  secret = "multichain-indexer-aws-secret-key"
}

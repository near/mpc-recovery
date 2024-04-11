terraform {
  backend "gcs" {
    bucket = "multichain-terraform-dev"
    prefix = "state/multichain-vm-test"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

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

data "google_secret_manager_secret_version" "sign_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = "multichain-sign-sk-dev-${count.index}"
  project = var.project_id
}

data "google_secret_manager_secret_version" "sk_share_secret_id" {
  count   = length(var.node_configs)
  secret  = "multichain-sk-share-dev-${count.index}"
  project = var.project_id
}

data "google_secret_manager_secret_version" "aws_access_key_secret_id" {
  secret = "multichain-indexer-aws-access-key"
}

data "google_secret_manager_secret_version" "aws_secret_key_secret_id" {
  secret = "multichain-indexer-aws-secret-key"
}

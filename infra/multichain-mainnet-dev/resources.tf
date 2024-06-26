terraform {
  backend "gcs" {
    bucket = "multichain-terraform-dev"
    prefix = "state/multichain-vm-test-mainnet"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

locals {
  instance_ip_map = {
    for idx, instance in module.instances : instance["hostname"] => google_compute_global_address.external_ips[idx].address
  }
}

# These data blocks grab the values from your GCP secret manager, please adjust secret names as desired
data "google_secret_manager_secret_version" "account_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].account_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "cipher_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].cipher_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sign_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sign_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sk_share_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sk_share_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "aws_access_key_secret_id" {
  secret = "multichain-indexer-aws-access-key"
}

data "google_secret_manager_secret_version" "aws_secret_key_secret_id" {
  secret = "multichain-indexer-aws-secret-key"
}

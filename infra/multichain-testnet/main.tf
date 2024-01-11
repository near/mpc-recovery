terraform {
  backend "gcs" {
    bucket = "multichain-terraform-prod"
    prefix = "state/multichain"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

locals {
  credentials  = var.credentials != null ? var.credentials : file(var.credentials_file)
  client_email = jsondecode(local.credentials).client_email
  client_id    = jsondecode(local.credentials).client_id

  workspace = {
    near_rpc = "https://rpc.testnet.near.org"
  }
}

data "external" "git_checkout" {
  program = ["${path.module}/../scripts/get_sha.sh"]
}

provider "google" {
  credentials = local.credentials

  project = var.project
  region  = var.region
  zone    = var.zone
}

/*
 * Create brand new service account with basic IAM
 */
resource "google_service_account" "service_account" {
  account_id   = "multichain-${var.env}"
  display_name = "Multichain ${var.env} Account"
}

resource "google_service_account_iam_binding" "serivce-account-iam" {
  service_account_id = google_service_account.service_account.name
  role               = "roles/iam.serviceAccountUser"

  members = [
    "serviceAccount:${local.client_email}",
  ]
}

/*
 * Ensure service account has access to Secret Manager variables
 */
resource "google_secret_manager_secret_iam_member" "account_sk_secret_access" {
  count = length(var.node_configs)

  secret_id = var.node_configs[count.index].account_sk_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "cipher_sk_secret_access" {
  count = length(var.node_configs)

  secret_id = var.node_configs[count.index].cipher_sk_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "aws_access_key_secret_access" {
  secret_id = var.aws_access_key_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "aws_secret_key_secret_access" {
  secret_id = var.aws_secret_key_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "sk_share_secret_access" {
  count = length(var.node_configs)

  secret_id = var.node_configs[count.index].sk_share_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "sk_share_secret_manager" {
  count = length(var.node_configs)

  secret_id = var.node_configs[count.index].sk_share_secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

module "node" {
  count  = length(var.node_configs)
  source = "../modules/multichain"

  service_name          = "multichain-${var.env}-${count.index}"
  project               = var.project
  region                = var.region
  service_account_email = google_service_account.service_account.email
  docker_image          = var.docker_image

  node_id         = count.index
  near_rpc        = local.workspace.near_rpc
  mpc_contract_id = var.mpc_contract_id
  account         = var.node_configs[count.index].account
  cipher_pk       = var.node_configs[count.index].cipher_pk
  indexer_options = var.indexer_options
  my_address      = var.node_configs[count.index].address

  account_sk_secret_id     = var.node_configs[count.index].account_sk_secret_id
  cipher_sk_secret_id      = var.node_configs[count.index].cipher_sk_secret_id
  aws_access_key_secret_id = var.aws_access_key_secret_id
  aws_secret_key_secret_id = var.aws_secret_key_secret_id
  sk_share_secret_id       = var.node_configs[count.index].sk_share_secret_id

  depends_on = [
    google_secret_manager_secret_iam_member.account_sk_secret_access,
    google_secret_manager_secret_iam_member.cipher_sk_secret_access,
    google_secret_manager_secret_iam_member.aws_access_key_secret_access,
    google_secret_manager_secret_iam_member.aws_secret_key_secret_access,
    google_secret_manager_secret_iam_member.sk_share_secret_access,
    google_secret_manager_secret_iam_member.sk_share_secret_manager
  ]
}

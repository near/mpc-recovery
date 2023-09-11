terraform {
  backend "gcs" {
    prefix = "state/mpc-recovery"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
    }
  }
}

locals {
  credentials  = var.credentials != null ? var.credentials : file(var.credentials_file)
  client_email = jsondecode(local.credentials).client_email
  client_id    = jsondecode(local.credentials).client_id

  env = {
    defaults = {
      near_rpc          = "https://rpc.testnet.near.org"
      near_root_account = "testnet"
    }
    testnet = {
    }
    mainnet = {
      near_rpc = "https://rpc.mainnet.near.org"
      near_root_account = "near"
    }
  }

  workspace = merge(local.env["defaults"], contains(keys(local.env), terraform.workspace) ? local.env[terraform.workspace] : local.env["defaults"])
}

data "external" "git_checkout" {
  program = ["${path.module}/scripts/get_sha.sh"]
}

provider "google" {
  credentials = local.credentials

  project = var.project
  region  = var.region
  zone    = var.zone
}

provider "docker" {
  registry_auth {
    address  = "${var.region}-docker.pkg.dev"
    username = "_json_key"
    password = local.credentials
  }
}

resource "google_service_account" "service_account" {
  account_id   = "mpc-recovery-${var.env}"
  display_name = "MPC Recovery ${var.env} Account"
}

resource "google_service_account_iam_binding" "serivce-account-iam" {
  service_account_id = google_service_account.service_account.name
  role               = "roles/iam.serviceAccountUser"

  members = [
    "serviceAccount:${local.client_email}",
  ]
}

resource "google_project_iam_member" "service-account-datastore-user" {
  project = var.project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_artifact_registry_repository" "mpc_recovery" {
  repository_id = "mpc-recovery-${var.env}"
  format        = "DOCKER"
}

resource "docker_registry_image" "mpc_recovery" {
  name          = docker_image.mpc_recovery.name
  keep_remotely = true
}

resource "docker_image" "mpc_recovery" {
  name = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.mpc_recovery.name}/mpc-recovery-${var.env}:${data.external.git_checkout.result.sha}"
  build {
    context = "${path.cwd}/.."
  }
}

module "signer" {
  count  = length(var.cipher_keys)
  source = "./modules/signer"

  env                   = var.env
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = docker_image.mpc_recovery.name

  node_id                = count.index
  allowed_oidc_providers = var.allowed_oidc_providers

  cipher_key = var.cipher_keys[count.index]
  sk_share   = var.sk_shares[count.index]

  depends_on = [docker_registry_image.mpc_recovery]
}

module "leader" {
  source = "./modules/leader"

  env                   = var.env
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = docker_image.mpc_recovery.name

  signer_node_urls       = concat(module.signer.*.node.uri, var.external_signer_node_urls)
  near_rpc               = local.workspace.near_rpc
  near_root_account      = local.workspace.near_root_account
  account_creator_id     = var.account_creator_id
  allowed_oidc_providers = var.allowed_oidc_providers

  account_creator_sk = var.account_creator_sk

  depends_on = [docker_registry_image.mpc_recovery, module.signer]
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.66.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
    }
  }
}

locals {
  credentials  = file(var.credentials_file)
  client_email = jsondecode(local.credentials).client_email
  client_id    = jsondecode(local.credentials).client_id
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

resource "google_project_iam_binding" "service-account-datastore-user" {
  project = var.project
  role    = "roles/datastore.user"

  members = [
    "serviceAccount:${google_service_account.service_account.email}",
  ]
}

resource "google_artifact_registry_repository" "mpc_recovery" {
  repository_id = "mpc-recovery-signer-${var.env}"
  format        = "DOCKER"
}

resource "docker_registry_image" "mpc_recovery" {
  name          = docker_tag.mpc_recovery.target_image
  keep_remotely = true
}

resource "docker_tag" "mpc_recovery" {
  source_image = var.docker_image
  target_image = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.mpc_recovery.name}/mpc-recovery-${var.env}"
}

# resource "docker_image" "mpc_recovery" {
#   name = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.mpc_recovery.name}/mpc-recovery-${var.env}"
#   build {
#     context = "${path.cwd}/.."
#   }
# }

module "signer" {
  source = "../modules/signer"

  env                   = var.env
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = docker_tag.mpc_recovery.target_image

  node_id              = var.node_id
  firebase_audience_id = var.firebase_audience_id

  cipher_key = var.cipher_key
  sk_share   = var.sk_share

  depends_on = [docker_registry_image.mpc_recovery]
}

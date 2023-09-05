resource "google_secret_manager_secret" "cipher_key" {
  secret_id = "mpc-recovery-encryption-cipher-${var.node_id}-${var.env}"
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "cipher_key_data" {
  secret      = google_secret_manager_secret.cipher_key.name
  secret_data = var.cipher_key
}

resource "google_secret_manager_secret_iam_member" "cipher_key_secret_access" {
  secret_id = google_secret_manager_secret.cipher_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
}

resource "google_secret_manager_secret" "secret_share" {
  secret_id = "mpc-recovery-secret-share-${var.node_id}-${var.env}"
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "secret_share_data" {
  secret      = google_secret_manager_secret.secret_share.name
  secret_data = var.sk_share
}

resource "google_secret_manager_secret_iam_member" "secret_share_secret_access" {
  secret_id = google_secret_manager_secret.secret_share.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
}

resource "google_secret_manager_secret" "allowed_oidc_providers" {
  secret_id = "mpc-recovery-allowed-oidc-providers-${var.node_id}-${var.env}"
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "allowed_oidc_providers_data" {
  secret      = google_secret_manager_secret.allowed_oidc_providers.name
  secret_data = jsonencode(var.allowed_oidc_providers)
}

resource "google_secret_manager_secret_iam_member" "allowed_oidc_providers_secret_access" {
  secret_id = google_secret_manager_secret.allowed_oidc_providers.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
}

resource "google_cloud_run_v2_service" "signer" {
  name     = "mpc-recovery-signer-${var.node_id}-${var.env}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      image = var.docker_image
      args  = ["start-sign"]

      env {
        name  = "MPC_RECOVERY_WEB_PORT"
        value = "3000"
      }
      env {
        name  = "MPC_RECOVERY_NODE_ID"
        value = var.node_id
      }
      env {
        name  = "MPC_RECOVERY_GCP_PROJECT_ID"
        value = var.project
      }
      env {
        name  = "MPC_RECOVERY_ENV"
        value = var.env
      }
      env {
        name  = "RUST_LOG"
        value = "mpc_recovery=debug"
      }

      ports {
        container_port = 3000
      }

      resources {
        cpu_idle = false

        limits = {
          cpu    = 2
          memory = "2Gi"
        }
      }
    }
  }
  depends_on = [
    google_secret_manager_secret_version.cipher_key_data,
    google_secret_manager_secret_version.secret_share_data,
    google_secret_manager_secret_version.allowed_oidc_providers_data,
    google_secret_manager_secret_iam_member.cipher_key_secret_access,
    google_secret_manager_secret_iam_member.secret_share_secret_access,
    google_secret_manager_secret_iam_member.allowed_oidc_providers_secret_access
  ]
}

// Allow unauthenticated requests
resource "google_cloud_run_v2_service_iam_member" "allow_all" {
  project  = google_cloud_run_v2_service.signer.project
  location = google_cloud_run_v2_service.signer.location
  name     = google_cloud_run_v2_service.signer.name

  role   = "roles/run.invoker"
  member = "allUsers"

  depends_on = [
    google_cloud_run_v2_service.signer
  ]
}

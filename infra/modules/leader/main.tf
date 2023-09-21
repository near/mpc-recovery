resource "google_secret_manager_secret" "account_creator_sk" {
  secret_id = "mpc-recovery-account-creator-sk-${var.env}"
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "account_creator_sk_data" {
  secret      = google_secret_manager_secret.account_creator_sk.name
  secret_data = var.account_creator_sk
}

resource "google_secret_manager_secret_iam_member" "account_creator_secret_access" {
  secret_id = google_secret_manager_secret.account_creator_sk.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
}

resource "google_secret_manager_secret" "fast_auth_partners" {
  secret_id = "mpc-recovery-allowed-oidc-providers-leader-${var.env}"
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "fast_auth_partners_data" {
  secret      = google_secret_manager_secret.fast_auth_partners.name
  secret_data = jsonencode(var.fast_auth_partners)
}

resource "google_secret_manager_secret_iam_member" "fast_auth_partners_secret_access" {
  secret_id = google_secret_manager_secret.fast_auth_partners.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
}

resource "google_cloud_run_v2_service" "leader" {
  name     = "mpc-recovery-leader-${var.env}"
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
      args  = ["start-leader"]

      env {
        name  = "MPC_RECOVERY_WEB_PORT"
        value = "3000"
      }
      env {
        name  = "MPC_RECOVERY_SIGN_NODES"
        value = join(",", var.signer_node_urls)
      }
      env {
        name  = "MPC_RECOVERY_NEAR_RPC"
        value = var.near_rpc
      }
      env {
        name  = "MPC_RECOVERY_NEAR_ROOT_ACCOUNT"
        value = var.near_root_account
      }
      env {
        name  = "MPC_RECOVERY_ACCOUNT_CREATOR_ID"
        value = var.account_creator_id
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
    google_secret_manager_secret_version.account_creator_sk_data,
    google_secret_manager_secret_version.fast_auth_partners_data,
    google_secret_manager_secret_iam_member.account_creator_secret_access,
    google_secret_manager_secret_iam_member.fast_auth_partners_secret_access,
    google_secret_manager_secret_iam_member.account_creator_secret_access
  ]
}

// Allow unauthenticated requests
resource "google_cloud_run_v2_service_iam_member" "allow_all" {
  project  = google_cloud_run_v2_service.leader.project
  location = google_cloud_run_v2_service.leader.location
  name     = google_cloud_run_v2_service.leader.name

  role   = "roles/run.invoker"
  member = "allUsers"

  depends_on = [
    google_cloud_run_v2_service.leader
  ]
}

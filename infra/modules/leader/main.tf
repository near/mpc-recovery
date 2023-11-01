resource "google_cloud_run_v2_service" "leader" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    annotations = var.metadata_annotations == null ? null : var.metadata_annotations

    vpc_access {
      connector = var.connector_id
      egress    = "PRIVATE_RANGES_ONLY"
    }

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
        name = "MPC_RECOVERY_ACCOUNT_CREATOR_SK"
        value_source {
          secret_key_ref {
            secret  = var.account_creator_sk_secret_id
            version = "1"
          }
        }
      }
      env {
        name = "FAST_AUTH_PARTNERS"
        value_source {
          secret_key_ref {
            secret  = var.fast_auth_partners_secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "MPC_RECOVERY_JWT_SIGNATURE_PK_URL"
        value = var.jwt_signature_pk_url
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

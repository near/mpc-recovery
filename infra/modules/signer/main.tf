resource "google_cloud_run_v2_service" "signer" {
  name     = "mpc-recovery-signer-${var.node_id}-${var.env}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    annotations = var.metadata_annotations == null ? null : var.metadata_annotations

    vpc_access {
      connector = var.connector_id
      egress    = "ALL_TRAFFIC"
    }

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
        name = "MPC_RECOVERY_CIPHER_KEY"
        value_source {
          secret_key_ref {
            secret  = var.cipher_key_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "MPC_RECOVERY_SK_SHARE"
        value_source {
          secret_key_ref {
            secret  = var.sk_share_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "OIDC_PROVIDERS"
        value_source {
          secret_key_ref {
            secret  = var.oidc_providers_secret_id
            version = "latest"
          }
        }
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

  lifecycle {
    # List of fields we don't want to see a diff for in terraform. Most of these fields are set
    # by GCP and is metadata we don't want to account when considering changes in the service.
    ignore_changes = [
      metadata[0].annotations["client.knative.dev/user-image"],
      metadata[0].annotations["run.googleapis.com/client-name"],
      metadata[0].annotations["run.googleapis.com/client-version"],
      metadata[0].annotations["run.googleapis.com/launch-stage"],
      metadata[0].annotations["run.googleapis.com/operation-id"],
      template[0].metadata[0].annotations["client.knative.dev/user-image"],
      template[0].metadata[0].annotations["run.googleapis.com/client-version"],
      template[0].metadata[0].annotations["run.googleapis.com/client-name"],
      template[0].metadata[0].labels["client.knative.dev/nonce"],
      template[0].metadata[0].labels["run.googleapis.com/startupProbeType"],
    ]
  }
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

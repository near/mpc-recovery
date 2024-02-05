resource "google_cloud_run_v2_service" "node" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    annotations = var.metadata_annotations == null ? null : var.metadata_annotations

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      image = var.docker_image
      args  = ["start"]

      env {
        name  = "MPC_RECOVERY_NODE_ID"
        value = var.node_id
      }
      env {
        name  = "MPC_RECOVERY_NEAR_RPC"
        value = var.near_rpc
      }
      env {
        name  = "MPC_RECOVERY_CONTRACT_ID"
        value = var.mpc_contract_id
      }
      env {
        name  = "MPC_RECOVERY_ACCOUNT_ID"
        value = var.account_id
      }
      env {
        name  = "MPC_RECOVERY_CIPHER_PK"
        value = var.cipher_pk
      }
      env {
        name  = "MPC_RECOVERY_LOCAL_ADDRESS"
        value = var.my_address
      }
      env {
        name  = "MPC_RECOVERY_INDEXER_S3_BUCKET"
        value = var.indexer_options.s3_bucket
      }
      env {
        name  = "MPC_RECOVERY_INDEXER_S3_REGION"
        value = var.indexer_options.s3_region
      }
      // Conditional block in case s3_url is present. See https://stackoverflow.com/a/69891235
      dynamic "env" {
        for_each = var.indexer_options.s3_url == null ? [] : [1]
        content {
          name  = "MPC_RECOVERY_INDEXER_S3_URL"
          value = var.indexer_options.s3_url
        }
      }
      env {
        name  = "MPC_RECOVERY_INDEXER_START_BLOCK_HEIGHT"
        value = var.indexer_options.start_block_height
      }
      env {
        name = "MPC_RECOVERY_ACCOUNT_SK"
        value_source {
          secret_key_ref {
            secret  = var.account_sk_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "MPC_RECOVERY_CIPHER_SK"
        value_source {
          secret_key_ref {
            secret  = var.cipher_sk_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AWS_ACCESS_KEY_ID"
        value_source {
          secret_key_ref {
            secret  = var.aws_access_key_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AWS_SECRET_ACCESS_KEY"
        value_source {
          secret_key_ref {
            secret  = var.aws_secret_key_secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "AWS_DEFAULT_REGION"
        value = var.indexer_options.s3_region
      }
      env {
        name  = "MPC_RECOVERY_GCP_PROJECT_ID"
        value = var.project
      }
      env {
        name  = "MPC_RECOVERY_SK_SHARE_SECRET_ID"
        value = var.sk_share_secret_id
      }
      env {
        name  = "MPC_RECOVERY_ENV"
        value = var.env
      }
      env {
        name  = "MPC_RECOVERY_GCP_DATASTORE_URL"
        value = var.datastore_url
      }
      env {
        name  = "MPC_RECOVERY_WEB_PORT"
        value = "3000"
      }
      env {
        name = "MPC_RECOVERY_USE_GCP_SECRET_MANAGER"
        value = var.use_gcp_secret_manager
      }
      env {
        name  = "RUST_LOG"
        value = "mpc_recovery_node=debug"
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
  project  = google_cloud_run_v2_service.node.project
  location = google_cloud_run_v2_service.node.location
  name     = google_cloud_run_v2_service.node.name

  role   = "roles/run.invoker"
  member = "allUsers"

  depends_on = [
    google_cloud_run_v2_service.node
  ]
}

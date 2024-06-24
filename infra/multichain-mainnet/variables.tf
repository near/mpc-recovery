variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
  default     = "pagoda-discovery-platform-prod"
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
  default     = "prod-us-central1"
}

variable "mig_name" {
  description = "The desired name to assign to the deployed managed instance group"
  type        = string
  default     = "mpc-mig"
}

variable "image" {
  description = "The Docker image to deploy to GCE instances"
  type        = string
  default     = "us-east1-docker.pkg.dev/pagoda-discovery-platform-dev/multichain/multichain-dev:mainnet-dev"
}

variable "image_port" {
  description = "The port the image exposes for HTTP requests"
  type        = number
  default     = 3000
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
  default     = "us-central1"
}

variable "network" {
  description = "The GCP network"
  type        = string
  default     = "prod"
}

variable "additional_metadata" {
  type        = map(any)
  description = "Additional metadata to attach to the instance"
  default     = {}
}

variable "service_account" {
  type = object({
    email  = string,
    scopes = list(string)
  })
  default = {
    email  = ""
    scopes = ["cloud-platform"]
  }
}

variable "env_variables" {
  type    = map(any)
  default = null
}

variable "node_configs" {
  type = list(object({
    account              = string
    cipher_pk            = string
    account_sk_secret_id = string
    cipher_sk_secret_id  = string
    sign_sk_secret_id    = string
    sk_share_secret_id   = string
    # ip_address           = string
  }))
}

variable "env" {
  type = string
  default = "dev"
}

variable "static_env" {
  type = list(object({
    name  = string
    value = string
  }))
  default = [
    {
      name  = "MPC_RECOVERY_NEAR_RPC"
      value = "https://rpc.mainnet.near.org"
    },
    {
      name  = "MPC_RECOVERY_CONTRACT_ID"
      value = "multichain-mpc-dev.near"
    },
    {
      name  = "MPC_RECOVERY_INDEXER_S3_BUCKET"
      value = "near-lake-data-mainnet"
    },
    {
      name  = "MPC_RECOVERY_INDEXER_START_BLOCK_HEIGHT"
      value = 159307004
    },
    {
      name  = "AWS_DEFAULT_REGION"
      value = "eu-central-1"
    },
    {
      name  = "MPC_RECOVERY_GCP_PROJECT_ID"
      value = "pagoda-discovery-platform-prod"
    },
    {
      name  = "MPC_RECOVERY_WEB_PORT"
      value = "3000"
    },
    {
      name  = "RUST_LOG"
      value = "mpc_recovery_node=debug"
    },
    {
      name  = "MPC_RECOVERY_INDEXER_S3_REGION"
      value = "eu-central-1"
    },
    {
      name  = "MPC_RECOVERY_MIN_TRIPLES"
      value = 20
    },
    {
      name  = "MPC_RECOVERY_MAX_TRIPLES"
      value = 640
    },
    {
      name  = "MPC_RECOVERY_MIN_PRESIGNATURES"
      value = 10
    },
    {
      name  = "MPC_RECOVERY_MAX_PRESIGNATURES"
      value = 320
    },
    {
      name  = "MPC_RECOVERY_MAX_CONCURRENT_INTRODUCTION"
      value = 2
    },
    {
      name  = "MPC_RECOVERY_MAX_CONCURRENT_GENERATION"
      value = 16
    },
    {
      name  = "MPC_RECOVERY_TRIPLE_TIMEOUT_SEC"
      value = 1200
    }
  ]
}

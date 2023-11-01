variable "env" {
}

variable "project" {
}

variable "credentials_file" {
  default = null
}

variable "credentials" {
  default = null
}

variable "region" {
  default = "us-east1"
}

variable "zone" {
  default = "us-east1-c"
}

variable "docker_image" {
  type = string
}

# Application variables
variable "account_creator_id" {
  default = "tmp_acount_creator.serhii.testnet"
}

variable "external_signer_node_urls" {
  type    = list(string)
  default = []
}

# Secrets
variable "account_creator_sk_secret_id" {
  type = string
}

variable "oidc_providers_secret_id" {
  type = string
}

variable "fast_auth_partners_secret_id" {
  type = string
}

variable "signer_configs" {
  type = list(object({
    cipher_key_secret_id = string
    sk_share_secret_id   = string
  }))
}

variable "dev-connector" {
  default = "projects/pagoda-shared-infrastructure/locations/us-east1/connectors/dev-connector1"
}

variable "prod-connector" {
  default = "projects/pagoda-shared-infrastructure/locations/us-east1/connectors/prod-us-east1-connector"
}

data "google_compute_subnetwork" "dev_subnetwork" {
  name    = "dev-us-central1"
  project = "pagoda-shared-infrastructure"
  region  = "us-central1"
}

data "google_compute_subnetwork" "prod_subnetwork" {
  name    = "prod-us-central1"
  project = "pagoda-shared-infrastructure"
  region  = "us-central1"
}

data "google_compute_network" "dev_network" {
  name    = "dev"
  project = "pagoda-shared-infrastructure"
}

data "google_compute_network" "prod_network" {
  name    = "prod"
  project = "pagoda-shared-infrastructure"
}

variable "jwt_signature_pk_url" {
  type = string
}
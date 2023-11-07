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

variable "fast_auth_partners_secret_id" {
  type = string
}

variable "signer_configs" {
  type = list(object({
    cipher_key_secret_id = string
    sk_share_secret_id   = string
  }))
}

variable "jwt_signature_pk_url" {
  type = string
}

variable "otlp_endpoint" {
  type    = string
  default = "http://localhost:4317"
}

variable "opentelemetry_level" {
  type    = string
  default = "off"
}

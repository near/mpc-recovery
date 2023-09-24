variable "env" {
}

variable "project" {
}

variable "region" {
}

variable "zone" {
}

variable "service_account_email" {
}

variable "docker_image" {
}

# Application variables
variable "node_id" {
}

# Secrets
variable "cipher_key_secret_id" {
  type = string
}

variable "sk_share_secret_id" {
  type = string
}

variable "oidc_providers_secret_id" {
  type = string
}

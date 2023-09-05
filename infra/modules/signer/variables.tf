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

variable "allowed_oidc_providers" {
  type = list(map(string))
}

# Secrets
variable "cipher_key" {
}

variable "sk_share" {
}

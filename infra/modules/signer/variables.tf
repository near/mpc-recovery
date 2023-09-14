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

variable "oidc_providers" {
  type = list(object({
    issuer   = string
    audience = string
  }))
  default = []
}

# Secrets
variable "cipher_key" {
}

variable "sk_share" {
}

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

variable "fast_auth_partners" {
  type = list(object({
    oidc_provider = object({
      issuer   = string
      audience = string
    })
    relayer = object({
      url     = string
      api_key = string
    })
  }))
  default = []
}

# Secrets
variable "cipher_key" {
}

variable "sk_share" {
}

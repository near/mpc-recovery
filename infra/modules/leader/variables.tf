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
variable "signer_node_urls" {
  type = list(string)
}

variable "near_rpc" {
}

variable "near_root_account" {
}

variable "account_creator_id" {
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
variable "account_creator_sk" {
}

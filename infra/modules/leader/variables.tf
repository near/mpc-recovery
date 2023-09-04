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

variable "relayer_api_key" {
}

variable "relayer_url" {
}

variable "near_root_account" {
}

variable "account_creator_id" {
}

variable "allowed_oidc_providers" {
}

# Secrets
variable "account_creator_sk" {
}

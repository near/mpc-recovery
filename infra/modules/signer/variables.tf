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

variable "connector_id" {
  description = "VPC connector ID for internal traffic"
}

variable "metadata_annotations" {
  type        = map(any)
  default     = null
  description = "Annotations for the metadata associated with this Service."
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

variable "service_name" {
  type = string
}
variable "env" {
  type = string
}

variable "project" {
  type = string
}

variable "connector_id" {
  description = "VPC connector ID for internal traffic"
}

variable "metadata_annotations" {
  type        = map(any)
  default     = null
  description = "Annotations for the metadata associated with this Service."
}

variable "region" {
  type = string
}

variable "zone" {
  type = string
}

variable "service_account_email" {
  type = string
}

variable "docker_image" {
  type = string
}

# Application variables
variable "signer_node_urls" {
  type = list(string)
}

variable "near_rpc" {
  type = string
}

variable "near_root_account" {
  type = string
}

variable "account_creator_id" {
  type = string
}

# Secrets
variable "account_creator_sk_secret_id" {
  type = string
}

variable "fast_auth_partners_secret_id" {
  type = string
}

variable "service_name" {
  type = string
}
variable "jwt_signature_pk_url" {
  type = string
}

variable "otlp_endpoint" {
  type = string
}

variable "opentelemetry_level" {
  type = string
}

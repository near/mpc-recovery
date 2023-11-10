variable "env" {
}

variable "project" {
}

variable "credentials_file" {}

variable "region" {
  default = "us-east1"
}

variable "zone" {
  default = "us-east1-c"
}

variable "docker_image" {
}

variable "node_id" {
}

# Secrets
variable "cipher_key_secret_id" {
  type = string
}

variable "sk_share_secret_id" {
  type = string
}

variable "jwt_signature_pk_url" {
  type = string
}

variable "region" {
}

variable "service_account_email" {
}

variable "docker_image" {
}

variable "metadata_annotations" {
  type        = map(any)
  default     = null
  description = "Annotations for the metadata associated with this Service."
}

# Application variables
variable "node_id" {
  type = number
}

variable "near_rpc" {
  type = string
}

variable "mpc_contract_id" {
  type = string
}

variable "account" {
  type = string
}

variable "cipher_pk" {
  type = string
}

variable "my_address" {
  type = string
}

variable "indexer_options" {
  type = object({
    s3_bucket          = string
    s3_region          = string
    s3_url             = optional(string)
    start_block_height = number
  })
}

variable "service_name" {
  type = string
}

# Secrets
variable "account_sk_secret_id" {
  type = string
}

variable "cipher_sk_secret_id" {
  type = string
}

variable "aws_access_key_secret_id" {
  type = string
}

variable "aws_secret_key_secret_id" {
  type = string
}

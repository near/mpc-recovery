variable "env" {
}

variable "project" {
}

variable "credentials_file" {
  default = null
}

variable "credentials" {
  default = null
}

variable "region" {
  default = "us-east1"
}

variable "zone" {
  default = "us-east1-c"
}

variable "docker_image" {
  type = string
}

variable "mpc_contract_id" {
  type = string
}

variable "indexer_options" {
  type = object({
    s3_bucket          = string
    s3_region          = string
    s3_url             = string
    start_block_height = number
  })
}

variable "node_configs" {
  type = list(object({
    account              = string
    cipher_pk            = string
    address              = string
    account_sk_secret_id = string
    cipher_sk_secret_id  = string
  }))
}

variable "aws_access_key_secret_id" {
  type = string
}

variable "aws_secret_key_secret_id" {
  type = string
}

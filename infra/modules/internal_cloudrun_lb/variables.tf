variable "name" {
  type        = string
  description = "The name to use as prefix for load balancer resources."
}

variable "service_name" {
  type        = string
  description = "The cloud run service name"
}

variable "project_id" {
  type        = string
  description = "The GCP project these resources belong to"
}

variable "region" {
  type        = string
  description = "The region where resources will live."
}

variable "network_id" {
  type        = string
  description = "The VPC network to connect to."
}

variable "subnetwork_id" {
  type        = string
  description = "Subnet for hosting the load balancer."
}
variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
  default     = "mig-subnet"
}

variable "mig_name" {
  description = "The desired name to assign to the deployed managed instance group"
  type        = string
  default     = "mig-test"
}

variable "mig_instance_count" {
  description = "The number of instances to place in the managed instance group"
  type        = string
  default     = "2"
}

variable "image" {
  description = "The Docker image to deploy to GCE instances"
  type        = string
  default     = "gcr.io/google-samples/hello-app:1.0"
}

variable "image_port" {
  description = "The port the image exposes for HTTP requests"
  type        = number
  default     = 8080
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
}

variable "network" {
  description = "The GCP network"
  type        = string
  default     = "mig-net"
}

variable "additional_metadata" {
  type        = map(any)
  description = "Additional metadata to attach to the instance"
  default     = {}
}

variable "service_account" {
  type = object({
    email  = string,
    scopes = list(string)
  })
  default = {
    email  = ""
    scopes = ["cloud-platform"]
  }
}

variable "env_variables" {
  type    = map(any)
  default = null
}

variable "versions" {
  type = list(object({
    name              = string
    instance_template = string
    target_size = object({
      fixed   = number
      percent = number
    })
  }))
}
terraform {
  required_version = ">=0.13.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.67, < 6"
    }
  }
  provider_meta "google" {
    module_name = "blueprints/terraform/terraform-google-vm:instance_template/v10.1.1"
  }
}

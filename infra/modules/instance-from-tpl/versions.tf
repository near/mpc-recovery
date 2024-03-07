terraform {
  required_version = ">=0.13.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.48, < 6"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.48, < 6"
    }
  }
  provider_meta "google" {
    module_name = "blueprints/terraform/terraform-google-vm:mig/v10.1.1"
  }
  provider_meta "google-beta" {
    module_name = "blueprints/terraform/terraform-google-vm:mig/v10.1.1"
  }
}

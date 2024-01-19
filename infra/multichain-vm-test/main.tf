provider "google" {
  project = var.project_id
}
provider "google-beta" {
  project = var.project_id
}
module "gce-container" {
  source  = "terraform-google-modules/container-vm/google"
  version = "~> 3.0"

  container = {
    image   = "us-east1-docker.pkg.dev/pagoda-discovery-platform-dev/multichain/multichain-dev:latest"
    command = "start"
    port    = "3000"

    env = [
      {
        name  = ""
        value = ""
      }
    ]
  }
}

module "mig_template" {
  source               = "../modules/mig_template"
  version              = "~> 10.0"
  network              = "dev"
  subnetwork           = "dev-us-central1"
  service_account      = var.service_account
  name_prefix          = var.network
  source_image_family  = "cos-stable"
  source_image_project = "cos-cloud"
  source_image         = reverse(split("/", module.gce-container.source_image))[0]
  metadata             = merge(var.additional_metadata, { "gce-container-declaration" = module.gce-container.metadata_value })
  tags = [
    "container-vm-multichain-test"
  ]
  labels = {
    "container-vm" = module.gce-container.vm_container_label
  }
}


module "mig" {
  source            = "./modules/mig"
  version           = "~> 10.0"
  instance_template = module.mig_template.self_link
  region            = var.region
  hostname          = var.network
  target_size       = "3"

  stateful_disks = [
    {
      device_name = "disk-name"
      delete_rule = "NEVER"
    },
  ]

  versions = [
    {
      name              = ""
      instance_template = module.mig_template.self_link
      target_size = {
        fixed = 1
      }
    }
  ]
  named_ports = [
    {
      name = "http",
      port = var.image_port
    }
  ]
}
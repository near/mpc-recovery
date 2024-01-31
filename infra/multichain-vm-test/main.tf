provider "google" {
  project = var.project_id
}
provider "google-beta" {
  project = var.project_id
}
module "gce-container" {
  count   = length(var.node_configs)
  source  = "terraform-google-modules/container-vm/google"
  version = "~> 3.0"

  container = {
    image   = "us-east1-docker.pkg.dev/pagoda-discovery-platform-dev/multichain/multichain-dev:latest"
    args = ["start"]
    port    = "3000"

    env = concat(var.static_env, [
      {
        name  = "MPC_RECOVERY_NODE_ID"
        value = "${count.index}"
      },
      {
        name  = "MPC_RECOVERY_ACCOUNT_ID"
        value = var.node_configs["${count.index}"].account
      },
      {
        name  = "MPC_RECOVERY_CIPHER_PK"
        value = var.node_configs["${count.index}"].cipher_pk
      },
      {
        name  = "MPC_RECOVERY_LOCAL_ADDRESS"
        value = var.node_configs["${count.index}"].account
      },
      {
        name  = "MPC_RECOVERY_ACCOUNT_SK"
        value = data.google_secret_manager_secret_version.account_sk_secret_id[count.index].secret_data
      },
      {
        name  = "MPC_RECOVERY_CIPHER_SK"
        value = data.google_secret_manager_secret_version.cipher_sk_secret_id[count.index].secret_data
      },
      {
        name  = "AWS_ACCESS_KEY_ID"
        value = data.google_secret_manager_secret_version.aws_access_key_secret_id.secret_data
      },
      {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = data.google_secret_manager_secret_version.aws_secret_key_secret_id.secret_data
      },
      {
        name  = "MPC_RECOVERY_LOCAL_ADDRESS"
        value = "http://${google_compute_address.internal_ips[count.index].address}"
      },
    ])
  }
}

resource "google_compute_address" "internal_ips" {
  count = length(var.node_configs)
  name = "multichain-dev-${count.index}"
  address_type = "INTERNAL"
  region = var.region
  subnetwork = "projects/pagoda-shared-infrastructure/regions/us-central1/subnetworks/dev-us-central1"
}

module "mig_template" {
  count                = length(var.node_configs)
  source               = "../modules/mig_template"
  network              = "projects/pagoda-shared-infrastructure/global/networks/dev"
  subnetwork           = "projects/pagoda-shared-infrastructure/regions/us-central1/subnetworks/dev-us-central1"
  region               = var.region
  service_account      = var.service_account
  name_prefix          = "multichain-${count.index}"
  source_image_family  = "cos-stable"
  source_image_project = "cos-cloud"
  machine_type         = "n2-standard-2"

  source_image         = reverse(split("/", module.gce-container[count.index].source_image))[0]
  metadata             = merge(var.additional_metadata, { "gce-container-declaration" = module.gce-container["${count.index}"].metadata_value })
  tags = [
    "multichain"
  ]
  labels = {
    "container-vm" = module.gce-container[count.index].vm_container_label
  }

  depends_on = [ google_compute_address.internal_ips ]
}


module "instances" {
  count = length(var.node_configs)
  source = "../modules/instance-from-tpl"
  region = var.region
  project_id = var.project_id
  hostname = "multichain-dev-${count.index}"
  network = "projects/pagoda-shared-infrastructure/global/networks/dev"
  subnetwork = "projects/pagoda-shared-infrastructure/regions/us-central1/subnetworks/dev-us-central1"

  instance_template = module.mig_template[count.index].self_link_unique
  static_ips = [ google_compute_address.internal_ips[count.index].address ]

}

resource "google_compute_health_check" "multichain_healthcheck" {
  name = "multichain-dev-healthcheck"

  http_health_check {
    port = 3000
    request_path = "/"
  }
  
}

resource "google_compute_backend_service" "multichain_backend" {
  name = "multichain-service"
  load_balancing_scheme = "INTERNAL_SELF_MANAGED"

  backend {
    group = google_compute_instance_group.multichain_group.id
  }

  health_checks = [ google_compute_health_check.multichain_healthcheck.id ]
}

resource "google_compute_instance_group" "multichain_group" {
  name = "multichain-instance-group"
  instances = module.instances[*].self_links[0]

  zone = "us-central1-a"
  named_port {
    name = "http"
    port = 3000
  }
}

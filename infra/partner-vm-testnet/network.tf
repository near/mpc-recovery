module "vpc" {
    source  = "terraform-google-modules/network/google"
    version = "~> 9.0"

    project_id   = var.project_id
    network_name = var.network
    routing_mode = "GLOBAL"

    subnets = [
        {
            subnet_name           = var.subnetwork
            subnet_ip             = "10.10.10.0/24"
            subnet_region         = var.region
        }
    ]

    routes = [
        {
            name                   = "egress-internet"
            description            = "route through IGW to access internet"
            destination_range      = "0.0.0.0/0"
            tags                   = "egress-inet"
            next_hop_internet      = "true"
        }
    ]

    ingress_rules = [ 
      {
        name = "allow-iap-ssh"
        description = "this rule allows you to connect to your VM via SSH without port 22 being public"
        source_ranges = [ "35.235.240.0/20" ]
        target_tags = [ "allow-ssh" ]
        allow = [ 
            {
            protocol = "tcp",
            ports = ["22"]
          } 
        ]
      },
     ]
}
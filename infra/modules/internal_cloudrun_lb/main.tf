resource "google_compute_region_network_endpoint_group" "default_neg" {
  name                  = "${var.name}-neg"
  project               = var.project_id
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = var.service_name
  }
}

resource "google_compute_region_backend_service" "default" {
  name                  = "${var.name}-backend-service"
  project               = var.project_id
  region                = var.region
  protocol              = "HTTP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  timeout_sec           = 30
  backend {
    group           = google_compute_region_network_endpoint_group.default_neg.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
}

resource "google_compute_region_url_map" "default" {
  name            = "${var.name}-url-map"
  project         = var.project_id
  region          = var.region
  default_service = google_compute_region_backend_service.default.id
}

resource "google_compute_region_target_http_proxy" "default" {
  name    = "${var.name}-http-proxy"
  region  = var.region
  project = var.project_id
  url_map = google_compute_region_url_map.default.id
}

resource "google_compute_forwarding_rule" "default" {
  name                  = "${var.name}-forwarding-rule"
  project               = var.project_id
  region                = var.region
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_region_target_http_proxy.default.id
  network               = var.network_id
  subnetwork            = var.subnetwork_id
  network_tier          = "PREMIUM"
}

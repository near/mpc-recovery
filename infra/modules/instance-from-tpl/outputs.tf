
output "available_zones" {
  description = "List of available zones in region"
  value       = data.google_compute_zones.available.names
}

output "self_links" {
  value = google_compute_instance_from_template.compute_instance[*].self_link
}

output "hostname" {
  value = local.hostname
}

output "ip_address" {
  value = local.static_ips
}
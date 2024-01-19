output "self_link" {
  description = "Self-link of managed instance group"
  value       = google_compute_region_instance_group_manager.mig.self_link
}

output "instance_group" {
  description = "Instance-group url of managed instance group"
  value       = google_compute_region_instance_group_manager.mig.instance_group
}

output "instance_group_manager" {
  description = "An instance of google_compute_region_instance_group_manager of the instance group."
  value       = google_compute_region_instance_group_manager.mig
}

output "health_check_self_links" {
  description = "All self_links of healthchecks created for the instance group."
  value       = local.healthchecks
}
output "self_link_unique" {
  description = "Unique self-link of instance template (recommended output to use instead of self_link)"
  value       = google_compute_instance_template.tpl.self_link_unique
}

output "self_link" {
  description = "Self-link of instance template"
  value       = google_compute_instance_template.tpl.self_link
}

output "name" {
  description = "Name of instance template"
  value       = google_compute_instance_template.tpl.name
}

output "tags" {
  description = "Tags that will be associated with instance(s)"
  value       = google_compute_instance_template.tpl.tags
}

output "collector_email" {
  value = google_service_account.collector.email
}

output "topic" {
  value = google_pubsub_topic.audit.id
}

output "subscription" {
  value = google_pubsub_subscription.audit.id
}

output "sink_enabled" {
  value = !google_logging_project_sink.audit.disabled
}

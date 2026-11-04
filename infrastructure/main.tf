locals {
  labels = { application = "googlesecops-lab", environment = "lab", managed_by = "terraform" }
  services = toset([
    "logging.googleapis.com", "pubsub.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com"
  ])
}

data "google_project" "lab" {
  project_id = var.project_id
}

resource "google_project_service" "lab" {
  for_each           = local.services
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false

  lifecycle {
    precondition {
      condition     = try(data.google_project.lab.labels["application"], "") == "googlesecops-lab"
      error_message = "The dedicated project must have the label application=googlesecops-lab."
    }
  }
}

resource "google_pubsub_topic" "audit" {
  name    = "gsl-audit"
  project = var.project_id
  labels  = local.labels
  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }

  depends_on = [google_project_service.lab]
}

resource "google_pubsub_subscription" "audit" {
  name                         = "gsl-audit-pull"
  project                      = var.project_id
  topic                        = google_pubsub_topic.audit.id
  labels                       = local.labels
  ack_deadline_seconds         = 30
  message_retention_duration   = "3600s"
  retain_acked_messages        = false
  enable_exactly_once_delivery = false
  expiration_policy {
    ttl = "259200s"
  }
}

resource "google_service_account" "collector" {
  project      = var.project_id
  account_id   = "gsl-audit-collector"
  display_name = "GoogleSecOps-Lab audit pull identity"
  depends_on   = [google_project_service.lab]
}

resource "google_pubsub_subscription_iam_member" "collect" {
  project      = var.project_id
  subscription = google_pubsub_subscription.audit.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.collector.email}"
}

resource "google_service_account_iam_member" "operator" {
  count              = var.operator_member == null ? 0 : 1
  service_account_id = google_service_account.collector.name
  role               = startswith(coalesce(var.operator_member, "none"), "principal://") ? "roles/iam.workloadIdentityUser" : "roles/iam.serviceAccountTokenCreator"
  member             = var.operator_member
}

resource "google_logging_project_sink" "audit" {
  name                   = "gsl-audit-routing"
  project                = var.project_id
  description            = "GoogleSecOps-Lab narrow activity sink"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.audit.id}"
  unique_writer_identity = true
  disabled               = !var.route_audit
  filter                 = <<-FILTER
    log_id("cloudaudit.googleapis.com/activity")
    (
      (protoPayload.serviceName=("iam.googleapis.com" OR "cloudresourcemanager.googleapis.com")
        AND protoPayload.methodName=~"(^|[.])(SetIamPolicy|CreateServiceAccountKey)$")
      OR (protoPayload.serviceName="logging.googleapis.com"
        AND protoPayload.methodName=~"[.](UpdateSink|DeleteSink|CreateExclusion|UpdateExclusion)$")
      OR (protoPayload.serviceName="compute.googleapis.com"
        AND protoPayload.methodName=~"[.]firewalls[.](insert|patch)$")
      OR (protoPayload.serviceName="pubsub.googleapis.com"
        AND protoPayload.methodName="google.pubsub.v1.Publisher.UpdateTopic"
        AND protoPayload.resourceName="projects/${var.project_id}/topics/gsl-audit")
    )
  FILTER
}

resource "google_pubsub_topic_iam_member" "logging_writer" {
  project = var.project_id
  topic   = google_pubsub_topic.audit.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.audit.writer_identity
}

resource "google_billing_budget" "lab" {
  count           = var.billing_account == null ? 0 : 1
  billing_account = var.billing_account
  display_name    = "GoogleSecOps-Lab / ${var.project_id}"
  budget_filter {
    projects = ["projects/${data.google_project.lab.number}"]
  }
  amount {
    specified_amount {
      units = tostring(var.budget_amount)
    }
  }
  threshold_rules {
    threshold_percent = 0.5
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "CURRENT_SPEND"
  }
}

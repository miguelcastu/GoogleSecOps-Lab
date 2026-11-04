mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      labels = { application = "googlesecops-lab" }
      number = "123456789012"
    }
  }
  mock_resource "google_pubsub_topic" {
    defaults = { id = "projects/gsl-ci-test/topics/gsl-audit" }
  }
  mock_resource "google_logging_project_sink" {
    defaults = { writer_identity = "serviceAccount:sink@example.test" }
  }
}

variables {
  project_id = "gsl-ci-test"
}

run "safe_defaults" {
  command = plan

  assert {
    condition     = google_logging_project_sink.audit.disabled
    error_message = "Audit routing must be disabled by default."
  }

  assert {
    condition     = google_pubsub_subscription.audit.message_retention_duration == "3600s" && !google_pubsub_subscription.audit.retain_acked_messages
    error_message = "Limit backlog and omit acknowledged message retention."
  }

  assert {
    condition     = length(google_billing_budget.lab) == 0
    error_message = "Billing configuration is opt-in."
  }
}

run "explicit_opt_in" {
  command = plan

  variables {
    route_audit     = true
    billing_account = "000000-000000-000000"
  }

  assert {
    condition     = !google_logging_project_sink.audit.disabled && length(google_billing_budget.lab) == 1
    error_message = "Explicit opt-in should enable routing and the scoped budget."
  }
}

run "wrong_project_prefix" {
  command = plan
  variables {
    project_id = "shared-production"
  }
  expect_failures = [var.project_id]
}

variable "project_id" {
  description = "Existing isolated Google Cloud project reserved for this lab."
  type        = string
  validation {
    condition     = can(regex("^gsl-[a-z0-9][a-z0-9-]{2,24}[a-z0-9]$", var.project_id))
    error_message = "Use a dedicated, explicitly approved gsl-* project ID."
  }
}

variable "region" {
  type        = string
  description = "Approved Pub/Sub message storage region."
  default     = "europe-west1"
}

variable "operator_member" {
  type        = string
  default     = null
  description = "Optional exact user, service account or federated principal authorized to impersonate the collector."
  validation {
    condition     = var.operator_member == null ? true : can(regex("^(user:[^*]+@[^*]+|serviceAccount:[^*]+@[^*]+|principal://iam.googleapis.com/[^*]+)$", var.operator_member))
    error_message = "Specify one exact IAM member."
  }
}

variable "route_audit" {
  type        = bool
  default     = false
  description = "Enable the narrow activity sink after reviewing project and billing controls."
}

variable "billing_account" {
  type        = string
  default     = null
  description = "Optional approved billing account ID for project-scoped budget alerts."
  validation {
    condition     = var.billing_account == null ? true : can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account))
    error_message = "Use the uppercase billing account ID."
  }
}

variable "budget_amount" {
  type        = number
  default     = 1
  description = "Budget amount in the billing account's currency. Budget notifications do not cap spending."
  validation {
    condition     = var.budget_amount >= 1 && var.budget_amount <= 20 && floor(var.budget_amount) == var.budget_amount
    error_message = "Use a whole amount from 1 through 20."
  }
}

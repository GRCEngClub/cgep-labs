# Lab 5.4: GCP Security Services Baseline.
# Org Policy (CM-6 / AC-3) + Workload Identity Federation (AC-2) +
# Data Access logs (AU-2) + SCC sources (SI-4).

terraform {
  required_version = ">= 1.6"
  required_providers {
    google      = { source = "hashicorp/google", version = "~> 5.0" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 5.0" }
  }
}

# user_project_override + billing_project bill API calls to your project.
# Without them the Org Policy API returns a 403 quota error.
provider "google" {
  project               = var.gcp_project
  user_project_override = true
  billing_project       = var.gcp_project
}

provider "google-beta" {
  project               = var.gcp_project
  user_project_override = true
  billing_project       = var.gcp_project
}

variable "gcp_project" {
  type        = string
  description = "GCP project ID. Lab uses your own; set via terraform.tfvars or -var."
}

variable "enable_org_policy" {
  type        = bool
  default     = true
  description = "Set to false when the project has no Organization above it."
}

variable "github_org" {
  type    = string
  default = "GRCEngClub"
}

variable "github_repo" {
  type    = string
  default = "cgep-app-starter"
}

# ----- Org Policy at project scope -----------------------------------------
# Org Policy needs the project to sit under an Organization, and
# roles/orgpolicy.policyAdmin is granted on the Organization. For a standalone
# project, set enable_org_policy = false. The same resources work at
# folder/organization scope by changing parent.

resource "google_org_policy_policy" "uniform_bucket_access" {
  count  = var.enable_org_policy ? 1 : 0
  name   = "projects/${var.gcp_project}/policies/storage.uniformBucketLevelAccess"
  parent = "projects/${var.gcp_project}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "disable_sa_keys" {
  count  = var.enable_org_policy ? 1 : 0
  name   = "projects/${var.gcp_project}/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/${var.gcp_project}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "require_oslogin" {
  count  = var.enable_org_policy ? 1 : 0
  name   = "projects/${var.gcp_project}/policies/compute.requireOsLogin"
  parent = "projects/${var.gcp_project}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ----- Workload Identity Federation for GitHub Actions ---------------------
# Replaces long-lived service account keys with short-lived OIDC tokens.

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "OIDC trust for GitHub Actions workflows"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.actor"      = "assertion.actor"
  }

  attribute_condition = "assertion.repository == \"${var.github_org}/${var.github_repo}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "gha" {
  account_id   = "cgep-grc-gate-sa"
  display_name = "CGE-P GRC gate (read-only)"
}

resource "google_project_iam_member" "gha_viewer" {
  project = var.gcp_project
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.gha.email}"
}

resource "google_service_account_iam_binding" "wif_user" {
  service_account_id = google_service_account.gha.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_org}/${var.github_repo}",
  ]
}

# ----- Data Access logs (AU-2) ---------------------------------------------
# OFF BY DEFAULT in GCP. Enabling them is a real operational decision because
# they incur Cloud Logging ingestion + storage cost.

resource "google_project_iam_audit_config" "storage" {
  project = var.gcp_project
  service = "storage.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

resource "google_project_iam_audit_config" "kms" {
  project = var.gcp_project
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

resource "google_project_iam_audit_config" "iam" {
  project = var.gcp_project
  service = "iam.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# ----- Outputs --------------------------------------------------------------

output "wif_provider" {
  value       = google_iam_workload_identity_pool_provider.github.name
  description = "Use as workload_identity_provider in your github actions workflow."
}

output "service_account_email" {
  value = google_service_account.gha.email
}

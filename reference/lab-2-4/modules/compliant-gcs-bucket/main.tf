# main.tf — compliant-gcs-bucket module
# Hardcodes encryption (SC-13/SC-28), uniform access (AC-3), versioning + retention (AU-11),
# and required labels (CM-6). Customization is opt-in only.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

locals {
  # Required labels are computed in locals so consumers cannot disable them via var.labels.
  required_labels = {
    project          = var.project_label
    environment      = var.environment
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }

  effective_labels = merge(var.labels, local.required_labels)

  bucket_name = "${var.project_label}-${var.environment}-${var.bucket_name_suffix}"
  keyring_id  = "${var.bucket_name_suffix}-ring"
  key_id      = "${var.bucket_name_suffix}-key"
}

# Lookup the GCS service account so we can grant it use of the CMEK.
data "google_storage_project_service_account" "gcs" {
  project = var.gcp_project
}

# SC-12: cryptographic key establishment. We own the key, not Google.
resource "google_kms_key_ring" "ring" {
  name     = local.keyring_id
  location = var.kms_location
  project  = var.gcp_project
}

# SC-13/SC-28: cryptographic protection at rest. Rotation every 90 days.
resource "google_kms_crypto_key" "key" {
  name     = local.key_id
  key_ring = google_kms_key_ring.ring.id

  rotation_period = "7776000s"

  # Allow destroy in lab; production should set prevent_destroy = true.
  lifecycle {
    prevent_destroy = false
  }
}

# Required for CMEK on GCS: bucket service account must encrypt/decrypt.
resource "google_kms_crypto_key_iam_member" "gcs_encrypter" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

# AC-3 + SC-28 + CM-6 + AU-11 in one resource declaration.
resource "google_storage_bucket" "bucket" {
  name     = local.bucket_name
  project  = var.gcp_project
  location = var.location

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  retention_policy {
    retention_period = var.retention_days * 86400
    is_locked        = false
  }

  labels = local.effective_labels

  depends_on = [google_kms_crypto_key_iam_member.gcs_encrypter]
}

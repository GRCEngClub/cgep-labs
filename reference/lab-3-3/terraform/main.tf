# Mixed-compliance fixture for Lab 3.3.
# Has compliant and non-compliant GCS buckets and firewall rules so the policy
# suite has something concrete to flag.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

variable "gcp_project" {
  type = string
}

# ---- Compliant resources ---------------------------------------------------

resource "google_kms_key_ring" "ring" {
  name     = "lab33-ring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name     = "lab33-key"
  key_ring = google_kms_key_ring.ring.id
}

resource "google_storage_bucket" "good" {
  name                        = "${var.gcp_project}-lab33-good"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

# ---- Non-compliant resources (the policy suite must catch these) -----------

resource "google_storage_bucket" "bad_no_cmek" {
  name                        = "${var.gcp_project}-lab33-no-cmek"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # No encryption block. SC-28 should fire.

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

resource "google_storage_bucket" "bad_public" {
  name                        = "${var.gcp_project}-lab33-public"
  location                    = "us-central1"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

resource "google_storage_bucket" "bad_no_labels" {
  name                        = "${var.gcp_project}-lab33-no-labels"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  # CM-6 should fire on missing labels.
}

resource "google_compute_network" "demo" {
  name                    = "lab33-demo"
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "open_ssh" {
  name    = "lab33-open-ssh"
  network = google_compute_network.demo.name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  # AC-3 should fire.
}

# consumers/negative-test/main.tf — designed to fail at plan time.
# Confirms input validation rejects production with too-short retention.

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

module "broken_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = var.gcp_project
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 30   # FAILS: prod requires >= 365
  bucket_name_suffix = "should-never-exist"
}

variable "gcp_project" {
  type        = string
  description = "GCP project ID. Set via terraform.tfvars or -var=gcp_project=<id>."
}

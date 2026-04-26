# variables.tf — module interface

variable "gcp_project" {
  type        = string
  description = "GCP project ID where the bucket and KMS resources will live."
}

variable "location" {
  type        = string
  description = "GCS bucket location. Multi-regions like US, EU are valid. Defaults to us-central1 to align with KMS."
  default     = "us-central1"
}

variable "kms_location" {
  type        = string
  description = "KMS keyring location. Must be a single region (multi-regions are not supported for keyrings). Defaults to us-central1."
  default     = "us-central1"
}

variable "project_label" {
  type        = string
  description = "Short identifier for the project. Used in bucket names and the project label."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_label))
    error_message = "project_label must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment. Drives retention and labels."

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "retention_days" {
  type        = number
  description = "Object retention in days. Production must be >= 365."

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 3650
    error_message = "retention_days must be between 1 and 3650."
  }

  validation {
    condition     = var.environment != "prod" || var.retention_days >= 365
    error_message = "retention_days must be >= 365 when environment == \"prod\"."
  }
}

variable "bucket_name_suffix" {
  type        = string
  description = "Unique suffix appended to the bucket name. Must be globally unique within GCS."

  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.bucket_name_suffix))
    error_message = "bucket_name_suffix must be 3-30 lowercase alphanumerics or hyphens."
  }
}

variable "labels" {
  type        = map(string)
  description = "Optional additional labels. Required compliance labels are merged on top and cannot be overridden."
  default     = {}
}

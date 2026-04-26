# variables.tf

variable "project_name" {
  type        = string
  description = "Short project identifier. Becomes part of bucket names and the Project tag."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment. Drives the Environment tag and downstream policy decisions."

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "bucket_suffix" {
  type        = string
  description = "Optional suffix to force a specific bucket name. Defaults to a random_id."
  default     = ""
}

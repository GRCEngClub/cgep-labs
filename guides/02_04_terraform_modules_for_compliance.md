# Lab 2.4: Terraform Modules for Compliance (GCP)

Lab 2.3 built one bucket. This lab builds a pattern. The shift to feel: you don't deploy buckets, you deploy a module that deploys buckets, and the security floor sits inside the module where consumers can't reach it.

## Learning objectives

- Compose a Terraform module with a clear interface: inputs, outputs, hardcoded compliance defaults.
- Encode SC-12, SC-13, SC-28, AU-11, and CM-6 controls so they cannot be turned off by a consumer.
- Emit a compliance attestation as a module output that downstream labs consume as evidence.

## Prerequisites

- A GCP project you control, with billing enabled. Examples below use the placeholder `your-gcp-project`; substitute your project ID.
- `gcloud` authenticated for both interactive (`gcloud auth login`) and Application Default Credentials (`gcloud auth application-default login`). Terraform's google provider uses ADC.
- Roles: `roles/storage.admin`, `roles/cloudkms.admin` on the project.
- Cloud KMS API enabled: `gcloud services enable cloudkms.googleapis.com`.
- Terraform `>= 1.6`.

## Estimated time & cost

- Time: 45 to 60 minutes.
- Cost: KMS keys are billed at about $0.06 per active key version per month. If you destroy the day you create, prorated cost is fractions of a cent. The bucket itself is free while empty.

## Architecture

The module produces one keyring, one CMEK, one IAM binding, one bucket. Two consumers (dev, prod) call the module with different `environment` and `retention_days`, getting the same security posture under different business config.

```
                                consumers/dev               consumers/prod
                                       │                            │
                                       ▼                            ▼
                          ┌──────────────────────────────────────────────┐
                          │        module: compliant-gcs-bucket           │
                          │   ┌─────────────┐  ┌──────────────────────┐  │
                          │   │ KMS keyring │─▶│ KMS crypto key       │  │
                          │   └─────────────┘  │ rotation 90d (SC-12) │  │
                          │                    └──────────┬───────────┘  │
                          │                               │ encrypter    │
                          │                               ▼              │
                          │                    ┌──────────────────────┐  │
                          │                    │ google_storage_bucket│  │
                          │                    │ uniform access (AC-3)│  │
                          │                    │ CMEK (SC-13/SC-28)   │  │
                          │                    │ versioning + retention (AU-11) │
                          │                    │ public-prevention=enforced     │
                          │                    │ required labels (CM-6)         │
                          │                    └──────────────────────┘  │
                          └──────────────────────────────────────────────┘
```

## Step-by-step walkthrough

### 5.1 Why a module

A module is a directory of Terraform with a clear interface: inputs, outputs, and a body. The body decides what's hardcoded. The interface decides what consumers can change. If you've done Lab 2.3, you wrote one bucket on AWS. This time you write one module on GCP and call it twice.

### 5.2 Design the interface

Three rules:

1. `main.tf` hardcodes anything compliance-relevant: encryption, uniform access, versioning, retention behavior, required labels.
2. `variables.tf` exposes only what business actually changes: project, environment, retention duration, names.
3. `outputs.tf` returns evidence: identifiers, plus a computed `compliance_attestation` map.

Consumers write a few lines. The module enforces the rest.

### 5.3 Build `modules/compliant-gcs-bucket/main.tf`

```hcl
# main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

locals {
  required_labels = {
    project          = var.project_label
    environment      = var.environment
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }

  effective_labels = merge(var.labels, local.required_labels)
  bucket_name      = "${var.project_label}-${var.environment}-${var.bucket_name_suffix}"
  keyring_id       = "${var.bucket_name_suffix}-ring"
  key_id           = "${var.bucket_name_suffix}-key"
}

data "google_storage_project_service_account" "gcs" {
  project = var.gcp_project
}

# SC-12: cryptographic key establishment. We own the key, not Google.
resource "google_kms_key_ring" "ring" {
  name     = local.keyring_id
  location = var.kms_location
  project  = var.gcp_project
}

# SC-13 / SC-28: cryptographic protection at rest. 90-day rotation.
resource "google_kms_crypto_key" "key" {
  name            = local.key_id
  key_ring        = google_kms_key_ring.ring.id
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = false  # set true in production
  }
}

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

  versioning { enabled = true }

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
```

Required labels live in `locals`, then merge on top of `var.labels`. A consumer can add labels but cannot suppress the four compliance ones. That asymmetry is the point.

### 5.4 Build `variables.tf` with validation

```hcl
# variables.tf
variable "gcp_project" {
  type        = string
  description = "GCP project ID where the bucket and KMS resources will live."
}

variable "location" {
  type        = string
  description = "GCS bucket location. Multi-regions like US, EU are valid for buckets."
  default     = "us-central1"
}

variable "kms_location" {
  type        = string
  description = "KMS keyring location. Must be a single region (multi-regions are not supported for keyrings)."
  default     = "us-central1"
}

variable "project_label" {
  type        = string
  description = "Short project identifier."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_label))
    error_message = "project_label must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment."
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
  description = "Globally-unique suffix appended to the bucket name."
  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.bucket_name_suffix))
    error_message = "bucket_name_suffix must be 3-30 lowercase alphanumerics or hyphens."
  }
}

variable "labels" {
  type        = map(string)
  description = "Optional additional labels. Required compliance labels are merged on top."
  default     = {}
}
```

> **Why two location vars:** GCS buckets accept multi-region names like `US` and `EU`. KMS keyrings do not. The first time I tried `var.location = "US"` for both, KMS rejected with `KMS_RESOURCE_NOT_FOUND_IN_LOCATION`. Splitting the variable keeps the lesson honest. Both default to `us-central1`.

### 5.5 Build `outputs.tf` returning compliance evidence

```hcl
# outputs.tf
output "bucket_url" {
  value       = google_storage_bucket.bucket.url
  description = "gs:// URL of the compliant bucket."
}

output "bucket_self_link" {
  value       = google_storage_bucket.bucket.self_link
  description = "Self-link of the compliant bucket."
}

output "kms_key_id" {
  value       = google_kms_crypto_key.key.id
  description = "Resource ID of the CMEK protecting this bucket."
}

output "compliance_attestation" {
  description = "Computed attestation of the controls this module enforces."
  value = {
    encryption_algorithm     = "google-managed-cmek-aes256"
    versioning_enabled       = google_storage_bucket.bucket.versioning[0].enabled
    public_access_prevention = google_storage_bucket.bucket.public_access_prevention
    uniform_access_enforced  = google_storage_bucket.bucket.uniform_bucket_level_access
    retention_period_days    = var.retention_days
    required_labels_present  = alltrue([
      for k in keys(local.required_labels) : contains(keys(google_storage_bucket.bucket.labels), k)
    ])
    kms_rotation_period      = google_kms_crypto_key.key.rotation_period
  }
}
```

`compliance_attestation` is the bridge to Lab 3 (Rego asserts on it) and Lab 6 (OSCAL evidence URI points at the JSON it ends up in).

### 5.6 Write consumer #1: dev environment, 30-day retention

```hcl
# consumers/dev/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "your-gcp-project"
  region  = "us-central1"
}

module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "your-gcp-project"
  project_label      = "cgep-lab"
  environment        = "dev"
  retention_days     = 30
  bucket_name_suffix = "dev-data-001"
}

output "attestation" { value = module.data_bucket.compliance_attestation }
output "bucket_url"  { value = module.data_bucket.bucket_url }
```

Six lines of business config. Twenty-plus controls.

### 5.7 Write consumer #2: prod environment, 365-day retention

Same module, swap two values:

```hcl
# consumers/prod/main.tf
module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "your-gcp-project"
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 365
  bucket_name_suffix = "prod-data-001"
}
```

(Same provider block, same outputs.)

### 5.8 Apply and observe

Run the cycle on dev. For lab purposes, prod-plan but don't apply (a 365-day retention lock takes a year to expire):

```bash
cd consumers/dev
terraform init
terraform plan -out=tfplan
terraform apply -auto-approve tfplan
```

You'll see, at the tail:

```
attestation = {
  "encryption_algorithm"     = "google-managed-cmek-aes256"
  "kms_rotation_period"      = "7776000s"
  "public_access_prevention" = "enforced"
  "required_labels_present"  = true
  "retention_period_days"    = 30
  "uniform_access_enforced"  = true
  "versioning_enabled"       = true
}
bucket_url = "gs://cgep-lab-dev-dev-data-001"
```

That output is the SC-12 / SC-13 / SC-28 / AC-3 / CM-6 / AU-11 attestation in machine-readable form.

### 5.9 The negative test

Copy `consumers/dev` to `consumers/negative-test`, change `environment` to `prod`, leave `retention_days` at 30, and run plan:

```hcl
module "broken_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "your-gcp-project"
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 30   # FAILS: prod requires >= 365
  bucket_name_suffix = "should-never-exist"
}
```

```
Error: Invalid value for variable

  on main.tf line 17:
   ...
   var.environment is "prod"
   var.retention_days is 30

retention_days must be >= 365 when environment == "prod".

This was checked by the validation rule at variables.tf:49,3-13.
```

This is the lesson. The compliance check happened at `terraform plan`, before any resource existed, with a message specific enough that the developer fixes it without filing a ticket.

## Verification

```bash
gcloud storage buckets describe gs://cgep-lab-dev-dev-data-001 \
  --format="yaml(uniform_bucket_level_access,public_access_prevention,labels,retention_policy)"

gcloud storage buckets describe gs://cgep-lab-dev-dev-data-001 \
  --format="value(default_kms_key,versioning_enabled)"

gcloud kms keys describe dev-data-001-key \
  --keyring=dev-data-001-ring --location=us-central1 \
  --format="value(rotationPeriod,nextRotationTime)"
```

Expected, abridged:

```
labels:
  compliance_scope: cge-p-lab
  environment: dev
  managed_by: terraform
  project: cgep-lab
public_access_prevention: enforced
retention_policy:
  retentionPeriod: '2592000'
uniform_bucket_level_access: true

projects/.../keyRings/dev-data-001-ring/cryptoKeys/dev-data-001-key  True

7776000s   2026-07-24T...
```

Six controls, three commands.

## Portfolio submission checklist

- [ ] `terraform/modules/compliant-gcs-bucket/{main.tf,variables.tf,outputs.tf,README.md}` committed.
- [ ] `terraform/primitives/compliant-gcs/` (one consumer) committed.
- [ ] Module `README.md` lists each control by NIST family: SC-12, SC-13, SC-28, AU-11, CM-6.
- [ ] `evidence/lab-2-4/plan.json` (output of `terraform show -json tfplan`).
- [ ] One consumer applied at least once; `terraform output -json compliance_attestation` saved.

## Troubleshooting

- **`KMS_RESOURCE_NOT_FOUND_IN_LOCATION`** when `var.location` is `US`. KMS keyrings need a single-region location (`us-central1`, `europe-west4`, etc.). Buckets accept multi-region. The two-variable split in the module above is the fix.
- **`Permission cloudkms.cryptoKeyEncrypterDecrypter denied`** during bucket creation. The GCS service account on the project must have encrypt/decrypt rights on the key. The `google_kms_crypto_key_iam_member` in the module handles it; the `depends_on` on the bucket sequences it. If you split this resource out, keep the dependency.
- **Bucket retention policy cannot be shortened after creation.** It can only be lengthened or removed entirely. Choose retention thoughtfully, especially for prod.
- **`googleapi: Error 409: ... already exists`** on bucket name. Bucket names are globally unique across GCP. Change `bucket_name_suffix`.
- **`reauth related error (invalid_rapt)`** from the google provider. Run `gcloud auth application-default login` again. ADC tokens expire and Terraform won't auto-refresh them.

## Cleanup

```bash
cd consumers/dev
terraform destroy -auto-approve
```

Two notes:

1. The bucket's `retention_policy.is_locked` is `false` in this module. If you ever set it to `true`, you cannot destroy the bucket until the retention period expires.
2. KMS crypto keys are not truly deleted by `terraform destroy`. They enter a 30-day soft-delete state where they can still be restored. The keyring object stays around indefinitely (it cannot be deleted; it's free). For a 30-day-clean account, this is fine.

A real test pass on dev with `retention_days = 30` destroys cleanly in about 5 seconds with 4 resources removed.

## How this feeds the capstone

Modules are how the capstone's IaC layer scales without losing the security floor. The capstone's evidence vault, workload buckets, and any other GCS storage you stand up reuse this module so the compliance floor is enforced once. In Ch 3 you'll write Rego policies that read the `compliance_attestation` output and refuse to merge a plan that can't produce it. In Ch 6 the OSCAL component for "compliant-gcs-bucket-v1" cites this module's path as its implementation, and the attestation JSON as its evidence link.

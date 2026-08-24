# Lab 2.4: Terraform Modules for Compliance (GCP)

In Lab 2.3 you built one bucket on AWS. This lab builds a *pattern* on GCP. The shift is worth naming up front, because it's the whole point: you stop deploying buckets and start deploying a **module** that deploys buckets, with the security baseline locked inside the module where the people using it can't switch it off.

For the GRC folks, this is the moment the "policy" stops being a document and becomes a thing that enforces itself. For the technical folks, this is ordinary module composition, with the twist that the module's job is compliance rather than convenience. You'll write one module and call it twice, once for a dev environment and once for prod, and watch the same controls hold under different business settings.

## Before you begin

If this is your first lab, work through [Set up your tools](../getting-started/tools.md) and [Set up your repo](../getting-started/repo-structure.md) first. They establish the `cgep-labs` repository and the tooling every lab uses. The rest of this guide assumes that's in place.

This lab runs on **Google Cloud**, so it needs one tool you haven't used yet and a little auth setup:

- **Google Cloud CLI (`gcloud`)**, the GCP equivalent of the AWS CLI. Install it from the official page: https://cloud.google.com/sdk/docs/install
- A **GCP project** you control, with billing enabled. Substitute your project ID wherever you see `your-gcp-project`.
- The Cloud KMS API turned on: `gcloud services enable cloudkms.googleapis.com`
- Roles `roles/storage.admin` and `roles/cloudkms.admin` on the project.
- Terraform `>= 1.6` (you already have this from Lab 2.3).

### One gcloud quirk that trips everyone up: ADC

`gcloud` actually has two separate logins, and Terraform cares about the second one.

```bash
gcloud auth login                      # logs YOU in, for running gcloud commands
gcloud auth application-default login  # logs in Application Default Credentials, which TERRAFORM uses
```

If you only run the first, your `gcloud` commands will work but Terraform will fail to authenticate, which is a confusing error the first time you hit it. Run both. The second one is what Terraform's Google provider reads.

## Time and cost

- Time: 45 to 60 minutes.
- Cost: KMS keys cost about $0.06 per active key version per month. If you destroy the same day, you pay a fraction of a cent. The bucket is free while empty.

## What you're building, and the controls behind it

The module produces, in one unit, a KMS keyring, a customer-managed encryption key that rotates on a schedule, an IAM binding so the storage service can use that key, and a bucket that's hardened by default. Two consumers (dev and prod) call the module with different business settings and inherit the identical security posture.

| Control | What it means in plain terms | Where the module enforces it |
|---|---|---|
| **SC-12** | You establish and own the encryption key, rather than letting the provider hold it. | `google_kms_key_ring` + `google_kms_crypto_key` |
| **SC-13 / SC-28** | Data is encrypted at rest with that key (a CMEK), and the key rotates. | `encryption {}` block + `rotation_period` |
| **AC-3** | Access is uniform and the public can't reach the bucket. | `uniform_bucket_level_access` + `public_access_prevention` |
| **AU-11** | Records are retained for a set period. | `retention_policy` |
| **CM-6** | Required labels are present and can't be dropped. | merged `labels` |

```
                          consumer: dev                consumer: prod
                                │                            │
                                ▼                            ▼
                  ┌──────────────────────────────────────────────┐
                  │        module: compliant-gcs-bucket           │
                  │   KMS keyring ─▶ crypto key (rotates, SC-12/13)│
                  │                      │ encrypter              │
                  │                      ▼                        │
                  │            hardened GCS bucket                 │
                  │   uniform access · CMEK · versioning ·        │
                  │   retention · required labels · public block  │
                  └──────────────────────────────────────────────┘
```

## Where these files live

The module is a reusable template, so it goes under `terraform/modules/`. The consumers are things you actually deploy, so they're primitives under `terraform/primitives/`.

```
cgep-labs/
├── terraform/
│   ├── modules/
│   │   └── compliant-gcs-bucket/   ← the module (the security floor)
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       ├── outputs.tf
│   │       └── README.md
│   └── primitives/
│       ├── compliant-gcs/          ← consumer: dev (you apply this)
│       │   └── main.tf
│       ├── compliant-gcs-prod/     ← consumer: prod (you only plan this)
│       │   └── main.tf
│       └── compliant-gcs-negative/ ← the validation-failure demo (plan only)
│           └── main.tf
└── evidence/lab-2-4/               ← filled in when you capture evidence
```

The module and the consumers are separated so the distinction stays visible. A consumer is a few lines of business config. The module is where the controls live.

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p \
  terraform/modules/compliant-gcs-bucket \
  terraform/primitives/compliant-gcs \
  terraform/primitives/compliant-gcs-prod \
  terraform/primitives/compliant-gcs-negative \
  evidence/lab-2-4

touch \
  terraform/modules/compliant-gcs-bucket/main.tf \
  terraform/modules/compliant-gcs-bucket/variables.tf \
  terraform/modules/compliant-gcs-bucket/outputs.tf \
  terraform/modules/compliant-gcs-bucket/README.md \
  terraform/primitives/compliant-gcs/main.tf \
  terraform/primitives/compliant-gcs-prod/main.tf \
  terraform/primitives/compliant-gcs-negative/main.tf

find terraform/modules/compliant-gcs-bucket terraform/primitives/compliant-gcs* evidence/lab-2-4 -type f | sort
```

## Step-by-step walkthrough

### Concept: what a module actually is

A module is just a directory of Terraform with a clear interface: inputs (`variables.tf`), outputs (`outputs.tf`), and a body (`main.tf`). The body decides what's hardcoded. The interface decides what consumers are allowed to change. The compliance trick is to hardcode the security baseline in the body and expose only business settings through the interface. A consumer can choose the environment and the retention period; it cannot choose to turn off encryption, because that choice was never offered.

### Step 1: Fill in `terraform/modules/compliant-gcs-bucket/main.tf`

Open the empty **`terraform/modules/compliant-gcs-bucket/main.tf`** from the scaffold and paste:

```hcl
# terraform/modules/compliant-gcs-bucket/main.tf
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

The line doing the most compliance work is `effective_labels = merge(var.labels, local.required_labels)`. A consumer can pass in extra labels through `var.labels`, but the four required compliance labels are merged on *top*, so a consumer can add labels and cannot suppress the required ones. That asymmetry, add-but-not-remove, is the pattern you'll reuse every time you encode a control in a module.

### Step 2: Fill in `variables.tf` with validation

Open **`terraform/modules/compliant-gcs-bucket/variables.tf`**. The `validation` blocks here are compliance running at plan time. The most important one refuses to let a production bucket have a short retention, before any resource exists.

```hcl
# terraform/modules/compliant-gcs-bucket/variables.tf
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

> **Why two location variables.** GCS buckets accept multi-region names like `US` and `EU`. KMS keyrings do not; they need a single region like `us-central1`. If you set both to `US`, KMS rejects it with `KMS_RESOURCE_NOT_FOUND_IN_LOCATION`. Splitting them into two variables, both defaulting to `us-central1`, keeps that honest.

### Step 3: Fill in `outputs.tf` returning compliance evidence

Open **`terraform/modules/compliant-gcs-bucket/outputs.tf`**. Most of these outputs are identifiers. The interesting one is `compliance_attestation`, a computed map that states, in machine-readable form, exactly which controls this module enforced.

```hcl
# terraform/modules/compliant-gcs-bucket/outputs.tf
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

That `compliance_attestation` is the bridge to later labs. In Chapter 3 a Rego policy reads it and refuses to merge a plan that can't produce it. In Chapter 6 the OSCAL component for this module cites the JSON it ends up in as its evidence.

### Step 4: Write the dev consumer

Open **`terraform/primitives/compliant-gcs/main.tf`** (scaffolded earlier). This is the whole consumer.

```hcl
# terraform/primitives/compliant-gcs/main.tf
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
output "kms_key_id"  { value = module.data_bucket.kms_key_id }
```

The `source = "../../modules/compliant-gcs-bucket"` is a relative path: from `terraform/primitives/compliant-gcs/`, climb up to `primitives`, up to `terraform`, then into `modules`. Six lines of business config, and the module supplies twenty-plus controls behind them.

> **Use your own bucket suffix.** GCS bucket names are globally unique across all of Google Cloud, not just your project. If everyone in the cohort uses `dev-data-001`, the first person wins and everyone else gets `Error 409: ... already exists`. Change `bucket_name_suffix` to something unique to you, for example `dev-data-<your-initials>`. Use that same personal suffix everywhere this guide shows `dev-data-001`.

> **Module outputs vs consumer outputs.** This catches people out. The module defines an output called `compliance_attestation`. The consumer re-exposes it under a name *it* chooses, here `attestation`. So when you run `terraform output`, you ask for the consumer's name (`attestation`), not the module's internal name. They point at the same value; only the label differs depending on which directory you're standing in.

### Step 5: Write the prod consumer (plan only)

Open **`terraform/primitives/compliant-gcs-prod/main.tf`**. Paste the same provider block and outputs as the dev consumer, then use this module block — same security floor, different retention:

```hcl
# terraform/primitives/compliant-gcs-prod/main.tf  (module block; also include provider + outputs from Step 4)
module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "your-gcp-project"
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 365
  bucket_name_suffix = "prod-data-001"   # use your personal suffix, e.g. prod-data-<your-initials>
}
```

You'll only *plan* this one, not apply it. A 365-day retention lock is real, and you don't want a bucket you can't delete for a year sitting in a lab account.

### Step 6: Apply dev and read the attestation

If your Application Default Credentials have gone stale since you set them up, refresh them first with `gcloud auth application-default login`. Then:

```bash
# from the repo root
cd terraform/primitives/compliant-gcs
terraform init
terraform plan -out=tfplan
terraform apply -auto-approve tfplan
```

At the tail of the apply you'll see the attestation:

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

That block is the SC-12 / SC-13 / SC-28 / AC-3 / CM-6 / AU-11 attestation in machine-readable form. It came out of the system; nobody typed it by hand.

### Step 7: The negative test

This is the lesson of the lab, so don't skip it. Open **`terraform/primitives/compliant-gcs-negative/main.tf`**, paste the same provider and outputs as the dev consumer, and use this module block so prod gets a too-short retention. Then run plan from that folder:

```hcl
# terraform/primitives/compliant-gcs-negative/main.tf  (module block; also include provider + outputs from Step 4)
module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "your-gcp-project"
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 30   # FAILS: prod requires >= 365
  bucket_name_suffix = "should-never-exist"
}
```

```bash
cd terraform/primitives/compliant-gcs-negative
terraform init
terraform plan
cd ../../..   # back to the repo root
```

```
Error: Invalid value for variable

  var.environment is "prod"
  var.retention_days is 30

retention_days must be >= 365 when environment == "prod".

This was checked by the validation rule at variables.tf:49,3-13.
```

Sit with what just happened. The compliance check fired at `terraform plan`, before any resource existed, with a message specific enough that the developer fixes it themselves without filing a ticket or waiting for a review. That's the difference between compliance as a gate at the end and compliance built into the thing developers already run.

## Verify it from the outside

Pull the names from Terraform outputs so you don't have to copy-paste from the apply screen. From the repo root (or with `-chdir` as shown):

```bash
BUCKET_URL=$(terraform -chdir=terraform/primitives/compliant-gcs output -raw bucket_url)
KMS_KEY_ID=$(terraform -chdir=terraform/primitives/compliant-gcs output -raw kms_key_id)

gcloud storage buckets describe "$BUCKET_URL" \
  --format="yaml(uniform_bucket_level_access,public_access_prevention,labels,retention_policy)"

gcloud storage buckets describe "$BUCKET_URL" \
  --format="value(default_kms_key,versioning_enabled)"

# KMS_KEY_ID is a full resource name; gcloud accepts it as the key argument.
gcloud kms keys describe "$KMS_KEY_ID" \
  --format="value(rotationPeriod,nextRotationTime)"
```

If `gcloud kms keys describe` on your CLI build rejects the full resource name, split it into the older flags instead: `--location=us-central1 --keyring=<suffix>-ring` and the short key name `<suffix>-key`, using the same personal suffix you set in the consumer.

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

projects/.../locations/us-central1/keyRings/.../cryptoKeys/...  True

7776000s   2026-07-24T...
```

Six controls, three commands. Your bucket URL will include your personal suffix rather than `dev-data-001`.

## Capture your evidence

Capture the dev consumer's plan and attestation into the repo-root evidence folder for this lab. Use the *consumer* output name (`attestation`), not the module's internal name (`compliance_attestation`):

```bash
# from the repo root
mkdir -p evidence/lab-2-4
terraform -chdir=terraform/primitives/compliant-gcs show -json tfplan > evidence/lab-2-4/plan.json
terraform -chdir=terraform/primitives/compliant-gcs output -json attestation > evidence/lab-2-4/attestation.json
```

The second file is the same attestation you saw on screen, captured as the machine-readable artifact a policy will check later.

Before you commit, open **`terraform/modules/compliant-gcs-bucket/README.md`** (scaffolded empty) and write one short paragraph listing the controls the module enforces: SC-12, SC-13, SC-28, AU-11, CM-6, AC-3.

## Commit your work

```bash
# from the repo root
git add terraform/modules/compliant-gcs-bucket terraform/primitives/compliant-gcs* evidence/lab-2-4
git commit -m "Lab 2.4: compliant GCS module + consumers + evidence"
git push
```

## Cleanup: tear down the live resources

With your evidence captured and pushed, destroy the dev bucket so it doesn't linger. Your committed evidence stays in the repo.

```bash
cd terraform/primitives/compliant-gcs
terraform destroy -auto-approve
```

Two things to know:

1. The bucket's `retention_policy.is_locked` is `false` in this module, so it destroys cleanly. If you ever set it to `true`, you cannot destroy the bucket until the retention period expires. That's exactly why you never applied the prod consumer.
2. KMS crypto keys aren't truly deleted by `terraform destroy`; they enter a 30-day soft-delete state, and the keyring object stays around (it's free and can't be deleted). For a lab account this is fine. A clean dev pass destroys in about five seconds.

## Portfolio submission checklist

- [ ] `terraform/modules/compliant-gcs-bucket/{main.tf,variables.tf,outputs.tf,README.md}` committed. The `README.md` lists each control by family: SC-12, SC-13, SC-28, AU-11, CM-6.
- [ ] `terraform/primitives/compliant-gcs/` (the dev consumer) committed.
- [ ] `evidence/lab-2-4/plan.json` and `evidence/lab-2-4/attestation.json` committed.
- [ ] No `.terraform/` directory or `*.tfstate` files committed (your `.gitignore` handles this).
- [ ] Live resources destroyed once evidence was committed (`terraform destroy` ran clean).

## Troubleshooting

- **Terraform fails to authenticate to GCP.** You probably ran only `gcloud auth login`. Run `gcloud auth application-default login` too; that's the credential Terraform reads.
- **`KMS_RESOURCE_NOT_FOUND_IN_LOCATION`.** You set `var.location` to a multi-region like `US` and it flowed into the keyring. Keyrings need a single region. The two-variable split in the module is the fix; leave `kms_location` at `us-central1`.
- **`Permission cloudkms.cryptoKeyEncrypterDecrypter denied` during bucket creation.** The GCS service account needs encrypt/decrypt rights on the key. The `google_kms_crypto_key_iam_member` resource grants it and the bucket's `depends_on` sequences it. Don't remove either.
- **`Error 409: ... already exists` on the bucket.** Bucket names are globally unique. Change `bucket_name_suffix` to your personal suffix.
- **`reauth related error (invalid_rapt)`.** Your ADC token expired. Run `gcloud auth application-default login` again; Terraform won't refresh it for you.
- **Bucket retention can't be shortened.** A retention policy can only be lengthened or removed, never shortened, after creation. Choose carefully, especially for prod.

## How this feeds the rest of the course

Modules are how the capstone's infrastructure scales without losing its security floor. In the capstone you'll wrap your KMS and S3 hardening as a module so dev and prod consume the same baseline, exactly the discipline you practiced here. In Chapter 3 you'll write Rego that reads the `compliance_attestation` output and blocks a plan that can't produce it. In Chapter 6 the OSCAL component for "compliant-gcs-bucket" cites this module's path as its implementation and the attestation JSON as its evidence. One module, enforced once, cited everywhere.

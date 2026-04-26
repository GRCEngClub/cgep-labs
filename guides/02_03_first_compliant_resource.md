# Lab 2.3: Building Your First Compliant Resource (AWS S3)

You've spent enough time in spreadsheets pretending they're controls. This lab ends that. You'll write Terraform for a single S3 bucket that satisfies five NIST 800-53 controls, SC-28, AU-3, AU-6, CM-6, AC-3, and produce machine-readable evidence of every one. No screenshots.

## Learning objectives

- Express NIST 800-53 controls as Terraform resources, citing each control where it's enforced.
- Capture pre- and post-deploy compliance evidence as JSON instead of screenshots.
- Build a primitive that the rest of the CGE-P labs will reuse and verify automatically.

## Prerequisites

- AWS account with permissions to create S3 buckets in `us-east-1` (administrator-equivalent on a sandbox account is easiest).
- Terraform `>= 1.6` (`terraform version`).
- AWS CLI v2 with a working profile. This lab uses `--profile <your-sandbox>` and exports SSO credentials before running Terraform, adapt to your profile.
- 30–45 minutes of focus.

## Estimated time & cost

- Time: 30–45 min the first time, 10 min on repeats.
- Cost: under $0.01 if you destroy same-day. Empty S3 buckets have no idle cost. You'll pay fractions of a cent for the API calls Terraform makes.

## Architecture

One primary bucket holds your data. A separate log bucket receives S3 server access logs from the primary. Both buckets enforce the same baseline: AES-256 server-side encryption, versioning, full public access block, and the four required compliance tags.

```
                ┌──────────────────────────┐
   default_tags │  Project / Environment / │
   (provider)   │  ManagedBy / ComplianceScope
                └──────────────┬───────────┘
                               │
            ┌──────────────────┴───────────────────┐
            ▼                                      ▼
  ┌────────────────────┐               ┌─────────────────────┐
  │ aws_s3_bucket      │   logs (AU-3) │ aws_s3_bucket (log) │
  │ primary            │──────────────▶│ ACL: log-delivery   │
  │ AES256 (SC-28)     │               │ AES256              │
  │ versioning ON      │               │ public-block (AC-3) │
  │ public-block (AC-3)│               └─────────────────────┘
  └────────────────────┘
```

## Step-by-step walkthrough

### 5.1 Create the project structure

```bash
mkdir -p terraform/primitives/compliant-s3 && cd terraform/primitives/compliant-s3
touch main.tf variables.tf outputs.tf README.md
```

This is the directory shape every lab will reuse. By Ch 7 your capstone repo will have a dozen of these.

### 5.2 Write the base bucket + tags

Open `main.tf` and start with the provider configuration. The `default_tags` block makes the four required compliance tags non-optional, every taggable resource you create from this provider gets them automatically.

```hcl
# main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = "us-east-1"

  # CM-6: Configuration settings, required compliance tags applied to every
  # taggable resource by default. Removes the chance of forgetting them.
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  effective_suffix = var.bucket_suffix != "" ? var.bucket_suffix : random_id.bucket_suffix.hex
  primary_name     = "${var.project_name}-${var.environment}-data-${local.effective_suffix}"
  log_name         = "${var.project_name}-${var.environment}-logs-${local.effective_suffix}"
}

resource "aws_s3_bucket" "primary" {
  bucket = local.primary_name
}
```

Now `variables.tf`. Validation blocks turn typos into plan-time failures.

```hcl
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
```

### 5.3 Add encryption, versioning, public access block

Three resources, three controls.

```hcl
# main.tf (continued)

# SC-28: Protection of information at rest.
# AES-256 keeps this lab simple. The commented block below shows how you'd
# switch to KMS-managed keys, covered in a later lab.
resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }

  # KMS teaser:
  # rule {
  #   apply_server_side_encryption_by_default {
  #     sse_algorithm     = "aws:kms"
  #     kms_master_key_id = aws_kms_key.bucket.arn
  #   }
  #   bucket_key_enabled = true
  # }
}

# CM-6: Versioning preserves prior object states for recovery and audit.
resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

# AC-3: Access control, explicit deny on every public access vector.
resource "aws_s3_bucket_public_access_block" "primary" {
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

All four flags must be `true`. Three is not enough. AWS treats them as independent doors.

### 5.4 Add the log bucket and wire up access logging

The log bucket needs its own encryption and public-access-block, plus an ACL allowing the S3 log delivery group to write into it. Define it before the `aws_s3_bucket_logging` that points at it.

```hcl
# main.tf (continued)

# AU-3 / AU-6: Content of audit records + audit review.
resource "aws_s3_bucket" "log" {
  bucket = local.log_name
}

resource "aws_s3_bucket_ownership_controls" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "log" {
  depends_on = [aws_s3_bucket_ownership_controls.log]
  bucket     = aws_s3_bucket.log.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket                  = aws_s3_bucket.log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "primary" {
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "access-logs/"
}
```

Now `outputs.tf`. The `encryption_algorithm` output is a deliberate piece of evidence, it's the SC-28 attestation in machine-readable form.

```hcl
# outputs.tf
output "bucket_arn"     { value = aws_s3_bucket.primary.arn }
output "bucket_name"    { value = aws_s3_bucket.primary.id }
output "log_bucket_arn" { value = aws_s3_bucket.log.arn }

output "encryption_algorithm" {
  description = "Server-side encryption algorithm in effect (SC-28 attestation)."
  value = one([
    for rule in aws_s3_bucket_server_side_encryption_configuration.primary.rule :
    rule.apply_server_side_encryption_by_default[0].sse_algorithm
  ])
}
```

> **Why the `one(...)` expression:** Terraform represents the `rule` block of `aws_s3_bucket_server_side_encryption_configuration` as a *set*, not a list. Sets are not index-addressable. The `for` expression flattens the single rule into a list, then `one()` extracts the lone element, failing loudly if there's ever more than one. This is the kind of thing that catches you off-guard the first time and never again.

### 5.5 terraform init / plan / apply

If you're using AWS SSO, export your credentials so Terraform's AWS provider can use them:

```bash
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
```

Then run the standard cycle:

```bash
terraform init
terraform validate
terraform plan -out=tfplan
terraform apply -auto-approve tfplan
```

Expected tail of `apply`:

```
Apply complete! Resources: 11 added, 0 changed, 0 destroyed.

Outputs:

bucket_arn = "arn:aws:s3:::cgep-lab-dev-data-XXXXXXXX"
bucket_name = "cgep-lab-dev-data-XXXXXXXX"
encryption_algorithm = "AES256"
log_bucket_arn = "arn:aws:s3:::cgep-lab-dev-logs-XXXXXXXX"
```

Eleven resources, four outputs. Your bucket suffix will differ.

### 5.6 Capture evidence with `terraform show -json`

```bash
mkdir -p evidence
terraform show -json tfplan > evidence/plan.json
terraform show -json        > evidence/state.json
```

Open `evidence/state.json` and find your bucket. You'll see SC-28 (`server_side_encryption_configuration[].rule[].apply_server_side_encryption_by_default[].sse_algorithm = "AES256"`), AC-3 (`public_access_block`'s four `true`s), CM-6 (the four tags), AU-3 (`logging[].target_bucket`).

`terraform show -json` output IS machine-readable compliance evidence. No screenshots needed.

## Verification

Run these three commands. Substitute your bucket name (output of `terraform output -raw bucket_name`).

```bash
BUCKET=$(terraform output -raw bucket_name)

aws s3api get-bucket-encryption    --profile <your-sandbox> --bucket "$BUCKET"
aws s3api get-bucket-versioning    --profile <your-sandbox> --bucket "$BUCKET"
aws s3api get-public-access-block  --profile <your-sandbox> --bucket "$BUCKET"
```

Expected output (abridged):

```json
{ "ServerSideEncryptionConfiguration": { "Rules": [ {
    "ApplyServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" },
    "BucketKeyEnabled": false
} ] } }

{ "Status": "Enabled" }

{ "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true, "IgnorePublicAcls": true,
    "BlockPublicPolicy": true, "RestrictPublicBuckets": true
} }
```

If any of those three are missing or wrong, the bucket isn't compliant. Fix the Terraform, re-apply, re-verify.

## Portfolio submission checklist

Commit to your capstone repo:

- `terraform/primitives/compliant-s3/main.tf`
- `terraform/primitives/compliant-s3/variables.tf`
- `terraform/primitives/compliant-s3/outputs.tf`
- `terraform/primitives/compliant-s3/README.md`, one paragraph: "this module enforces SC-28, AU-3, AU-6, CM-6, AC-3 on a single S3 bucket."
- `evidence/lab-2-3/plan.json`
- `evidence/lab-2-3/state.json`

## Troubleshooting

- **`BucketAlreadyExists`**, S3 bucket names are globally unique. The `random_id` suffix should prevent this; if you set `bucket_suffix` manually, change it.
- **`AccessDenied` writing to the log bucket**, the log bucket needs the `log-delivery-write` ACL, which requires `aws_s3_bucket_ownership_controls` set to `BucketOwnerPreferred` *first*. The `depends_on` in the snippet above sequences this correctly.
- **`failed to find SSO session section`**, Terraform's AWS provider doesn't always parse SSO config the way the CLI does. Run `eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"` before Terraform commands.
- **Terraform state lock errors**, usually a leftover from an interrupted run. `terraform force-unlock <lock-id>` if you're sure no one else is applying.
- **Region mismatch**, your AWS profile may default to one region while the provider says `us-east-1`. The provider wins for resource creation, but `aws s3api` reads fall back to the profile region. Pass `--region us-east-1` to `aws s3api` if a verification check returns "NoSuchBucket".

## Cleanup

Versioned buckets can't be destroyed while they hold any object versions. Empty them first:

```bash
LOG_BUCKET=$(terraform output -raw log_bucket_arn | sed 's/.*:::\(.*\)/\1/')

# Empty the primary bucket (rare for it to have anything yet, but be safe)
aws s3 rm "s3://$(terraform output -raw bucket_name)" --recursive --profile <your-sandbox>

# The log bucket may have access-log objects. Empty all versions:
aws s3api list-object-versions --profile <your-sandbox> --bucket "$LOG_BUCKET" \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json \
  | aws s3api delete-objects --profile <your-sandbox> --bucket "$LOG_BUCKET" --delete file:///dev/stdin || true

terraform destroy -auto-approve
```

If you destroyed within a few minutes of applying, the log bucket is probably empty and the `delete-objects` call no-ops harmlessly.

## How this feeds the capstone

This is your first compliant primitive. By the end of the course you'll have a dozen.

- **Ch 3**, you'll write Rego policies that read this exact `plan.json` and prove each control is in place. The `state.json` becomes a continuous-evaluation input.
- **Ch 4**, the `terraform plan + show -json` ritual you ran by hand becomes a CI step. The `evidence/lab-2-3/` artifacts are the seed of the signed evidence bundles your pipeline will produce.
- **Ch 6**, you'll write an OSCAL Component Definition for this module. SC-28's `implemented-requirement` will point at the `evidence/lab-2-3/state.json` URI. An assessor reads the OSCAL, follows the link, sees the same JSON you just generated. The audit becomes a traversal.

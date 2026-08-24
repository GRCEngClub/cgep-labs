# Lab 5.2: AWS Security Services Baseline

So far your evidence has come from pull requests. But compliance doesn't stop when you stop pushing code. This lab stands up the AWS-native services that keep producing evidence continuously: CloudTrail records every action taken in your account, AWS Config records what each resource looked like over time, and Security Hub gathers findings from across the account into one normalized list mapped to NIST controls. Together they're the always-on backbone underneath the pipeline you built in Chapter 4.

For the GRC folks, these three services are where "continuous monitoring" stops being a phrase and starts being a JSON feed you can hand an auditor. For the technical folks, this is standing up account-level security tooling with Terraform, with the goal of producing evidence rather than dashboards.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first.

You need an AWS account where you have admin or near-admin rights, and Terraform `>= 1.6`. Check whether Security Hub is already on before you start, so you don't disturb an existing setup: `aws securityhub describe-hub --profile default`. Commands in this lab use `--profile default`; if you named your profile something else in Lab 2.3, replace `default` with that name.

This lab is self-contained: it deploys its own baseline and doesn't depend on any earlier lab's live resources.

## Time and cost: read this first

> **This lab costs real money.** Unlike every lab before it, the services here bill while they run. Read this before you apply.

- **CloudTrail:** management events are free, and this lab doesn't enable the paid data events.
- **Security Hub:** roughly $0.001 per security check per month. The NIST 800-53 standard is about 300 checks, so a quiet single-account lab is under $1/month, but a month of leaving it on with multiple standards is more like $5 to $8.
- **AWS Config:** about $2/month per recorder plus a tiny per-evaluation charge. This lab treats Config as optional, partly for cost and partly because org accounts often block it (more below).

If you destroy within an hour of applying, expect under $1 total. The single highest-impact thing you can do to stop ongoing cost is to unsubscribe the Security Hub standards, since Hub itself is free and the standards' checks are what bill. Budget 60 to 90 minutes, most of it waiting for findings to populate.

## Architecture

```
   CloudTrail (multi-region, mgmt events)  ─▶  S3 bucket (logs)
        AU-2 / AU-12 / AU-10 (log-file validation)

   AWS Config recorder ─▶ S3 bucket          (optional; an org SCP may block it)
        CM-2 / CM-6 / CM-8

   Security Hub (NIST 800-53 + FSBP)  ◀─ findings from Config, GuardDuty, native checks
        RA-5 / SI-4
```

## Why native baselines instead of a shiny vendor tool

Plenty of vendors will sell you a polished security console. CloudTrail, Config, and Security Hub are already inside the platform you're paying for, they're mapped to the same NIST controls an auditor will ask about, and they emit JSON you can pipe straight into the pipeline you already built. They aren't beautiful. They're durable, and they're the ones the assessor already trusts. For compliance evidence, durable wins.

## Step-by-step walkthrough

### Where these files live

Account-level baselines are conceptually distinct from the deployable primitives and reusable modules, so they get their own area:

```
cgep-labs/
├── terraform/
│   └── baselines/
│       └── aws/
│           ├── main.tf
│           ├── cloudtrail.tf
│           ├── security_hub.tf
│           ├── variables.tf
│           ├── outputs.tf
│           └── README.md
└── evidence/lab-5-2/
    └── security-hub-findings.json   ← filled in when you capture evidence
```

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p terraform/baselines/aws evidence/lab-5-2

touch \
  terraform/baselines/aws/main.tf \
  terraform/baselines/aws/cloudtrail.tf \
  terraform/baselines/aws/security_hub.tf \
  terraform/baselines/aws/variables.tf \
  terraform/baselines/aws/outputs.tf \
  terraform/baselines/aws/README.md

find terraform/baselines/aws evidence/lab-5-2 -type f | sort

# Most of the steps below edit files in this folder:
cd terraform/baselines/aws
ls
```

### Step 0: The connective scaffolding

The service files below reference a provider, a random suffix, and your account ID. Open **`terraform/baselines/aws/main.tf`** and **`terraform/baselines/aws/variables.tf`** first (the original lab assumed these; they're spelled out here so the baseline applies cleanly).

```hcl
# terraform/baselines/aws/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project         = "cgep-lab"
      Environment     = "baseline"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

data "aws_caller_identity" "current" {}
resource "random_id" "suffix" { byte_length = 4 }
```

```hcl
# terraform/baselines/aws/variables.tf
variable "aws_region" {
  type    = string
  default = "us-east-1"
}
```

### Step 1: CloudTrail

A multi-region trail with log-file validation. The bucket policy scopes the `aws:SourceArn` condition to exactly the trail you're about to create, which is the part people most often get wrong. Open **`terraform/baselines/aws/cloudtrail.tf`** and paste:

```hcl
# terraform/baselines/aws/cloudtrail.tf
resource "aws_s3_bucket" "trail" {
  bucket        = "cgep-lab-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

resource "aws_cloudtrail" "mgmt" {
  name                          = "cgep-lab-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}
```

The single most valuable line is `enable_log_file_validation = true`. It makes CloudTrail emit an hourly digest file signed by an AWS-managed key, which an auditor can use to detect after-the-fact tampering with the logs. That's AU-10, integrity of audit information, handed to you for free.

### Step 2: Security Hub

Subscribe to two standards: NIST 800-53 Rev 5 and AWS Foundational Security Best Practices. Subscribing is free; you pay per check. Open **`terraform/baselines/aws/security_hub.tf`** and paste:

```hcl
# terraform/baselines/aws/security_hub.tf
resource "aws_securityhub_account" "this" {}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}
```

If Security Hub is already enabled in the account, `apply` will fail with `ResourceConflictException`. Import the existing one instead of fighting it:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile default)
terraform import aws_securityhub_account.this "$ACCOUNT_ID"
```

### Step 3: AWS Config (optional, often blocked)

Config is the third service, but in org-managed accounts it's frequently centralized and blocked for member accounts by a service control policy that denies `config:*`. If you try to deploy a Config recorder and see:

```
AccessDeniedException: ... not authorized to perform: config:PutConfigurationRecorder
... with an explicit deny in a service control policy
```

then Config is managed elsewhere in your org, and you should leave it out of this lab. Here's the elegant part: when Config is missing, Security Hub raises a CRITICAL finding titled "AWS Config should be enabled and use the service-linked role for resource recording." That finding *is* evidence. Your account is reporting on its own gap, in machine-readable form, without you writing a word. For a GRC engineer, a system that documents its own deficiencies is exactly the goal.

### Step 4: Add outputs, then apply and wait

Open **`terraform/baselines/aws/outputs.tf`** so verify commands can pull names without copy-pasting:

```hcl
# terraform/baselines/aws/outputs.tf
output "trail_name" {
  value       = aws_cloudtrail.mgmt.name
  description = "CloudTrail name for verify commands."
}

output "trail_bucket" {
  value       = aws_s3_bucket.trail.id
  description = "S3 bucket receiving CloudTrail logs."
}

output "securityhub_account_id" {
  value       = aws_securityhub_account.this.id
  description = "Account ID Security Hub is enabled in (also the terraform import id)."
}
```

```bash
# you should already be in terraform/baselines/aws from the mkdir above
eval "$(aws configure export-credentials --profile default --format env)"
terraform init
terraform apply -auto-approve
```

Then wait 10 to 20 minutes. Security Hub populates its first findings slowly, so an empty result right after apply is normal, not a failure.

### Step 5: Verify

```bash
TRAIL=$(terraform output -raw trail_name)

aws cloudtrail get-trail-status --name "$TRAIL" --region us-east-1 \
  --profile default \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'
# Expect IsLogging: true

aws securityhub describe-hub --region us-east-1 --profile default --query HubArn
# Expect arn:aws:securityhub:us-east-1:ACCOUNT:hub/default

aws securityhub get-findings --region us-east-1 --profile default --max-results 5 \
  --query 'Findings[?Severity.Label==`CRITICAL`].{Title:Title,GeneratorId:GeneratorId}' \
  --output json
```

A freshly-deployed account typically shows somewhere between 1 and 50 findings within the first hour, mostly account-level controls like CloudTrail configuration, the root account, and the password policy. One of the first you'll likely see is the "AWS Config should be enabled" finding from Step 3.

### Step 6: Capture findings as evidence

```bash
# still inside terraform/baselines/aws — climb to the repo root's evidence folder
mkdir -p ../../../evidence/lab-5-2
aws securityhub get-findings --region us-east-1 --profile default --max-results 50 \
  > ../../../evidence/lab-5-2/security-hub-findings.json
```

This JSON is exactly the kind of artifact your Lab 4.4 signing step uploads to the vault. In Chapter 6 your OSCAL component points at a signed copy of a file like this as its evidence for continuous monitoring.

## Verification

- `aws cloudtrail get-trail-status` returns `"IsLogging": true`.
- `aws securityhub describe-hub` returns the hub ARN.
- At least one finding appears within 30 minutes.
- `evidence/lab-5-2/security-hub-findings.json` is captured and non-empty.

Before you commit, open **`terraform/baselines/aws/README.md`** (scaffolded empty) and map each service to its controls: AU-2/AU-12/AU-10 (CloudTrail), RA-5/SI-4 (Security Hub), CM-2/CM-6/CM-8 (Config, if present).

## Commit your work

```bash
# from the repo root
git add terraform/baselines/aws evidence/lab-5-2
git commit -m "Lab 5.2: AWS security services baseline + findings evidence"
git push
```

## Cleanup: tear down promptly to stop the bill

This is the lab where forgetting to clean up actually costs you, so do it the same day. Capture your evidence first (the commit above already did), then:

```bash
cd terraform/baselines/aws

# Optional: if you want to leave Security Hub enabled, drop it from state first.
# Otherwise skip this line and let destroy disable it.
# terraform state rm aws_securityhub_account.this

terraform destroy -auto-approve
```

The CloudTrail bucket holds the trail's own log objects; `force_destroy = true` lets Terraform empty and delete it. The standards subscriptions take about 15 seconds each to detach. If you only want to stop the cost without tearing everything down, unsubscribing the Security Hub standards is the high-impact move.

## Portfolio submission checklist

- [ ] `terraform/baselines/aws/` committed with `cloudtrail.tf`, `security_hub.tf`, `main.tf`, `variables.tf`, `outputs.tf`, `README.md` (and `config.tf` if your account allowed it).
- [ ] The README maps services to controls: AU-2/AU-12/AU-10 (CloudTrail), RA-5/SI-4 (Security Hub), CM-2/CM-6/CM-8 (Config).
- [ ] `evidence/lab-5-2/security-hub-findings.json` captured. If you signed it via the Lab 2.5 capture script, note the vault VersionId in the README.

## Troubleshooting

- **`InsufficientS3BucketPolicyException` on CloudTrail.** The bucket policy is missing the `aws:SourceArn` condition. Both statements above include it; keep them if you adapt the policy.
- **`ResourceConflictException: Account is already subscribed to Security Hub`.** Something enabled it first. Import with your account ID from `aws sts get-caller-identity` and re-apply.
- **`explicit deny in a service control policy` for Config.** Your account is org-managed and Config is centralized. Leave Config out; the Security Hub "Config should be enabled" finding is your evidence of the gap.
- **No findings after 30 minutes.** The first wave is batched. Confirm the subscriptions applied with `aws securityhub get-enabled-standards`.
- **Config recorder name conflict.** Only one recorder per region. Delete the existing one before re-applying.

## How this feeds the capstone

Your capstone's OSCAL component (Chapter 6) declares implemented requirements for AU-2, AU-9, AU-10, RA-5, and SI-4, and names CloudTrail and Security Hub as the implementation. The evidence link points at a signed copy of `security-hub-findings.json` in your vault. An assessor follows the chain from catalog to profile to component to evidence to verified bundle, never once logging into your AWS console. That's the continuous-monitoring half of the assurance story, and it's now standing up on its own.

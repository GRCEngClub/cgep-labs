# Lab 5.2: AWS Security Services Baseline

CloudTrail records what happened. Config records what the resource looked like. Security Hub aggregates findings into one normalized view. Together they're the AWS-native compliance backbone, the layer that keeps producing evidence after you stop pushing PRs. This lab stands them up via Terraform and captures the first wave of findings.

## Learning objectives

- Deploy a multi-region CloudTrail with log-file validation, mapped to AU-2, AU-12, AU-10.
- Enable Security Hub with the NIST 800-53 Rev 5 standard subscribed.
- Pull Security Hub findings as a JSON evidence artifact and route them into your audit trail.

## Prerequisites

- AWS account where you have admin or near-admin rights. Examples below use `--profile <your-sandbox>`; substitute yours.
- Terraform `>= 1.6`.
- The account has not already enabled Security Hub on a paid tier you don't want to disturb. Check with `aws securityhub describe-hub`.

## Estimated time & cost

THIS LAB COSTS REAL MONEY. Read this section before applying.

- CloudTrail: management events are free. We do not enable data events here.
- Security Hub: about $0.001 per security check per month. The NIST 800-53 standard runs ~300 checks. A single-account lab with no compute racks up under $1 per month.
- AWS Config: about $2 per month per recorder + $0.001 per rule evaluation. Many Security Hub controls require Config to be enabled to evaluate. The reference walkthrough in this lab does NOT deploy Config because it's blocked by an org-level SCP in the test account. The Terraform code for Config is included for learners who can deploy it.

If you destroy within an hour of applying, expect under $1 charged. Leaving Security Hub running for a month with NIST and FSBP standards in a single quiet account is on the order of $5-8.

## Architecture

```
   us-east-1 (and every other region)
   ──────────────────────────────────
   CloudTrail (multi-region, mgmt events) ─▶ S3 bucket (logs)
        AU-2 / AU-12 / AU-10 (file-validation)

   AWS Config recorder ─▶ S3 bucket (config items)        (optional: SCP may block)
        CM-2 / CM-6 / CM-8

   Security Hub (NIST 800-53 + FSBP) ◀─ findings from Config + GuardDuty + native checks
        RA-5 / SI-4
```

## Step-by-step walkthrough

### Concept: Why baseline services beat point tools

Every cloud security vendor will sell you a slick console. CloudTrail, Config, and Security Hub are inside the platform you're already paying for, mapped to the same NIST controls auditors ask about, and producing JSON you can pipe into your existing pipeline. They aren't pretty. They're durable. Pick the durable one.

### Step 1 CloudTrail

Multi-region, with log-file validation on (AU-10). The bucket policy must scope the `aws:SourceArn` condition to the trail you're about to create.

The CloudTrail snippet below references `random_id.suffix.hex`, `var.aws_region`, and `data.aws_caller_identity.current.account_id`. Wire those (and the provider) up first:

```hcl
# terraform/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}
```

```hcl
# terraform/variables.tf
variable "aws_region" {
  type    = string
  default = "us-east-1"
}
```

Then the CloudTrail resources:

```hcl
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

`enable_log_file_validation = true` makes CloudTrail emit a digest file every hour signed by an AWS-managed key. Your auditor can use it to detect tampering. That's AU-10 (integrity of audit information) for free.

### Step 2 Security Hub

Two standards subscribed: NIST 800-53 Rev 5 and AWS Foundational Security Best Practices. Both are free to subscribe to; you pay per security check.

```hcl
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

If Security Hub is already enabled in the account from a previous experiment or org baseline, terraform apply will hit `ResourceConflictException`. Import it instead:

```bash
terraform import aws_securityhub_account.this <ACCOUNT_ID>
```

### Step 3 AWS Config (may be SCP-blocked)

The reference Terraform includes a Config recorder + delivery channel + IAM role + bucket. Org-managed accounts often have an SCP like:

```
"Effect": "Deny", "Action": "config:*"
```

scoped to non-management accounts. If your `terraform apply` returns:

```
AccessDeniedException: User ... is not authorized to perform: config:PutConfigurationRecorder
on resource ... with an explicit deny in a service control policy
```

then Config is centrally managed in your org and the lab's Terraform should be commented out for now. The cleanest reference signal Security Hub gives you when Config is missing is a CRITICAL finding titled:

> "AWS Config should be enabled and use the service-linked role for resource recording"

That finding is its own evidence: your account is reporting on its own gap.

### Step 4 Apply and wait

```bash
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
terraform init
terraform apply -auto-approve
```

Wait 10 to 20 minutes. Security Hub findings populate slowly on first deploy.

### Step 5 Verify

```bash
aws cloudtrail get-trail-status --name cgep-lab-mgmt --region us-east-1 \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'
# Expect IsLogging: true

aws securityhub describe-hub --region us-east-1 --query HubArn
# Expect arn:aws:securityhub:us-east-1:ACCOUNT:hub/default

aws securityhub get-findings --region us-east-1 --max-results 5 \
  --query 'Findings[?Severity.Label==`CRITICAL`].{Title:Title,GeneratorId:GeneratorId}' \
  --output json
```

Reference run output (after Security Hub had been enabled for a few minutes):

```json
[
  {
    "Title": "AWS Config should be enabled and use the service-linked role for resource recording",
    "GeneratorId": "security-control/Config.1"
  }
]
```

In a freshly-deployed account, expect anywhere from 1 to ~50 findings within an hour. The first batch is mostly account-level controls (CloudTrail config, root account, password policy).

### Step 6 Capture findings as evidence

```bash
mkdir -p evidence/lab-5-2
aws securityhub get-findings --region us-east-1 --max-results 50 \
  > evidence/lab-5-2/security-hub-findings.json

wc -c evidence/lab-5-2/security-hub-findings.json
# 25KB or so for a small account
```

This file is what your Lab 4.4 capture-evidence step uploads to your vault. The capstone's OSCAL component points at signed copies of files like this for control statements about continuous monitoring.

## Verification

- `aws cloudtrail get-trail-status` returns `"IsLogging": true`.
- `aws securityhub describe-hub` returns the hub ARN.
- `aws securityhub get-findings` returns at least one finding within 30 minutes of enabling.
- `evidence/lab-5-2/security-hub-findings.json` is captured and non-empty.

## Portfolio submission checklist

- [ ] `terraform/baselines/aws/` directory committed with `cloudtrail.tf`, `security_hub.tf`, optionally `config.tf`, plus `main.tf`, `variables.tf`, `outputs.tf`, `README.md`.
- [ ] README explains which controls each service satisfies (AU-2/AU-12/AU-10 for CloudTrail, RA-5/SI-4 for Security Hub, CM-2/CM-6/CM-8 for Config).
- [ ] `evidence/lab-5-2/security-hub-findings.json` captured. If you signed it via Lab 2.5's `capture-evidence.sh`, note the vault VersionId in the README.

## Troubleshooting

- **`InsufficientS3BucketPolicyException`** on CloudTrail. The bucket policy is missing the `aws:SourceArn` condition. Both statements above include it; if you adapt them, keep it.
- **`ResourceConflictException: Account is already subscribed to Security Hub`**. Some other automation enabled it first. `terraform import aws_securityhub_account.this <ACCOUNT_ID>` and re-apply.
- **`AccessDeniedException ... explicit deny in a service control policy`** for Config. Your account is org-managed and Config is centralized. Comment out the Config resources in the lab's Terraform. The Security Hub finding "AWS Config should be enabled" is itself the evidence that this gap exists.
- **No findings after 30 minutes.** Security Hub batches the first wave. If you really see nothing, check that the standards subscriptions actually applied: `aws securityhub get-enabled-standards`.
- **Config recorder name conflict**. Only one recorder per region. If a previous deploy left one, delete the existing recorder before re-applying.

## Cleanup

```bash
# Capture evidence first.
aws securityhub get-findings --region us-east-1 --max-results 50 \
  > evidence/lab-5-2/security-hub-findings.json

# Detach Security Hub from terraform state if you want to keep it enabled.
terraform state rm aws_securityhub_account.this

# Destroy the rest (CloudTrail, S3 buckets, IAM, optional Config).
terraform destroy -auto-approve
```

CloudTrail's bucket has objects (the trail's own logs). `force_destroy = true` in the bucket resource lets terraform delete it. The standards subscriptions take ~15 seconds each to detach.

If you're worried about ongoing cost, the high-impact action is unsubscribing the Security Hub standards. Hub itself is free; the standards' security checks are what bill.

## How this feeds the capstone

Your capstone's OSCAL component (Lab 6.1) declares an `implemented-requirement` for AU-2, AU-9, AU-10, RA-5, and SI-4. The implementation statement names CloudTrail and Security Hub. The evidence URI points at a signed copy of `security-hub-findings.json` in your vault. An assessor follows the chain: catalog -> profile -> component -> evidence URI -> verified bundle. They don't have to log into your AWS console.

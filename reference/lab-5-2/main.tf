# Lab 5.2: AWS Security Services Baseline.
# CloudTrail (AU-2/AU-12) + Config (CM-2/CM-6/CM-8) + Security Hub (RA-5/SI-4).

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

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

resource "random_id" "suffix" { byte_length = 4 }

data "aws_caller_identity" "current" {}

locals {
  trail_bucket = "cgep-lab-cloudtrail-${random_id.suffix.hex}"
}

# ----- CloudTrail (AU-2 / AU-12 / AU-10) ------------------------------------

resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
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
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
    type = "Service"
    identifiers = ["cloudtrail.amazonaws.com"]
  }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
    type = "Service"
    identifiers = ["cloudtrail.amazonaws.com"]
  }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
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
  enable_log_file_validation    = true   # AU-10: integrity of audit records

  depends_on = [aws_s3_bucket_policy.trail]
}

# ----- Security Hub (RA-5 / SI-4) -------------------------------------------

resource "aws_securityhub_account" "this" {}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# ----- Outputs --------------------------------------------------------------

output "trail_name"   { value = aws_cloudtrail.mgmt.name }
output "trail_bucket" { value = aws_s3_bucket.trail.id }
output "hub_arn"      { value = aws_securityhub_account.this.arn }

# # ----- AWS Config (CM-2 / CM-6 / CM-8) --------------------------------------
# # Records resource configuration changes. Security Hub controls depend on it
# # for many NIST 800-53 evaluations.
#
# resource "aws_iam_role" "config" {
#   name = "cgep-lab-config-${random_id.suffix.hex}"
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [{
#       Effect    = "Allow"
#       Principal = { Service = "config.amazonaws.com" }
#       Action    = "sts:AssumeRole"
#     }]
#   })
# }
#
# resource "aws_iam_role_policy_attachment" "config_managed" {
#   role       = aws_iam_role.config.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
# }
#
# resource "aws_iam_role_policy" "config_s3" {
#   role = aws_iam_role.config.name
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect   = "Allow"
#         Action   = ["s3:PutObject", "s3:GetBucketAcl"]
#         Resource = ["${aws_s3_bucket.config.arn}", "${aws_s3_bucket.config.arn}/*"]
#       }
#     ]
#   })
# }
#
# resource "aws_s3_bucket" "config" {
#   bucket        = "cgep-lab-config-${random_id.suffix.hex}"
#   force_destroy = true
# }
#
# resource "aws_s3_bucket_public_access_block" "config" {
#   bucket                  = aws_s3_bucket.config.id
#   block_public_acls       = true
#   block_public_policy     = true
#   ignore_public_acls      = true
#   restrict_public_buckets = true
# }
#
# data "aws_iam_policy_document" "config_bucket" {
#   statement {
#     sid    = "AWSConfigBucketPermissions"
#     effect = "Allow"
#     principals {
#     type = "Service"
#     identifiers = ["config.amazonaws.com"]
#   }
#     actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
#     resources = [aws_s3_bucket.config.arn]
#   }
#   statement {
#     sid    = "AWSConfigBucketDelivery"
#     effect = "Allow"
#     principals {
#     type = "Service"
#     identifiers = ["config.amazonaws.com"]
#   }
#     actions   = ["s3:PutObject"]
#     resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
#     condition {
#       test     = "StringEquals"
#       variable = "s3:x-amz-acl"
#       values   = ["bucket-owner-full-control"]
#     }
#   }
# }
#
# resource "aws_s3_bucket_policy" "config" {
#   bucket = aws_s3_bucket.config.id
#   policy = data.aws_iam_policy_document.config_bucket.json
# }
#
# resource "aws_config_configuration_recorder" "this" {
#   name     = "cgep-lab-recorder"
#   role_arn = aws_iam_role.config.arn
#
#   recording_group {
#     all_supported                 = true
#     include_global_resource_types = true
#   }
# }
#
# resource "aws_config_delivery_channel" "this" {
#   name           = "cgep-lab-delivery"
#   s3_bucket_name = aws_s3_bucket.config.id
#   depends_on     = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.config]
# }
#
# resource "aws_config_configuration_recorder_status" "this" {
#   name       = aws_config_configuration_recorder.this.name
#   is_enabled = true
#   depends_on = [aws_config_delivery_channel.this]
# }
#
# output "config_bucket" { value = aws_s3_bucket.config.id }
#
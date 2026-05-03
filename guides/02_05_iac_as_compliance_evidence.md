# Lab 2.5: IaC as Compliance Evidence (AWS)

A reviewed, signed, immutably-stored Terraform commit is stronger evidence than a screenshot. This lab builds the vault that holds your evidence and the script that puts it there.

## Learning objectives

- Define chain of custody in terms of integrity, attribution, and reproducibility.
- Build an S3 Object Lock vault that refuses deletion by design.
- Capture a Terraform workspace's evidence files, hash them, bundle them, and upload to the vault with a recorded VersionId.

## Prerequisites

- Lab 2.3 completed with `evidence/plan.json` and the workspace still on disk. We use it as the workspace we capture from.
- AWS CLI v2 with a working profile (lab uses `--profile <your-sandbox>`).
- `sha256sum` or `shasum` on PATH.
- Terraform `>= 1.6`.
- Optional but recommended: Cosign installed for the signing add-on at the end.

## Estimated time & cost

- 45 minutes.
- Cost: Object Lock itself is free. You pay standard S3 storage rates on the bundles you upload, which for this lab will be a few KB. Under one cent if you destroy same-day.

## Architecture

The capture script reads from your Lab 2.3 workspace, hashes everything, tars it, and writes to a vault that does not allow deletion of objects within their retention window.

```
   Lab 2.3 workspace                capture-evidence.sh                 Object Lock vault
   ─────────────────                ───────────────────                 ─────────────────
   tfplan, terraform/      ──▶      collect plan.json,        ──▶      s3://VAULT/runs/RUN_ID/
   .tf files, git log               state.json, commit.txt             bundle.tar.gz
                                    version.txt; SHA-256                Retention: GOVERNANCE
                                    each; tar; aws put-object           or COMPLIANCE
                                                  │
                                                  ▼
                                       single-line JSON receipt
                                       (run_id, key, version_id)
```

## Step-by-step walkthrough

### Concept: Why code is evidence

A screenshot of an AWS console says "I once saw this." A Terraform plan committed to git, reviewed in a pull request, applied in CI, and stored in a vault that refuses deletion says "this is what was deployed, who reviewed it, when, and the artifact is unchanged since." Three properties auditors want: integrity, attribution, reproducibility. Code-as-evidence delivers all three. Screenshots deliver none.

### Step 1 Build the evidence vault

Object Lock has one critical constraint: it must be enabled at bucket creation. You cannot retrofit it. Start fresh.

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
  region = "us-east-1"
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = "evidence"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "suffix" { byte_length = 4 }

locals {
  vault_name = "${var.project_name}-grc-evidence-vault-${random_id.suffix.hex}"
}

resource "aws_s3_bucket" "vault" {
  bucket              = local.vault_name
  object_lock_enabled = true        # MUST be set at bucket creation
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }   # Object Lock requires versioning
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = var.lock_mode           # GOVERNANCE for labs, COMPLIANCE for production
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Refuse bucket deletion from anyone except the account root.
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = aws_s3_bucket.vault.arn
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}
```

```hcl
# terraform/variables.tf
variable "project_name" { type = string, default = "cgep-lab" }

variable "lock_mode" {
  type        = string
  description = "GOVERNANCE for lab work; COMPLIANCE for real evidence."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default retention applied to every uploaded object."
  default     = 1
}
```

```hcl
# terraform/outputs.tf
output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Feed this to capture-evidence.sh --vault."
}
```

> **GOVERNANCE vs COMPLIANCE.** GOVERNANCE retention can be bypassed by a privileged caller using `--bypass-governance-retention`. COMPLIANCE cannot be bypassed by anyone, including root, until the retention window expires. Use GOVERNANCE for lab work so you can clean up. Use COMPLIANCE for real evidence. The script and the rest of the pattern are identical either way.

### Step 2 Write `capture-evidence.sh`

A single bash script. Reads the workspace, builds a manifest, uploads, prints a JSON receipt to stdout that downstream pipelines can pipe.

```bash
#!/usr/bin/env bash
# scripts/capture-evidence.sh
# Usage:
#   capture-evidence.sh --workspace <path> --run-id <id> --vault <bucket> [--profile <p>]

set -euo pipefail

PROFILE_ARG=""
WORKSPACE=""
RUN_ID=""
VAULT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --run-id)    RUN_ID="$2";    shift 2 ;;
    --vault)     VAULT="$2";     shift 2 ;;
    --profile)   PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$VAULT" ]] && {
  echo "Usage: $0 --workspace <path> --run-id <id> --vault <bucket> [--profile <p>]" >&2
  exit 2
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_DIR="$WORK/bundle-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

( cd "$WORKSPACE" && [[ -f tfplan ]] && \
    terraform show -json tfplan > "$BUNDLE_DIR/plan.json" 2>/dev/null || true )
( cd "$WORKSPACE" && terraform state pull > "$BUNDLE_DIR/state.json" 2>/dev/null || true )
( cd "$WORKSPACE" && git log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null \
    || echo "no git commit available" > "$BUNDLE_DIR/commit.txt" )
terraform version > "$BUNDLE_DIR/version.txt"

# manifest.json: filename, sha256, size, captured_at_utc per file
{
  echo "["
  FIRST=1
  for f in "$BUNDLE_DIR"/*; do
    base=$(basename "$f")
    [[ "$base" == "manifest.json" ]] && continue
    HASH=$($SHASUM "$f" | awk '{print $1}')
    SIZE=$(wc -c < "$f" | tr -d ' ')
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$base" "$HASH" "$SIZE" "$CAPTURED_AT"
  done
  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

BUNDLE_TGZ="$WORK/bundle-$RUN_ID.tar.gz"
( cd "$WORK" && tar czf "$BUNDLE_TGZ" "bundle-$RUN_ID" )

KEY="runs/$RUN_ID/bundle.tar.gz"
UPLOAD_OUT=$(aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" --key "$KEY" --body "$BUNDLE_TGZ" --output json)
VERSION_ID=$(echo "$UPLOAD_OUT" | awk -F'"' '/"VersionId"/{print $4}')

printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","captured_at_utc":"%s"}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$CAPTURED_AT"
```

`set -euo pipefail` plus the `trap` handles partial-failure cleanup. The single-line JSON receipt at the end is what your CI pipeline captures and stores.

### Step 3 Run it against Lab 2.3's workspace

```bash
chmod +x scripts/capture-evidence.sh

eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
cd terraform && terraform init && terraform apply -auto-approve
VAULT=$(terraform output -raw vault_name)

cd ..  # back to lab-2-5 root
bash scripts/capture-evidence.sh \
  --workspace ../lab-2-3 \
  --run-id    test-001 \
  --vault     "$VAULT" \
  --profile   <your-sandbox>
```

Receipt:

```json
{"run_id":"test-001","vault":"cgep-lab-grc-evidence-vault-XXXXXXXX","key":"runs/test-001/bundle.tar.gz","version_id":"<base64-version-id>","captured_at_utc":"<iso-utc-timestamp>"}
```

The VersionId is the durable handle. Save it. Anything that points at this evidence in the future (your OSCAL component's evidence URI, for example) uses `s3://VAULT/KEY?versionId=...`.

### Step 4 Verify in S3

```bash
aws s3api get-object-retention \
  --bucket "$VAULT" --key runs/test-001/bundle.tar.gz --profile <your-sandbox>
```

Expected:

```json
{
  "Retention": {
    "Mode": "GOVERNANCE",
    "RetainUntilDate": "<retain-until-utc>"
  }
}
```

The retention date is set by the bucket's default rule, applied at upload. You did not have to set it explicitly.

### Step 5 The destructive test

This is the lesson. Try to delete the object you just uploaded.

```bash
aws s3api delete-object \
  --bucket "$VAULT" \
  --key runs/test-001/bundle.tar.gz \
  --version-id "<base64-version-id>" \
  --profile <your-sandbox>
```

You will see:

```
An error occurred (AccessDenied) when calling the DeleteObject operation:
Access Denied because object protected by object lock.
```

That message is the proof of immutability. A pipeline that uploads here, and an auditor who reads from here, both rely on this rejection. The lesson is not that S3 has a feature called Object Lock; the lesson is that your evidence is now resistant to silent tampering by an admin who would rather the evidence not exist.

### Step 6 Optional: sign the bundle with Cosign

Cosign keyless signing uses Sigstore's public Fulcio CA. From a laptop you authenticate via OIDC. From CI (Lab 4.4) the GitHub OIDC token flows automatically.

```bash
COSIGN_EXPERIMENTAL=1 cosign sign-blob \
  --yes --bundle bundle.sig.bundle \
  /tmp/bundle-test-001.tar.gz
aws s3 cp bundle.sig.bundle "s3://$VAULT/runs/test-001/bundle.sig.bundle" --profile <your-sandbox>
```

Verification (Lab 4.4 covers this end-to-end):

```bash
cosign verify-blob \
  --bundle bundle.sig.bundle \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  /tmp/bundle-test-001.tar.gz
```

## Verification

Three explicit checks that should all pass:

```bash
# Object Lock configured at the bucket level
aws s3api get-object-lock-configuration --bucket "$VAULT" --profile <your-sandbox>

# Retention on a specific uploaded object
aws s3api get-object-retention --bucket "$VAULT" --key runs/test-001/bundle.tar.gz --profile <your-sandbox>

# Deletion attempt fails
aws s3api delete-object --bucket "$VAULT" --key runs/test-001/bundle.tar.gz \
  --version-id "$VERSION_ID" --profile <your-sandbox>  # expect AccessDenied
```

## Portfolio submission checklist

- [ ] `terraform/primitives/evidence-vault/` deploys the vault as shown above
- [ ] `scripts/capture-evidence.sh` is committed and executable
- [ ] At least one bundle uploaded with its VersionId recorded in `evidence/lab-2-5/receipt.json`
- [ ] (Stretch) A Cosign signature file alongside the bundle in the vault

## Troubleshooting

- **`InvalidBucketState: Object Lock configuration cannot be enabled on existing buckets`**, Object Lock must be set at bucket creation. There is no upgrade path. Destroy and recreate.
- **`COMPLIANCE` mode and accidentally too long a retention**, you cannot shorten or remove the retention. The objects sit until they expire. For lab work, always start with `GOVERNANCE` + 1 day. Move to `COMPLIANCE` only when you intend the data to outlive you.
- **Clock drift**, RetainUntilDate is wall-clock UTC. If your laptop or CI runner has a wildly skewed clock, retention math will surprise you. Trust the server's date, not yours.
- **Cosign keyless from a laptop** requires a browser to complete the OIDC flow. Inside GitHub Actions it is automatic via `permissions: id-token: write`. Lab 4.4 covers the CI side.

## Cleanup

GOVERNANCE mode allows bypass with `--bypass-governance-retention`. Use it to delete the test object and any delete markers, then `terraform destroy`:

```bash
aws s3api delete-object --bucket "$VAULT" --key runs/test-001/bundle.tar.gz \
  --version-id "$VERSION_ID" --bypass-governance-retention --profile <your-sandbox>

# remove any delete markers
aws s3api list-object-versions --bucket "$VAULT" --output json --profile <your-sandbox> \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); items=[*d.get("Versions",[]),*d.get("DeleteMarkers",[])]; print(json.dumps({"Objects":[{"Key":o["Key"],"VersionId":o["VersionId"]} for o in items]}))' > /tmp/del.json
aws s3api delete-objects --bucket "$VAULT" --delete file:///tmp/del.json \
  --bypass-governance-retention --profile <your-sandbox> || true

terraform destroy -auto-approve
```

In COMPLIANCE mode you cannot do this. The bucket sits, with its objects, until every retention has expired. For real production evidence, that's the point. For a lab, GOVERNANCE is correct.

A real test pass on this lab destroys 7 resources cleanly in under five seconds.

## How this feeds the capstone

This vault IS the capstone's evidence vault. Every PR that closes one of the [`cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) gaps runs through Lab 4.3's pipeline, which calls Lab 4.4's signing step, which uploads to this vault using this exact pattern. Your Ch 6 OSCAL component's evidence links resolve to objects here. The grader downloads from here. Build it once, well.

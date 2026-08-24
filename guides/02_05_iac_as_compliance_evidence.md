# Lab 2.5: IaC as Compliance Evidence (AWS)

You've built compliant resources. This lab is about *proving* they were compliant, in a way that holds up months later when nobody remembers the deploy. You'll build a storage vault that physically refuses to let anything be deleted, and a script that captures a Terraform workspace's evidence, hashes it, and locks it away.

If Labs 2.3 and 2.4 were about building things correctly, this one is about making the record of that correctness tamper-resistant. For the GRC folks, this is chain of custody made literal. For the technical folks, this is S3 Object Lock plus a bash script, in service of a goal you may not have had to design for before: evidence an administrator can't quietly make disappear.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first.

This lab is on AWS, so you need:

- A working **AWS CLI** profile. Commands below use `--profile default`; if you named your profile something else in Lab 2.3, replace `default` with that name.
- `sha256sum` or `shasum` on your PATH. Git Bash ships `sha256sum`; macOS ships `shasum`. The script handles either.
- Terraform `>= 1.6`.
- Optional, for the signing step at the end: **Cosign**, from https://docs.sigstore.dev/cosign/system_config/installation/

> **Windows users, read this before you start the script.** Git Bash tries to convert anything that looks like a Unix path (a leading `/`) into a Windows path. The capture script and the cleanup commands below pass things that *look* like paths but aren't, such as `file:///dev/stdin` and S3 keys. If a command fails with a mangled-looking path, re-run it with `MSYS_NO_PATHCONV=1` in front. It's the single most common Windows snag in this lab.

## Time and cost

- Time: about 45 minutes.
- Cost: Object Lock itself is free. You pay standard S3 rates on the few kilobytes you upload, well under a cent if you destroy the same day.

## Why code is better evidence than a screenshot

A screenshot of the AWS console says "I once saw this." A Terraform plan committed to git, reviewed in a pull request, and stored in a vault that refuses deletion says something much stronger: this is what was deployed, here's who reviewed it and when, and the artifact hasn't changed since. Auditors care about three properties, and it's worth holding them in your head for the rest of the course:

- **Integrity:** the evidence hasn't been altered.
- **Attribution:** you can tell who produced it.
- **Reproducibility:** anyone can regenerate or re-verify it.

Code-as-evidence delivers all three. A screenshot delivers none. This lab builds the machinery that gives you all three automatically.

## Where these files live

```
cgep-labs/
├── terraform/
│   └── primitives/
│       └── evidence-vault/     ← the Object Lock vault (you build this here)
│           ├── main.tf
│           ├── variables.tf
│           └── outputs.tf
├── scripts/
│   └── capture-evidence.sh     ← the capture script (you write this here)
└── evidence/
    └── lab-2-5/
        └── receipt.json        ← the upload receipt you record
```

The vault you build in this lab is not a throwaway. It is the same evidence vault your capstone uses, so build it carefully.

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p terraform/primitives/evidence-vault scripts evidence/lab-2-5

touch \
  terraform/primitives/evidence-vault/main.tf \
  terraform/primitives/evidence-vault/variables.tf \
  terraform/primitives/evidence-vault/outputs.tf \
  scripts/capture-evidence.sh

chmod +x scripts/capture-evidence.sh

find terraform/primitives/evidence-vault scripts/capture-evidence.sh evidence/lab-2-5 | sort
```

## Step-by-step walkthrough

### Step 0: Stand up something to capture

This lab captures evidence *from* a live Terraform workspace. On a fresh day, the bucket you built in Lab 2.3 has been destroyed, so re-apply it now to give yourself a real workspace to capture from. You already have the code committed, so this is quick:

```bash
# from the repo root
cd terraform/primitives/compliant-s3
eval "$(aws configure export-credentials --profile default --format env)"  # if you use SSO
terraform init
terraform apply -auto-approve -var="project_name=cgep-lab" -var="environment=dev"
cd ../../..   # back to the repo root
```

Now there's a live, compliant workspace at `terraform/primitives/compliant-s3` with state on disk, which is exactly what the capture script needs.

### Step 1: Build the evidence vault

Object Lock has one hard rule: it must be enabled when the bucket is created. You cannot add it to an existing bucket. So this is a fresh bucket, built to be immutable from birth. Open the empty **`terraform/primitives/evidence-vault/main.tf`** from the scaffold and paste:

```hcl
# terraform/primitives/evidence-vault/main.tf
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

Open **`terraform/primitives/evidence-vault/variables.tf`** next:

```hcl
# terraform/primitives/evidence-vault/variables.tf
variable "project_name" {
  type    = string
  default = "cgep-lab"
}

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

Open **`terraform/primitives/evidence-vault/outputs.tf`**:

```hcl
# terraform/primitives/evidence-vault/outputs.tf
output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Feed this to capture-evidence.sh --vault."
}
```

> **GOVERNANCE vs COMPLIANCE, and why it matters for a lab.** In GOVERNANCE mode, a privileged caller can bypass retention with `--bypass-governance-retention`, which means you can clean up after the lab. In COMPLIANCE mode, nobody can delete a locked object until its retention expires, not even the account root. Use GOVERNANCE for lab work so you can tear down. Use COMPLIANCE when you mean it. The script and the rest of the pattern are identical either way, which is the point: you practice the real workflow and only the mode differs.

### Step 2: Write `capture-evidence.sh`

One bash script. It reads a workspace, builds a manifest of hashes, uploads a bundle to the vault, and prints a one-line JSON receipt that a pipeline can capture later. Open the empty **`scripts/capture-evidence.sh`** from the scaffold and paste:

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

BUNDLE_TGZ="/tmp/bundle-$RUN_ID.tar.gz"
( cd "$WORK" && tar czf "$BUNDLE_TGZ" "bundle-$RUN_ID" )

KEY="runs/$RUN_ID/bundle.tar.gz"
UPLOAD_OUT=$(aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" --key "$KEY" --body "$BUNDLE_TGZ" --output json)
VERSION_ID=$(echo "$UPLOAD_OUT" | awk -F'"' '/"VersionId"/{print $4}')

printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","captured_at_utc":"%s"}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$CAPTURED_AT"
```

You don't need to understand every line, but the shape is worth knowing. It collects the plan, the state, the git commit, and the Terraform version; it computes a SHA-256 of each so any later change is detectable; it tars them into one bundle; it uploads that bundle to the vault; and it prints a single-line JSON receipt with the `version_id` that uniquely identifies what it just stored. The `set -euo pipefail` and the `trap` at the top mean a partial failure cleans up after itself rather than leaving junk behind.

### Step 3: Run it against your Lab 2.3 workspace

Apply the vault, grab its name, then run the capture against the compliant-s3 workspace you re-applied in Step 0:

```bash
# from the repo root
cd terraform/primitives/evidence-vault
eval "$(aws configure export-credentials --profile default --format env)"
terraform init && terraform apply -auto-approve
VAULT=$(terraform output -raw vault_name)
cd ../../..   # back to the repo root

bash scripts/capture-evidence.sh \
  --workspace terraform/primitives/compliant-s3 \
  --run-id    test-001 \
  --vault     "$VAULT" \
  --profile   default
```

You'll get a receipt:

```json
{"run_id":"test-001","vault":"cgep-lab-grc-evidence-vault-XXXXXXXX","key":"runs/test-001/bundle.tar.gz","version_id":"<base64-version-id>","captured_at_utc":"<iso-utc-timestamp>"}
```

The `version_id` is the durable handle to this exact evidence. Save it. Anything that points at this evidence later, like your OSCAL component's evidence link in Chapter 6, references `s3://VAULT/KEY?versionId=...`. Write the whole receipt to your evidence folder:

```bash
mkdir -p evidence/lab-2-5
# paste the receipt line into the file, or capture it directly:
bash scripts/capture-evidence.sh \
  --workspace terraform/primitives/compliant-s3 \
  --run-id    test-001 \
  --vault     "$VAULT" \
  --profile   default > evidence/lab-2-5/receipt.json
```

### Step 4: Verify the retention took hold

```bash
aws s3api get-object-retention \
  --bucket "$VAULT" --key runs/test-001/bundle.tar.gz --profile default
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

You never set that retention by hand. The bucket's default rule applied it automatically at upload. That's the property you want in production: evidence is born protected, not protected as an afterthought someone might forget.

### Step 5: The destructive test

This is the moment the whole lab is built around, so do it deliberately. Try to delete the object you just uploaded:

```bash
# capture the current version's ID directly from S3, instead of copy-pasting it
VERSION_ID=$(aws s3api list-object-versions --bucket "$VAULT" \
  --prefix runs/test-001/bundle.tar.gz \
  --query "Versions[?IsLatest].VersionId | [0]" --output text --profile default)

aws s3api delete-object \
  --bucket "$VAULT" \
  --key runs/test-001/bundle.tar.gz \
  --version-id "$VERSION_ID" \
  --profile default
```

You will see:

```
An error occurred (AccessDenied) when calling the DeleteObject operation:
Access Denied because object protected by object lock.
```

That rejection is the proof. The lesson isn't that S3 has a feature called Object Lock; it's that your evidence is now resistant to silent tampering by an administrator who would prefer the evidence didn't exist. An auditor reading from this vault, and a pipeline writing to it, both depend on that "Access Denied." It's the technical fact underneath the words "chain of custody."

### Step 6 (optional): Sign the bundle with Cosign

If you installed Cosign, you can add a cryptographic signature. Keyless signing uses Sigstore's public infrastructure; from a laptop you authenticate through your browser, and in CI (Lab 4.4) a GitHub token does it automatically.

```bash
COSIGN_EXPERIMENTAL=1 cosign sign-blob \
  --yes --bundle bundle.sig.bundle \
  /tmp/bundle-test-001.tar.gz
aws s3 cp bundle.sig.bundle "s3://$VAULT/runs/test-001/bundle.sig.bundle" --profile default
```

Lab 4.4 covers verification end to end. For now, signing it is enough to see the shape.

## Capture and commit

The vault Terraform, the script, and the receipt all belong in the repo:

```bash
git add terraform/primitives/evidence-vault scripts/capture-evidence.sh evidence/lab-2-5
git commit -m "Lab 2.5: evidence vault + capture script + receipt"
git push
```

## Cleanup: tear down the live resources

Two things are live right now: the vault, and the Lab 2.3 workspace you re-applied in Step 0. Clean up both, in order, after your evidence is committed.

First, empty and destroy the vault. GOVERNANCE mode lets you bypass the lock to delete; in COMPLIANCE mode you could not, which is the whole point of COMPLIANCE.

```bash
cd terraform/primitives/evidence-vault

# capture the current version's ID directly from S3, instead of copy-pasting it
VERSION_ID=$(aws s3api list-object-versions --bucket "$VAULT" \
  --prefix runs/test-001/bundle.tar.gz \
  --query "Versions[?IsLatest].VersionId | [0]" --output text --profile default)

aws s3api delete-object --bucket "$VAULT" --key runs/test-001/bundle.tar.gz \
  --version-id "$VERSION_ID" --bypass-governance-retention --profile default

# remove any delete markers
aws s3api list-object-versions --bucket "$VAULT" --profile default \
  --query "[Versions[],DeleteMarkers[]][].{Key:Key,VersionId:VersionId}" --output text \
  | while read -r key version; do
      aws s3api delete-object --bucket "$VAULT" --key "$key" \
        --version-id "$version" --bypass-governance-retention --profile default
    done

terraform destroy -auto-approve
```

Then destroy the re-applied Lab 2.3 workspace so it isn't left running:

```bash
cd ../compliant-s3
# empty the buckets first (see Lab 2.3 cleanup), then:
terraform destroy -auto-approve
```

In COMPLIANCE mode none of this deletion would be possible; the vault would sit, with its objects, until every retention expired. For real production evidence, that's exactly what you want.

## Portfolio submission checklist

- [ ] `terraform/primitives/evidence-vault/` deploys the Object Lock vault.
- [ ] `scripts/capture-evidence.sh` is committed and executable.
- [ ] `evidence/lab-2-5/receipt.json` records at least one upload with its `version_id`.
- [ ] (Stretch) A Cosign signature file alongside the bundle in the vault.
- [ ] Both live workspaces (vault and re-applied compliant-s3) destroyed after evidence was committed.

## Troubleshooting

- **`InvalidBucketState: Object Lock configuration cannot be enabled on existing buckets`.** Object Lock must be set at creation. There's no upgrade path; destroy and recreate.
- **Accidentally used COMPLIANCE with a long retention.** You can't shorten or remove it. The objects sit until they expire. For lab work always start with GOVERNANCE and a 1-day retention.
- **Clock drift.** `RetainUntilDate` is wall-clock UTC. A badly skewed laptop or runner clock makes retention math surprising. Trust the server's date.
- **(Windows) a path-looking argument gets mangled.** Git Bash rewrote a `/`-leading value. Re-run with `MSYS_NO_PATHCONV=1` in front, especially for `file:///...` arguments.
- **`Need sha256sum or shasum`.** Neither hashing tool is on your PATH. Git Bash includes `sha256sum`; on macOS `shasum` is built in. Confirm with `command -v sha256sum`.
- **Cosign keyless from a laptop** needs a browser to complete the login. Inside GitHub Actions it's automatic. Lab 4.4 covers the CI side.

## How this feeds the rest of the course

This vault is the capstone's evidence vault, not a practice version of it. Every push to `main` in your capstone runs the pipeline from Chapter 4, which signs a bundle and uploads it here using this exact pattern. Your Chapter 6 OSCAL component's evidence links resolve to objects in this vault. The grader downloads from here and verifies the signature, recomputes the hash, and checks the retention. You built it once, in a lab, and it carries all the way to the finish line.

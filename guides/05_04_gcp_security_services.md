# Lab 5.4: GCP Security Services Baseline

This is the GCP counterpart to Lab 5.2, and the contrast is the lesson. Where AWS gives you an aggregator that *flags* problems after they happen, GCP leans on identity and prevention: Org Policy rejects a misconfigured resource at the moment of the API call, Workload Identity Federation replaces downloadable service-account keys with short-lived tokens, and Data Access logs record reads and writes once you turn them on. You'll set up all three for one project.

For the GRC folks, this is the difference between a detective control (catch it later) and a preventive one (it never happens). For the technical folks, this is GCP's identity-first security model, and you'll recognize WIF as the same OIDC pattern you wired into AWS in Lab 4.3, just on the other cloud.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first.

You need:

- A GCP project you own with billing on, and these APIs enabled: `cloudkms.googleapis.com`, `iam.googleapis.com`, `cloudresourcemanager.googleapis.com`, and `orgpolicy.googleapis.com`.
- Roles: `roles/orgpolicy.policyAdmin`, `roles/iam.workloadIdentityPoolAdmin`, `roles/logging.admin` (a project owner can grant these at project scope).
- `gcloud` authenticated both ways: `gcloud auth login` and `gcloud auth application-default login` (Terraform reads the second).
- Terraform `>= 1.6`.

Substitute your project ID for `your-gcp-project` and your GitHub repo (`<your-github-org>/cgep-labs`, or whichever repo will assume the WIF identity) wherever those placeholders appear. This lab is self-contained; it deploys its own baseline and depends on no earlier lab's live resources.

## Time and cost

- Time: 75 to 90 minutes, much of it waiting for Org Policy to propagate (5 to 10 minutes per change).
- Cost: Org Policy and WIF are free. Data Access logs cost about $0.50/GB ingested plus log storage, which is pennies on an empty project. Security Command Center Standard is free; Premium isn't used here.

## Architecture

```
   project (your-gcp-project)
   ─────────────────────────
   Org Policy (REJECT at the API call):
     storage.uniformBucketLevelAccess = TRUE      (CM-6)
     iam.disableServiceAccountKeyCreation = TRUE  (AC-2)
     compute.requireOsLogin = TRUE                (AC-3)

   Workload Identity Federation:
     pool + provider trusting GitHub's OIDC
     bound to one repo via attribute_condition
     mapped to a read-only service account

   Data Access audit logs (per service, off by default):
     storage / cloudkms / iam  →  DATA_READ + DATA_WRITE + ADMIN_READ
```

## Why identity-first

GCP's bet is that the smallest unit of security is the principal, not the resource. Org Policy enforces at the API, so a bucket creation that violates a constraint is rejected outright rather than flagged after the fact. WIF replaces the old "make a service account, download a JSON key, paste it into GitHub secrets, pray it never leaks" dance with "the workflow presents a short-lived OIDC token, GCP swaps it for a temporary access token, the token expires on its own." Together they make whole categories of attack simply not worth attempting.

## Step-by-step walkthrough

### Where these files live

```
cgep-labs/
├── terraform/baselines/gcp/
│   ├── main.tf
│   ├── org_policy.tf
│   ├── wif.tf          ← also holds the two outputs used in verify/demo
│   ├── audit_logs.tf
│   ├── variables.tf
│   └── README.md
└── evidence/lab-5-4/
    └── iam-policy.json   ← filled in when you capture evidence
```

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p terraform/baselines/gcp evidence/lab-5-4

touch \
  terraform/baselines/gcp/main.tf \
  terraform/baselines/gcp/org_policy.tf \
  terraform/baselines/gcp/wif.tf \
  terraform/baselines/gcp/audit_logs.tf \
  terraform/baselines/gcp/variables.tf \
  terraform/baselines/gcp/README.md

find terraform/baselines/gcp evidence/lab-5-4 -type f | sort

# Most of the steps below edit files in this folder:
cd terraform/baselines/gcp
ls
```

Open **`terraform/baselines/gcp/main.tf`** and **`terraform/baselines/gcp/variables.tf`** first — the snippets below assume these shared pieces:

```hcl
# terraform/baselines/gcp/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}
```

```hcl
# terraform/baselines/gcp/variables.tf
variable "gcp_project" { type = string }
variable "github_repo" {
  type        = string
  description = "OWNER/REPO that the WIF provider will trust."
}
```

### Step 1: Org Policy at project scope

Three constraints, each enforced (rejected) at the API. Open **`terraform/baselines/gcp/org_policy.tf`** and paste:

```hcl
# terraform/baselines/gcp/org_policy.tf
resource "google_org_policy_policy" "uniform_bucket_access" {
  name   = "projects/${var.gcp_project}/policies/storage.uniformBucketLevelAccess"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

resource "google_org_policy_policy" "disable_sa_keys" {
  name   = "projects/${var.gcp_project}/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

resource "google_org_policy_policy" "require_oslogin" {
  name   = "projects/${var.gcp_project}/policies/compute.requireOsLogin"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}
```

`enforce = "TRUE"` means rejection at the API. (If you wanted audit-only behavior without rejecting, you'd omit the rules block.)

### Step 2: Workload Identity Federation

Pool, provider, service account, binding. The `attribute_condition` is the line that matters most. Open **`terraform/baselines/gcp/wif.tf`**. Notice both the condition and the IAM binding read `var.github_repo` — set that once at apply time and you don't have to hunt for hardcoded repo strings:

```hcl
# terraform/baselines/gcp/wif.tf
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.actor"      = "assertion.actor"
  }

  attribute_condition = "assertion.repository == \"${var.github_repo}\""

  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

resource "google_service_account" "gha" {
  account_id   = "cgep-grc-gate-sa"
  display_name = "CGE-P GRC gate (read-only)"
}

resource "google_project_iam_member" "gha_viewer" {
  project = var.gcp_project
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.gha.email}"
}

resource "google_service_account_iam_binding" "wif_user" {
  service_account_id = google_service_account.gha.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}",
  ]
}

output "wif_service_account_email" {
  value       = google_service_account.gha.email
  description = "Service account email for the Org Policy key-creation demo and for GitHub Actions auth."
}

output "workload_identity_provider" {
  value       = google_iam_workload_identity_pool_provider.github.name
  description = "Full provider resource name for google-github-actions/auth."
}
```

> **Never loosen the condition.** `var.github_repo` must be your real `OWNER/REPO` (for lab work, your `cgep-labs` fork or the capstone repo you'll call from CI). Without a tight condition, *any* GitHub repository on the public internet could present a token and impersonate your service account. This single line is the GCP equivalent of the scoped `sub` you set in the AWS OIDC trust back in Lab 4.3.

A workflow then authenticates with no key on disk. After you apply, feed it the outputs rather than hand-building the resource names:

```yaml
permissions:
  id-token: write   # required to mint the OIDC token
  contents: read

steps:
  - uses: google-github-actions/auth@v2
    with:
      # terraform output -raw workload_identity_provider
      workload_identity_provider: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions/providers/github
      # terraform output -raw wif_service_account_email
      service_account: cgep-grc-gate-sa@your-gcp-project.iam.gserviceaccount.com

  - run: gcloud storage ls
```

The token is minted when the job starts, expires after an hour, and never touches the filesystem. Same posture as the AWS OIDC pattern, different cloud, which is exactly the portability a GRC engineer wants.

### Step 3: Enable Data Access audit logs

These are off by default, and that default is the single most common GCP audit finding, because almost nobody turns them on. Open **`terraform/baselines/gcp/audit_logs.tf`** and paste:

```hcl
# terraform/baselines/gcp/audit_logs.tf
resource "google_project_iam_audit_config" "storage" {
  project = var.gcp_project
  service = "storage.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

resource "google_project_iam_audit_config" "kms" {
  project = var.gcp_project
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

resource "google_project_iam_audit_config" "iam" {
  project = var.gcp_project
  service = "iam.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
```

### Step 4: Apply once, then test Org Policy enforcement

With `org_policy.tf`, `wif.tf`, and `audit_logs.tf` in place, apply the whole baseline. Refresh Application Default Credentials first if Terraform has started failing auth:

```bash
# from terraform/baselines/gcp
gcloud auth application-default login   # only if ADC is stale
terraform init
terraform apply -auto-approve \
  -var="gcp_project=your-gcp-project" \
  -var="github_repo=<your-github-org>/cgep-labs"

SA_EMAIL=$(terraform output -raw wif_service_account_email)
```

Give Org Policy a few minutes to propagate, then deliberately try to create a key on the service account you just created:

```bash
gcloud iam service-accounts keys create /tmp/key.json \
  --iam-account="$SA_EMAIL" --project=your-gcp-project
```

Expected:

```
ERROR: (gcloud.iam.service-accounts.keys.create) FAILED_PRECONDITION:
Key creation is not allowed on this service account.
constraint iam.disableServiceAccountKeyCreation
```

Sit with this for a moment, because it's the whole point of the lab. The control didn't surface three hours later as a finding to triage. The forbidden action simply did not happen. That refusal at the API is the strongest layer in defense-in-depth: there's nothing to remediate because there's nothing to remediate.

Optional: if you already have a GCS bucket in the project, list it and confirm a Data Access log shows up (delivery can take ~30 seconds):

```bash
gcloud storage ls gs://your-test-bucket
sleep 30
gcloud logging read 'protoPayload.serviceName="storage.googleapis.com" AND
  protoPayload.methodName=~"storage.objects.list"' --limit 5 --format=json
```

### Step 5: Security Command Center (only if you have an Org)

If your project sits in an Organization with Security Command Center on, findings flow in automatically. SCC Standard is free at the org level. This lab doesn't provision it (that needs org admin), but if you have it, dump findings as evidence:

```bash
gcloud scc findings list ORG_ID --source=- --format=json > ../../../evidence/lab-5-4/scc-findings.json
```

For a standalone project with no Org, SCC isn't available, and the Org Policy enforcements above are your equivalent preventive layer.

## Verification

```bash
# still inside terraform/baselines/gcp
gcloud org-policies list --project=your-gcp-project | grep -E "uniformBucket|disableServiceAccount|requireOsLogin"

gcloud iam workload-identity-pools list --location=global --project=your-gcp-project

# gcloud can project just the auditConfigs field — no Python required
mkdir -p ../../../evidence/lab-5-4
gcloud projects get-iam-policy your-gcp-project \
  --format="json(auditConfigs)" \
  > ../../../evidence/lab-5-4/iam-policy.json
cat ../../../evidence/lab-5-4/iam-policy.json

# the forbidden action should still fail
SA_EMAIL=$(terraform output -raw wif_service_account_email)
gcloud iam service-accounts keys create /tmp/k.json \
  --iam-account="$SA_EMAIL" \
  --project=your-gcp-project
# Expect: FAILED_PRECONDITION
```

Before you commit, open **`terraform/baselines/gcp/README.md`** (scaffolded empty) and note the "Data Access logs are off by default" lesson plus which Org Policy constraints you enforced.

## Commit your work

```bash
# from the repo root
git add terraform/baselines/gcp evidence/lab-5-4
git commit -m "Lab 5.4: GCP security baseline (org policy, WIF, data access logs)"
git push
```

## Cleanup

```bash
cd terraform/baselines/gcp
terraform destroy -auto-approve \
  -var="gcp_project=your-gcp-project" \
  -var="github_repo=<your-github-org>/cgep-labs"
```

Two things to know:

1. WIF pools enter a 30-day soft-delete. You can't recreate one with the same `workload_identity_pool_id` until that expires (or you `undelete` and then delete with `--purge`).
2. Turning off Org Policy enforcement doesn't retroactively change resources you already created. A bucket made with uniform access stays that way; the policy just stops blocking new violations.

## Portfolio submission checklist

- [ ] `terraform/baselines/gcp/` committed (split files or one `main.tf`).
- [ ] A demo GitHub Actions workflow that authenticates via WIF, with no service-account JSON key anywhere in the repo.
- [ ] `evidence/lab-5-4/iam-policy.json` capturing the Data Access logs config.
- [ ] README notes the "Data Access logs are off by default" lesson.

## Troubleshooting

- **Org Policy propagation latency.** First-apply changes can take 5 to 10 minutes. A forbidden action attempted immediately after apply may briefly slip through; wait, then test.
- **`PERMISSION_DENIED` creating the WIF provider.** You need `roles/iam.workloadIdentityPoolAdmin`, which `Owner` alone doesn't include.
- **WIF condition mismatch.** `assertion.repository` is the literal `OWNER/REPO`. Case, spelling, and the slash all matter. An opaque `PERMISSION_DENIED` from `auth@v2` usually means the condition doesn't match your repo.
- **Data Access log cost.** A busy project can ingest gigabytes a day. Start with `storage.googleapis.com` only before enabling KMS and IAM.
- **`policySpec is not supported`.** Enable the v2 Org Policy API: `gcloud services enable orgpolicy.googleapis.com`.

## How this feeds the capstone

WIF is your key-free pattern for any capstone workflow that touches GCP; if the pipeline reaches into GCP, it uses WIF, never a downloaded key. The Org Policy enforcements sit *above* your Rego policies in the defense stack: Rego is detective (it catches a bad plan), Org Policy is preventive (it refuses the bad action). And the Data Access logs feed your OSCAL component's AU-2 statement, enabled per service, with the IAM policy JSON as the evidence behind it.

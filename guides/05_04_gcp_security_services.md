# Lab 5.4: GCP Security Services Baseline

GCP leads with identity and data. Where AWS gives you a flat IAM policy and a Security Hub aggregator, GCP gives you Org Policy that rejects misconfigurations at the API call, Workload Identity Federation that replaces service account keys with short-lived OIDC tokens, and Data Access logs that, deliberately, you have to turn on. This lab does all three for one project.

## Learning objectives

- Enforce Org Policy at the API so non-compliant resource creation is rejected before it exists.
- Replace long-lived service account keys with Workload Identity Federation for GitHub Actions.
- Enable Data Access audit logs for Cloud Storage, Cloud KMS, and IAM (off by default; this is the #1 GCP audit finding).

## Prerequisites

- A GCP project you own, with billing enabled and APIs `cloudkms.googleapis.com`, `iam.googleapis.com`, and `cloudresourcemanager.googleapis.com` enabled.
- Roles you need: `roles/orgpolicy.policyAdmin`, `roles/iam.workloadIdentityPoolAdmin`, `roles/logging.admin`. At project scope these can be granted by the project owner; at organization scope you need org-level rights.
- `gcloud` authenticated for both `gcloud auth login` (interactive) and `gcloud auth application-default login` (Terraform's google provider uses ADC).
- Terraform `>= 1.6`.

If your project sits inside an Organization and you want to apply Org Policy at the org or folder scope, the same resources below take a different `parent` value. The lab uses project scope so it works in any GCP environment.

## Estimated time & cost

- 75 to 90 minutes the first time, mostly waiting for Org Policy propagation (5-10 minutes per change).
- Cost: Org Policy is free. WIF is free. Data Access logs cost $0.50/GB ingested + Cloud Logging storage; for an empty project this is pennies. Security Command Center Standard is free; Premium is enterprise-priced and not used in this lab.

## Architecture

```
   project (your-gcp-project)
   ─────────────────────────
   Org Policy (project scope, REJECT at API):
     storage.uniformBucketLevelAccess = TRUE      (CM-6)
     iam.disableServiceAccountKeyCreation = TRUE  (AC-2)
     compute.requireOsLogin = TRUE                (AC-3)

   Workload Identity Federation:
     pool: github-actions
     provider: token.actions.githubusercontent.com
     attribute_condition: assertion.repository == "GRCEngClub/cgep-app-starter"
     service_account: cgep-grc-gate-sa@... (roles/viewer)

   Data Access audit logs (per service):
     storage.googleapis.com    DATA_READ + DATA_WRITE + ADMIN_READ
     cloudkms.googleapis.com   DATA_READ + DATA_WRITE + ADMIN_READ
     iam.googleapis.com        DATA_READ + DATA_WRITE + ADMIN_READ
```

## Step-by-step walkthrough

### Concept: Why identity-first

GCP's bet is that the smallest unit of security is the principal, not the resource. Org Policy enforces at the API call: a bucket creation attempt that violates `uniformBucketLevelAccess` is REJECTED, not flagged. WIF replaces "create a service account, download a JSON key, paste into GitHub Secrets, hope nobody leaks it" with "the GitHub Actions runtime presents an OIDC token, GCP swaps it for a short-lived access token, the token expires automatically." The two together make whole categories of attack uneconomical.

### Step 1 Org Policy at project scope

```hcl
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

`enforce = "TRUE"` is rejection at the API. To audit-only-without-rejection, omit the rules block; the policy is then in "inherited" state and only visible in the policy listing.

### Step 2 Test the enforcement

After apply, intentionally try to violate one:

```bash
gcloud iam service-accounts keys create /tmp/key.json \
  --iam-account=YOUR_SA_EMAIL --project=your-gcp-project
```

Expected response:

```
ERROR: (gcloud.iam.service-accounts.keys.create) FAILED_PRECONDITION:
Key creation is not allowed on this service account.
constraint iam.disableServiceAccountKeyCreation
```

This is the lesson. The control didn't fire after the fact in a Security Hub finding three hours later. The action didn't happen. That's defense-in-depth's strongest layer.

### Step 3 Workload Identity Federation

Pool, provider, service account, IAM binding. The `attribute_condition` is critical. Without it, ANY GitHub repo on the public internet can use this provider to impersonate your service account.

```hcl
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

  attribute_condition = "assertion.repository == \"GRCEngClub/cgep-app-starter\""

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
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/GRCEngClub/cgep-app-starter",
  ]
}
```

A GitHub Actions workflow then authenticates without keys:

```yaml
permissions:
  id-token: write   # required to mint the OIDC token
  contents: read

steps:
  - uses: google-github-actions/auth@v2
    with:
      workload_identity_provider: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions/providers/github
      service_account: cgep-grc-gate-sa@your-gcp-project.iam.gserviceaccount.com

  - run: gcloud storage ls
```

The token is minted at job start, expires after one hour, never lands on disk. Same security posture as the AWS OIDC pattern in Lab 4.3, different cloud.

### Step 4 Enable Data Access audit logs

Off by default. This is the most-cited GCP audit finding because nobody turns them on.

```hcl
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

Verify a read shows up:

```bash
gsutil ls gs://your-test-bucket
sleep 30  # log delivery latency
gcloud logging read 'protoPayload.serviceName="storage.googleapis.com" AND \
  protoPayload.methodName=~"storage.objects.list"' --limit 5 --format=json
```

### Step 5 Security Command Center

If your project sits in an Organization with Security Command Center enabled, findings flow in automatically. SCC Standard is free at the org level; Premium is enterprise-priced and not used here. The lab does not provision SCC because it requires org admin; if you have it, dump findings as evidence:

```bash
gcloud scc findings list ORG_ID --source=- --format=json > evidence/lab-5-4/scc-findings.json
```

For standalone projects without an Org, SCC is unavailable. The Org Policy enforcements above provide the equivalent preventative layer.

## Verification

```bash
# Org Policies in effect
gcloud org-policies list --project=your-gcp-project | grep -E "uniformBucket|disableServiceAccount|requireOsLogin"

# WIF pool exists
gcloud iam workload-identity-pools list --location=global --project=your-gcp-project

# Data Access logs enabled
gcloud projects get-iam-policy your-gcp-project --format=json \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get("auditConfigs",[]),indent=2))'

# Try a forbidden action
gcloud iam service-accounts keys create /tmp/k.json \
  --iam-account=cgep-grc-gate-sa@your-gcp-project.iam.gserviceaccount.com \
  --project=your-gcp-project
# Expect: FAILED_PRECONDITION
```

## Portfolio submission checklist

- [ ] `terraform/baselines/gcp/main.tf` (or split files) committed.
- [ ] At least one demo GitHub Actions workflow using WIF, no service account JSON keys anywhere.
- [ ] `evidence/lab-5-4/iam-policy.json` (output of `get-iam-policy`) capturing the Data Access logs config.
- [ ] README notes the "Data Access logs are off by default" lesson.

## Troubleshooting

- **Org Policy propagation latency.** First-apply changes can take 5-10 minutes to take effect at the API. A test that creates a forbidden bucket *immediately* after `terraform apply` may briefly succeed.
- **`PERMISSION_DENIED` on `google_iam_workload_identity_pool_provider`.** You need `roles/iam.workloadIdentityPoolAdmin` on the project, not just `Owner`.
- **WIF `attribute.repository` condition mismatch.** GitHub's `assertion.repository` is the `OWNER/REPO` literal. Spelling, case, and the slash all matter. If your workflow gets opaque `PERMISSION_DENIED` from `auth@v2`, the condition is wrong.
- **Data Access logs cost.** In a busy project these can ingest GBs/day. Start with a single service (`storage.googleapis.com`) before turning on KMS and IAM.
- **`google_org_policy_policy` requires the v2 Org Policy API.** Run `gcloud services enable orgpolicy.googleapis.com` if Terraform errors with `policySpec is not supported`.

## Cleanup

```bash
terraform destroy -auto-approve
```

Two notes:

1. WIF pools enter a 30-day soft-delete state. They cannot be re-created with the same `workload_identity_pool_id` until the soft-delete expires or you `gcloud iam workload-identity-pools undelete` and then delete again with `--purge`.
2. Disabling Org Policy enforcement does not retroactively un-enforce existing resources. Buckets you created with uniform access stay that way; the policy just stops blocking new ones.

## How this feeds the capstone

The WIF pattern from this lab is your AWS-OIDC equivalent for any GCP-touching workflow. If your capstone's pipeline reaches into GCP for any reason, it uses WIF, not keys. The Org Policy enforcements add a preventative layer above your Rego (which is detective). And the Data Access logs feed your OSCAL component's AU-2 implementation statement: enabled per-service, with the IAM policy JSON as evidence.

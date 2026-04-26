# Lab 3.3: Writing Compliance Policies in Rego (GCP)

You wrote Terraform that satisfies controls. Now you write the policy that proves a Terraform plan satisfies those controls before it ever applies. Three policies, three NIST 800-53 controls, one library that survives a cloud change.

## Learning objectives

- Author Rego policies with structured metadata that maps each rule to a NIST control.
- Write `_test.rego` fixtures that assert both passing and failing behavior.
- Run the suite against a real `terraform plan -json` output and watch the right resources fire.

## Prerequisites

- OPA installed (`opa version` reports `>= 0.60.0`).
- Terraform `>= 1.6` and the `google` provider authenticated against a GCP project (the lab's fixture creates GCS buckets and a firewall rule). Examples below use the placeholder `your-gcp-project`; substitute your project ID.
- Lab 2.3 or 2.4 completed (you should have seen `terraform show -json` output at least once).

## Estimated time & cost

- 60 to 75 minutes.
- Cost: free for this lab. We only generate `terraform plan` output. Nothing is applied.

## The three policies at a glance

| Control | File | Enforces |
|---|---|---|
| SC-28 | `policies/sc28_encryption.rego` | Every `google_storage_bucket` has an `encryption { default_kms_key_name }` block. |
| AC-3  | `policies/ac3_no_public.rego`   | Buckets have `uniform_bucket_level_access=true` and `public_access_prevention="enforced"`. Firewalls don't expose ports 22 or 3389 to `0.0.0.0/0`. |
| CM-6  | `policies/cm6_required_tags.rego` | Every taggable resource carries the four required labels: `project`, `environment`, `managed_by`, `compliance_scope`. |

Every deny message includes the resource address AND the NIST control ID. The developer fixes their own violation without filing a GRC ticket.

## Step-by-step walkthrough

### 5.1 Project structure

```bash
mkdir -p policies/tests terraform fixtures
```

### 5.2 The test bed

A small Terraform fixture with both compliant and non-compliant resources gives the policy suite something concrete to flag.

```hcl
# terraform/main.tf
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

variable "gcp_project" { type = string }

# A KMS key for the compliant buckets.
resource "google_kms_key_ring" "ring" {
  name     = "lab33-ring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name     = "lab33-key"
  key_ring = google_kms_key_ring.ring.id
}

# Compliant: CMEK, uniform access, all labels.
resource "google_storage_bucket" "good" {
  name                        = "${var.gcp_project}-lab33-good"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption { default_kms_key_name = google_kms_crypto_key.key.id }

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

# Non-compliant cases (each will trip exactly one policy).
resource "google_storage_bucket" "bad_no_cmek"   { /* same as good, no encryption block */ }
resource "google_storage_bucket" "bad_public"    { /* uniform_bucket_level_access = false */ }
resource "google_storage_bucket" "bad_no_labels" { /* no labels */ }

resource "google_compute_network" "demo" {
  name                    = "lab33-demo"
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "open_ssh" {
  name          = "lab33-open-ssh"
  network       = google_compute_network.demo.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow { protocol = "tcp", ports = ["22"] }
}
```

Generate `plan.json`:

```bash
cd terraform
terraform init
terraform plan -out=tfplan -var=gcp_project=your-gcp-project
terraform show -json tfplan > plan.json
```

You don't have to apply. The policies operate on `plan.json`.

### 5.3 SC-28: Encryption at Rest

```rego
# policies/sc28_encryption.rego
# METADATA
# title: SC-28 - Encryption at Rest (GCS)
# description: "Every google_storage_bucket must encrypt at rest with a customer-managed encryption key (CMEK)."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: "Add an encryption { default_kms_key_name = ... } block referencing a google_kms_crypto_key you control."
package compliance.sc28

import rego.v1

deny contains msg if {
	some resource in input.planned_values.root_module.resources
	resource.type == "google_storage_bucket"
	not has_cmek(resource)
	msg := sprintf(
		"[SC-28] %s: missing customer-managed encryption key. Remediation: add encryption { default_kms_key_name = ... }.",
		[resource.address],
	)
}

# The same logic for module-wrapped buckets (recurse into child_modules).
deny contains msg if {
	some child in input.planned_values.root_module.child_modules
	some resource in child.resources
	resource.type == "google_storage_bucket"
	not has_cmek(resource)
	msg := sprintf(
		"[SC-28] %s: missing customer-managed encryption key. Remediation: add encryption { default_kms_key_name = ... }.",
		[resource.address],
	)
}

has_cmek(resource) if {
	count(resource.values.encryption) > 0
	not empty_kms_key(resource.values.encryption[0])
}

empty_kms_key(enc) if enc.default_kms_key_name == ""
empty_kms_key(enc) if enc.default_kms_key_name == null
```

> **Why `has_cmek` checks the block, not the value.** At plan time, the KMS key resource ID is "(known after apply)" because Terraform hasn't created the key yet. The plan JSON omits unknown values entirely. We accept any non-empty `encryption` block as "configured", and only fail when the block is missing or holds an empty/null key name. This is the correct policy semantics: the developer wired CMEK, the value resolves at apply.

### 5.4 SC-28 tests

```rego
# policies/tests/sc28_encryption_test.rego
package compliance.sc28_test

import rego.v1
import data.compliance.sc28

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type": "google_storage_bucket",
	"values": {
		"name": "good",
		"encryption": [{"default_kms_key_name": "projects/x/locations/us/keyRings/r/cryptoKeys/k"}],
	},
}]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type": "google_storage_bucket",
	"values": {"name": "bad", "encryption": []},
}]}}}

test_compliant_passes if { count(sc28.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
	some msg in sc28.deny with input as noncompliant_input
	contains(msg, "SC-28")
	contains(msg, "google_storage_bucket.bad")
}
```

```bash
opa test -v policies/
```

Both tests pass. Move on.

### 5.5 AC-3: No public access

Two rule sets in one file: buckets and firewalls.

```rego
# policies/ac3_no_public.rego
# METADATA
# title: AC-3 - Access Enforcement (no public GCS or open firewall)
# description: "GCS buckets must enforce uniform_bucket_level_access AND public_access_prevention=enforced. Firewall rules must not allow 0.0.0.0/0 on management ports (22, 3389)."
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: "Set uniform_bucket_level_access = true, public_access_prevention = enforced. For firewalls, narrow source_ranges or remove the rule."
package compliance.ac3

import rego.v1

# --- Buckets --------------------------------------------------------

deny contains msg if {
	resource := bucket_resource[_]
	not bucket_locked_down(resource)
	msg := sprintf(
		"[AC-3] %s: bucket allows public access. Remediation: set uniform_bucket_level_access=true and public_access_prevention=\"enforced\".",
		[resource.address],
	)
}

bucket_resource contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "google_storage_bucket"
}

bucket_resource contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
	r.type == "google_storage_bucket"
}

bucket_locked_down(r) if {
	r.values.uniform_bucket_level_access == true
	r.values.public_access_prevention == "enforced"
}

# --- Firewalls ------------------------------------------------------

mgmt_port(p) if p == "22"
mgmt_port(p) if p == "3389"

public_range(s) if s == "0.0.0.0/0"
public_range(s) if s == "*"

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "google_compute_firewall"
	r.values.direction == "INGRESS"
	some src in r.values.source_ranges
	public_range(src)
	some allow in r.values.allow
	some port in allow.ports
	mgmt_port(port)
	msg := sprintf(
		"[AC-3] %s: management port %s open to %s. Remediation: narrow source_ranges or remove the rule.",
		[r.address, port, src],
	)
}
```

### 5.6 AC-3 tests

```rego
# policies/tests/ac3_no_public_test.rego
package compliance.ac3_test
import rego.v1
import data.compliance.ac3

compliant_bucket := {"planned_values":{"root_module":{"resources":[{
  "address":"google_storage_bucket.good", "type":"google_storage_bucket",
  "values":{"uniform_bucket_level_access":true,"public_access_prevention":"enforced"}}]}}}

public_bucket := {"planned_values":{"root_module":{"resources":[{
  "address":"google_storage_bucket.bad", "type":"google_storage_bucket",
  "values":{"uniform_bucket_level_access":false,"public_access_prevention":"inherited"}}]}}}

open_firewall := {"planned_values":{"root_module":{"resources":[{
  "address":"google_compute_firewall.open_ssh", "type":"google_compute_firewall",
  "values":{"direction":"INGRESS","source_ranges":["0.0.0.0/0"],
            "allow":[{"protocol":"tcp","ports":["22"]}]}}]}}}

test_compliant_bucket_passes if { count(ac3.deny) == 0 with input as compliant_bucket }

test_public_bucket_fails if {
	some msg in ac3.deny with input as public_bucket
	contains(msg, "AC-3")
}

test_open_management_port_fails if {
	some msg in ac3.deny with input as open_firewall
	contains(msg, "AC-3")
	contains(msg, "22")
}
```

### 5.7 CM-6: Required labels

This one uses set subtraction. Required labels are a set; the resource's labels are a set; the difference is what's missing.

```rego
# policies/cm6_required_tags.rego
# METADATA
# title: CM-6 - Configuration Settings (required compliance labels)
# description: "Every taggable resource must carry the four required labels: project, environment, managed_by, compliance_scope."
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: "Add the four required labels (project, environment, managed_by, compliance_scope) to the resource."
package compliance.cm6

import rego.v1

required := {"project", "environment", "managed_by", "compliance_scope"}

labelable_type(t) if t == "google_storage_bucket"
labelable_type(t) if t == "google_compute_instance"
labelable_type(t) if t == "google_compute_disk"

deny contains msg if {
	resource := all_resources[_]
	labelable_type(resource.type)
	provided := provided_labels(resource)
	missing := required - provided
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required labels %v. Remediation: add the missing labels to the resource.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

provided_labels(resource) := keys if {
	resource.values.labels
	keys := {k | resource.values.labels[k]}
}

provided_labels(resource) := set() if { not resource.values.labels }

sort_array(s) := sorted if { sorted := sort([x | some x in s]) }
```

CM-6 test:

```rego
# policies/tests/cm6_required_tags_test.rego
package compliance.cm6_test
import rego.v1
import data.compliance.cm6

complete := {"planned_values":{"root_module":{"resources":[{
  "address":"google_storage_bucket.good", "type":"google_storage_bucket",
  "values":{"labels":{"project":"x","environment":"dev","managed_by":"terraform","compliance_scope":"cge-p-lab"}}}]}}}

missing := {"planned_values":{"root_module":{"resources":[{
  "address":"google_storage_bucket.bad", "type":"google_storage_bucket",
  "values":{"labels":{"project":"x"}}}]}}}

no_labels := {"planned_values":{"root_module":{"resources":[{
  "address":"google_storage_bucket.naked", "type":"google_storage_bucket",
  "values":{}}]}}}

test_complete_passes  if { count(cm6.deny) == 0 with input as complete }
test_partial_fails    if { some msg in cm6.deny with input as missing;   contains(msg, "CM-6") }
test_no_labels_fail   if { some msg in cm6.deny with input as no_labels; contains(msg, "CM-6") }
```

### 5.8 Run the full library against the real plan

```bash
opa test -v policies/
# PASS: 8/8

opa eval -d policies -i terraform/plan.json data.compliance.sc28.deny --format=pretty
opa eval -d policies -i terraform/plan.json data.compliance.ac3.deny  --format=pretty
opa eval -d policies -i terraform/plan.json data.compliance.cm6.deny  --format=pretty
```

Expected:

```
[
  "[SC-28] google_storage_bucket.bad_no_cmek: missing customer-managed encryption key. Remediation: add encryption { default_kms_key_name = ... }."
]

[
  "[AC-3] google_compute_firewall.open_ssh: management port 22 open to 0.0.0.0/0. Remediation: narrow source_ranges or remove the rule.",
  "[AC-3] google_storage_bucket.bad_public: bucket allows public access. Remediation: set uniform_bucket_level_access=true and public_access_prevention=\"enforced\"."
]

[
  "[CM-6] google_storage_bucket.bad_no_labels: missing required labels [\"compliance_scope\", \"environment\", \"managed_by\", \"project\"]. Remediation: add the missing labels to the resource."
]
```

Each non-compliant resource is flagged exactly once by the right control. The good bucket is quiet.

### 5.9 Fix the broken Terraform, re-eval

Add the missing pieces to your fixture, regenerate `plan.json`, run the same evals. Every deny set is empty.

That's the full developer feedback loop in under a minute, no human reviewer required.

## Verification

- `opa test -v policies/` reports `PASS: 8/8`.
- Eval of each `data.compliance.<control>.deny` produces exactly the expected violations against `plan.json`.
- After fixing the fixture, all three deny sets are empty.

## Portfolio submission checklist

- [ ] `policies/` committed with three policies, each with a `# METADATA` block.
- [ ] `policies/tests/` committed with at least one passing fixture and one failing fixture per policy.
- [ ] `evidence/lab-3-3/opa-test-results.json` (output of `opa test --format=json policies/`).
- [ ] A `policies/README.md` listing each policy, its control, severity, and remediation.

## Troubleshooting

- **`rego_parse_error: yaml: ... mapping values are not allowed`** in METADATA: the YAML parser hates unquoted colons inside a value. Wrap `description:` and `remediation:` values in double quotes.
- **A passing fixture surprises you with a deny.** Plan JSON puts module-wrapped resources under `child_modules[]`, not `root_module.resources`. The rules above recurse; if you write your own, do the same.
- **`encryption: [{}]` for a CMEK-using bucket.** Terraform sets `default_kms_key_name` to "(known after apply)" at plan time and omits the key from JSON. Don't require the key to be a populated string in your `has_cmek` predicate; require the block to exist and not be explicitly empty.
- **Set subtraction `required - provided` returns the wrong type.** Both operands must be sets, not arrays. `provided_labels` returns a set comprehension `{k | resource.values.labels[k]}` exactly because of this.

## Cleanup

The fixture is plan-only. There's nothing deployed to destroy unless you ran `terraform apply` (which the lab does not require).

## How this feeds the capstone

Your capstone's policy suite starts here. The three rules in this lab cover the most common compliance gaps, but they are written against GCP resources. In Lab 3.4 you'll add AWS variants targeting `aws_s3_bucket` and friends, and run the combined suite through Conftest as the gate the GitHub Actions pipeline calls. Same library, every cloud, one set of control IDs in your OSCAL component.

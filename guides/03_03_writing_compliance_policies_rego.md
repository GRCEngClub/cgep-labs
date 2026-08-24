# Lab 3.3: Writing Compliance Policies in Rego (GCP)

Every lab so far has been about building infrastructure correctly. This one flips around: you write the thing that *checks* infrastructure, automatically, before it's ever built. You'll write three small policies that read a Terraform plan and refuse it if it violates a control, and you'll write tests that prove each policy catches what it's supposed to.

This is the heart of Policy as Code, and it's the moment a control stops being a sentence in a document and becomes a program that runs. For the GRC folks, you're encoding the rule you've always written in prose so a machine enforces it every time. For the technical folks, this is unit testing, except the thing under test is your infrastructure's compliance posture.

A heads-up: the language you'll write in, Rego, looks unfamiliar at first. It's worth pushing through the strangeness, because the payoff is a compliance check that runs in under a second with no human in the loop. There's a short "how to read Rego" primer below before you write any.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first.

New tool for this lab:

- **OPA (Open Policy Agent)**, the engine that runs Rego policies. Get it from the official docs at https://www.openpolicyagent.org/docs, or grab the binary directly from https://github.com/open-policy-agent/opa/releases.
  - macOS: `brew install opa`
  - Linux: download `opa_linux_amd64_static`, `chmod +x` it, move it onto your PATH as `opa`.
  - Windows (Git Bash): download `opa_windows_amd64.exe`, rename it `opa.exe`, and put it on your PATH.
  - Confirm with `opa version` (you want `>= 0.60.0`).

Also useful: a GCP project (the fixture creates plan-only GCS buckets and a firewall) and the fact that you've seen `terraform show -json` output back in Lab 2.3 or 2.4. Substitute your project ID for `your-gcp-project`.

## Time and cost

- Time: 60 to 75 minutes. It's a new language; give yourself room.
- Cost: free. You only ever generate a `terraform plan`. Nothing is applied.

## How to read a Rego rule (read this once)

A compliance policy in Rego is a set of `deny` rules. Each one says: add a message to the `deny` set when all of these conditions are true. Here's the shape, annotated:

```
deny contains msg if {        # "add msg to the deny set when..."
    some resource in input...  # ...there's a resource in the plan...
    resource.type == "..."     # ...of this type...           (these lines are ANDed)
    not has_cmek(resource)     # ...that fails this check...
    msg := sprintf("...", [..]) # ...and here's the message to record.
}
```

Three things to hold onto:

- **Every line in the block is an AND.** The rule only fires when all conditions hold. If any line is false, this rule produces nothing.
- **`input` is the Terraform plan**, parsed into JSON. `input.planned_values.root_module.resources` is the list of resources Terraform intends to create. You're querying that structure.
- **An empty `deny` set means "compliant."** No messages, no violations. The whole game is writing rules that stay quiet on good infrastructure and speak up on bad.

That's enough to read everything below. You'll pick up the rest by doing it.

## The three policies at a glance

| Control | File | What it requires |
|---|---|---|
| **SC-28** | `policies/sc28_encryption.rego` | Every bucket has a customer-managed encryption key. |
| **AC-3** | `policies/ac3_no_public.rego` | Buckets aren't public; firewalls don't open ports 22 or 3389 to the world. |
| **CM-6** | `policies/cm6_required_tags.rego` | Every taggable resource carries the four required labels. |

Every deny message names the resource *and* the NIST control. That's deliberate: a developer who sees `[SC-28] google_storage_bucket.bad_no_cmek: missing customer-managed encryption key` fixes it themselves, without a GRC ticket or a meeting.

## Where these files live

Policies live at the repo root in `policies/`, which is exactly where your capstone expects them. The throwaway test infrastructure goes in a primitive.

```
cgep-labs/
├── policies/
│   ├── sc28_encryption.rego
│   ├── ac3_no_public.rego
│   ├── cm6_required_tags.rego
│   ├── README.md
│   └── tests/
│       ├── sc28_encryption_test.rego
│       ├── ac3_no_public_test.rego
│       └── cm6_required_tags_test.rego
├── terraform/primitives/policy-fixture/   ← plan-only test bed
│   └── main.tf
└── evidence/lab-3-3/
    └── opa-test-results.json              ← filled in when you capture evidence
```

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates every path in the diagram above as an empty file so the later steps are "open and paste," not "guess where this goes."

```bash
# from the repo root
mkdir -p policies/tests terraform/primitives/policy-fixture evidence/lab-3-3

touch \
  policies/sc28_encryption.rego \
  policies/ac3_no_public.rego \
  policies/cm6_required_tags.rego \
  policies/README.md \
  policies/tests/sc28_encryption_test.rego \
  policies/tests/ac3_no_public_test.rego \
  policies/tests/cm6_required_tags_test.rego \
  terraform/primitives/policy-fixture/main.tf

find policies terraform/primitives/policy-fixture evidence/lab-3-3 -type f | sort
```

## Step-by-step walkthrough

### Step 1: Build the test bed

A policy needs something to check. This fixture has one compliant bucket and three broken ones, each broken in exactly one way, plus a firewall left wide open. Open **`terraform/primitives/policy-fixture/main.tf`** from the scaffold and paste:

> The original lab abbreviated the three non-compliant buckets as comments. They're written out in full here so the fixture actually plans.

```hcl
# terraform/primitives/policy-fixture/main.tf
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

# Non-compliant: no encryption block (trips SC-28).
resource "google_storage_bucket" "bad_no_cmek" {
  name                        = "${var.gcp_project}-lab33-bad-no-cmek"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels = {
    project = "lab33", environment = "dev"
    managed_by = "terraform", compliance_scope = "cge-p-lab"
  }
}

# Non-compliant: public access not locked down (trips AC-3).
resource "google_storage_bucket" "bad_public" {
  name                        = "${var.gcp_project}-lab33-bad-public"
  location                    = "us-central1"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
  encryption { default_kms_key_name = google_kms_crypto_key.key.id }
  labels = {
    project = "lab33", environment = "dev"
    managed_by = "terraform", compliance_scope = "cge-p-lab"
  }
}

# Non-compliant: no labels (trips CM-6).
resource "google_storage_bucket" "bad_no_labels" {
  name                        = "${var.gcp_project}-lab33-bad-no-labels"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  encryption { default_kms_key_name = google_kms_crypto_key.key.id }
}

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

Generate the plan JSON. This is the file your policies read. If Application Default Credentials are stale, refresh them with `gcloud auth application-default login` first:

```bash
# from the repo root
cd terraform/primitives/policy-fixture
terraform init
terraform plan -out=tfplan -var=gcp_project=your-gcp-project
terraform show -json tfplan > plan.json
cd ../../..
```

You never apply. The policies work entirely off `plan.json`, which is why this lab is free and fast.

### Step 2: SC-28, encryption at rest

Open **`policies/sc28_encryption.rego`** and paste:

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

That `# METADATA` block at the top is the GRC bridge in code form. It ties this rule to SC-28, names the framework and severity, and states the fix. Tools can read it, and so can an auditor. The policy isn't just a check; it's self-documenting evidence of which control it implements.

Two details that confuse everyone the first time:

- **There are two `deny` rules that look identical.** The first checks buckets declared at the top level; the second recurses into `child_modules`, because when a bucket comes from a module (like your Lab 2.4 module), Terraform nests it under `child_modules` in the plan JSON, not in the top-level resources. Miss this and your policy silently ignores every module-wrapped resource.
- **`has_cmek` checks that the block exists, not that the key has a value.** At plan time, the KMS key ID is often "known after apply," so the JSON omits it. Requiring a populated string would wrongly fail correct code. The rule accepts any non-empty `encryption` block and only fails when it's missing or explicitly empty. That's the right semantics: the developer wired CMEK; the value resolves when it applies.

### Step 3: SC-28 tests

Tests are how you trust a policy. Each one feeds in a hand-built input and asserts the rule does the right thing. Open **`policies/tests/sc28_encryption_test.rego`** and paste:

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

The `with input as ...` swaps in your fake plan so the rule runs against it. One test proves compliant infra stays quiet; the other proves bad infra gets flagged with the right control. A policy without both halves is a policy you can't trust.

### Step 4: AC-3, no public access

Two checks in one file: buckets that aren't locked down, and firewalls that open management ports to the world. Open **`policies/ac3_no_public.rego`** and paste:

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

The firewall rule reads like a sentence once you slow down: for an ingress firewall, if any source range is public and any allowed port is a management port, deny. Each `some ... in` walks a list; the whole block fires only when a public range and a management port coexist.

### Step 5: AC-3 tests

Open **`policies/tests/ac3_no_public_test.rego`** and paste:

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

### Step 6: CM-6, required labels

This one uses set subtraction. The required labels are a set, the resource's labels are a set, and whatever's left after subtracting is what's missing. Open **`policies/cm6_required_tags.rego`** and paste:

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

> **Why `provided_labels` returns a set, not an array.** Rego's `-` (subtraction) only works on two sets. The comprehension `{k | resource.values.labels[k]}` builds a set of the label keys precisely so `required - provided` gives you the missing ones. Swap it for an array and you'll get a type error that's baffling until you know this.

Open **`policies/tests/cm6_required_tags_test.rego`** and paste:

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

### Step 7: Run the whole library against the real plan

```bash
opa test -v policies/
# PASS: 8/8

opa eval -d policies -i terraform/primitives/policy-fixture/plan.json data.compliance.sc28.deny --format=pretty
opa eval -d policies -i terraform/primitives/policy-fixture/plan.json data.compliance.ac3.deny  --format=pretty
opa eval -d policies -i terraform/primitives/policy-fixture/plan.json data.compliance.cm6.deny  --format=pretty
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

Read that carefully: each broken bucket is flagged exactly once, by the right control, and the good bucket is silent. That's a policy library doing its job.

### Step 8: Fix the fixture, watch the denies vanish

Add the missing pieces (an `encryption` block to `bad_no_cmek`, lock down `bad_public`, labels to `bad_no_labels`), regenerate `plan.json`, and re-run the three evals. Every deny set comes back empty. That's the full developer feedback loop, start to finish, in under a minute and with no reviewer involved. That speed is the entire argument for Policy as Code.

When you're done with the demo, you can leave the fixture in either state. The unit tests in `policies/tests/` already prove each policy against hand-built inputs; the fixture plan is for the live walkthrough, not for grading.

Before you capture evidence, open **`policies/README.md`** (scaffolded empty) and list each policy file with its control ID, severity, and a one-line remediation — the same facts that appear in each `# METADATA` block.

## Capture your evidence

```bash
# from the repo root
mkdir -p evidence/lab-3-3
opa test --format=json policies/ > evidence/lab-3-3/opa-test-results.json
```

## Commit your work

```bash
# from the repo root
git add policies evidence/lab-3-3 terraform/primitives/policy-fixture
git commit -m "Lab 3.3: Rego compliance policies + tests + evidence"
git push
```

## Cleanup

There's nothing to tear down. The fixture is plan-only; you never applied it, so no live resources exist. (If you did run `terraform apply` out of curiosity, `terraform destroy` in the fixture folder cleans it up.)

## Portfolio submission checklist

- [ ] `policies/` holds the three policies, each with a `# METADATA` block.
- [ ] `policies/tests/` holds passing and failing fixtures for each policy.
- [ ] `policies/README.md` lists each policy with its control, severity, and remediation.
- [ ] `evidence/lab-3-3/opa-test-results.json` captures the test run.

## Troubleshooting

- **`rego_parse_error: yaml: mapping values are not allowed`** in a METADATA block: the YAML parser chokes on unquoted colons inside a value. Wrap the `description:` and `remediation:` values in double quotes.
- **A bucket you expected to flag passes.** Module-wrapped resources live under `child_modules[]`, not `root_module.resources`. The rules here recurse into both; if you write your own, do the same or you'll miss every module resource.
- **A CMEK bucket fails SC-28.** At plan time the key ID is "known after apply" and missing from the JSON. Don't require a populated key string; require the block to exist. The `has_cmek` predicate already does this.
- **`required - provided` throws a type error.** Both sides must be sets. `provided_labels` returns a set comprehension for exactly this reason.

## How this feeds the rest of the course

This is the start of your capstone's policy suite. The three rules here are written against GCP, and in Lab 3.4 you'll add AWS variants and wire the whole library into Conftest as the gate your CI pipeline calls on every pull request. The control IDs in these METADATA blocks become the same IDs your OSCAL component cites in Chapter 6. One policy library, written once, enforced on every change and referenced by every audit artifact you produce from here on.

# Lab 6.1: Introduction to OSCAL

OSCAL is NIST's machine-readable format for security controls, profiles, components, system security plans, and assessments. The point isn't the format. The point is that an assessor can traverse from a control catalog to a profile to a component to an evidence URI without ever talking to you. The audit becomes a graph traversal. This lab writes the smallest piece of that graph: one component definition, validated by `trestle`, with evidence links pointing at real signed objects in your vault.

## Learning objectives

- Author a valid OSCAL Component Definition for a Terraform module.
- Author a minimal Profile selecting the controls the component implements.
- Wire evidence URIs to objects in the Lab 2.5 vault, validate the whole chain with `trestle`.

## Prerequisites

- Python `>= 3.10`.
- `pip install compliance-trestle` (NIST's OSCAL Python toolkit).
- Lab 2.3 (or Lab 2.4) module on disk. We'll describe it in OSCAL.
- Lab 2.5 vault exists, so evidence URIs resolve.

## Estimated time & cost

- 60 to 75 minutes.
- Free. OSCAL tooling is open source. No cloud calls beyond fetching the NIST 800-53 catalog.

## Architecture

```
   Terraform module                        OSCAL                                Auditor
   ────────────────                        ─────                                ───────
   reference/lab-2-3/    ───describes───▶  component-definition.json
   main.tf, etc.                           ├─ control-implementations            "show me your
                                           │   source: NIST 800-53 catalog        SC-28 evidence"
                                           ├─ implemented-requirements
                                           │   sc-28, ac-3, au-3, cm-6
                                           │   props: terraform-resource refs
                                           │   links: rel=evidence, href=s3://
                                           │
                                           profile.json (selects sc-28, ac-3, ...)
                                                                                  ▼
                                                                           follows href into vault
                                                                           runs verify-evidence.sh
                                                                           sees CHAIN INTACT
```

## Step-by-step walkthrough

### 5.1 The five OSCAL models

| Model | What it describes | Built in this lab |
|---|---|---|
| **Catalog** | A library of controls (e.g., NIST 800-53 Rev 5). | No, we link to the NIST-published one. |
| **Profile** | A subset of controls selected from one or more catalogs. | Yes, minimal. |
| **Component Definition** | How a software component implements specific controls. | Yes, the centerpiece. |
| System Security Plan (SSP) | A whole system's controls + components. | Stretch goal for capstone. |
| Assessment Plan / Results | What the auditor planned, what the auditor found. | Out of scope. |

### 5.2 Initialize a trestle workspace

```bash
pip install compliance-trestle
mkdir lab-6-1 && cd lab-6-1
trestle init
```

You'll get an OSCAL-shaped directory: `catalogs/`, `profiles/`, `component-definitions/`, etc.

### 5.3 Create the component definition skeleton

```bash
trestle create -t component-definition -o compliant-s3-v1 -x json
```

Trestle generates a minimal valid skeleton. Open `component-definitions/compliant-s3-v1/component-definition.json` and replace it with the real document.

### 5.4 The component definition

```json
{
  "component-definition": {
    "uuid": "GENERATED-UUID-V4",
    "metadata": {
      "title": "compliant-s3 module v1",
      "last-modified": "2026-04-26T18:00:00.000000+00:00",
      "version": "1.0.0",
      "oscal-version": "1.1.3",
      "parties": [
        {
          "uuid": "PARTY-UUID-V4",
          "type": "organization",
          "name": "Your organization"
        }
      ]
    },
    "components": [
      {
        "uuid": "COMPONENT-UUID-V4",
        "type": "software",
        "title": "compliant-s3",
        "description": "Reusable Terraform pattern for an AWS S3 primary bucket plus a dedicated access-log bucket. Hardcodes server-side encryption, versioning, public access block, access logging, and required compliance tags.",
        "purpose": "Provide a compliant-by-default S3 primitive that any team can adopt with three lines of consumer Terraform.",
        "responsible-roles": [
          { "role-id": "provider", "party-uuids": ["PARTY-UUID-V4"] }
        ],
        "control-implementations": [
          {
            "uuid": "CI-UUID-V4",
            "source": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            "description": "Implementation of NIST 800-53 Rev 5 controls satisfied by this module.",
            "implemented-requirements": [
              {
                "uuid": "REQ-UUID-V4",
                "control-id": "sc-28",
                "description": "AES-256 server-side encryption is enforced via aws_s3_bucket_server_side_encryption_configuration. Hardcoded; consumers cannot override.",
                "props": [
                  { "name": "implementation-status", "value": "implemented" },
                  { "name": "terraform-resource", "value": "aws_s3_bucket_server_side_encryption_configuration.primary" }
                ],
                "links": [
                  {
                    "rel": "evidence",
                    "href": "s3://EVIDENCE_VAULT/runs/LATEST/evidence-LATEST.tar.gz",
                    "text": "Signed pipeline bundle containing terraform plan.json."
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

Add similar `implemented-requirements` for `ac-3`, `au-3`, and `cm-6`. The full reference is in `reference/lab-6-1/component-definitions/compliant-s3-v1/component-definition.json`.

> **Generate UUIDs the right way.** OSCAL requires v4 UUIDs (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` where `y` is 8/9/a/b). Don't hand-write them. Run `python3 -c "import uuid; print(uuid.uuid4())"` per UUID. `trestle validate` rejects the wrong format with a regex error; this catches you the first time you try.

### 5.5 Validate

```bash
trestle validate -f component-definitions/compliant-s3-v1/component-definition.json
```

Expected:

```
VALID: Model .../component-definition.json passed the Validator
to confirm the model passes all registered validation tests.
```

### 5.6 The Profile

A profile selects which controls from the catalog this component covers.

```bash
trestle create -t profile -o cge-p-minimum -x json
```

Edit `profiles/cge-p-minimum/profile.json`:

```json
{
  "profile": {
    "uuid": "PROFILE-UUID-V4",
    "metadata": {
      "title": "CGE-P minimum control selection",
      "last-modified": "2026-04-26T18:00:00.000000+00:00",
      "version": "1.0.0",
      "oscal-version": "1.1.3"
    },
    "imports": [
      {
        "href": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "include-controls": [
          { "with-ids": ["sc-28", "ac-3", "au-3", "cm-6"] }
        ]
      }
    ],
    "merge": { "as-is": true }
  }
}
```

Validate:

```bash
trestle validate -f profiles/cge-p-minimum/profile.json
```

### 5.7 Resolve the profile against the catalog

```bash
trestle profile-resolve -n cge-p-minimum -o cge-p-minimum-resolved
```

Trestle fetches the NIST catalog, applies your selection, and writes a resolved profile, the flat list of controls your component is responsible for. This is what an SSP would import.

### 5.8 Demonstrate the traversal

Pick `sc-28` in your component definition. Follow the `links[rel=evidence].href` to the vault. Run Lab 4.4's `verify-evidence.sh`:

```bash
EVIDENCE_VAULT=<your-vault> bash scripts/verify-evidence.sh <run_id>
```

`CHAIN INTACT`. The OSCAL document, the catalog reference, the implementation statement, the evidence URI, and the signed bundle in the vault are now linked. An assessor reading the OSCAL can verify your control without you in the room.

## Verification

- `trestle validate` returns `VALID` for the component definition AND the profile.
- `trestle profile-resolve` produces a resolved profile.
- At least one evidence URI in the component definition resolves to a real signed object in your vault.

## Portfolio submission checklist

- [ ] `oscal/components/<your-component>.json` validated by trestle.
- [ ] `oscal/profiles/cge-p-minimum.json` validated.
- [ ] `evidence/lab-6-1/trestle-validate.txt`, the output of `trestle validate`, captured.
- [ ] README in `oscal/` explaining which module each component describes and where the evidence lives.

## Troubleshooting

- **`string does not match regex` on UUIDs.** OSCAL strictly requires v4. Use `python3 -c "import uuid; print(uuid.uuid4())"`. Don't hand-write.
- **`trestle validate`** fails on missing required fields. Use `trestle describe -t component-definition -n <name>` to inspect the schema requirements; the schema is strict and helpfully verbose.
- **Evidence URIs that don't resolve.** OSCAL itself doesn't validate that hrefs resolve. A broken URI is silently a useless attestation. Wire your CI to verify the references during the resolve step, or write a small script.
- **Catalog imports fail.** NIST's GitHub URLs sometimes change. Anchor to a tag (`/blob/v5.0.0/`) instead of `main` if you want stability.
- **Different OSCAL versions don't compose.** Catalog and profile and component must all share an `oscal-version`. Trestle pins to whatever version it installed; check with `trestle version`.

## Cleanup

OSCAL is YAML/JSON in your repo. There's nothing in the cloud to destroy. Commit and move on.

## How this feeds the capstone

This component definition is the OSCAL layer of your capstone. The capstone's repo holds:

```
oscal/
  components/<your-component>.json      # describes what you built
  profiles/cge-p-minimum.json           # selects the controls you implement
```

The component definition's `links[rel=evidence].href` points at the latest signed bundle in your vault, written by the Lab 4.3+4.4 pipeline. The chain ends in the vault.

A grader reading your `WRITEUP.md` is told to start at `oscal/components/`. They follow the chain to the vault. They run `verify-evidence.sh`. They see `CHAIN INTACT`. That's the engineered assurance demonstration the capstone is asking for. You just shipped it.

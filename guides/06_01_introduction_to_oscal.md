# Lab 6.1: Introduction to OSCAL

OSCAL is NIST's machine-readable format for security controls, profiles, components, and assessments. Don't get hung up on the format itself; the reason it exists is the interesting part. With OSCAL, an assessor can start at a control catalog, follow a link to a profile, follow another to a component, and follow one more to a piece of evidence, all without ever talking to you. The audit turns into a graph traversal. This lab writes the smallest real piece of that graph: one component definition, validated by a tool called `trestle`, with evidence links that point at the actual signed bundles in your vault.

For the GRC folks, this is your control narrative rewritten so a machine can read it and an assessor can verify it. For the technical folks, this is authoring structured JSON against a strict schema, where the unusual payoff is that your documentation becomes executable: every claim links to evidence that can be checked.

This is the documentation layer that ties the whole course together. Everything you built (the compliant module, the policies, the pipeline, the signed vault) gets described here in a way an outside assessor can traverse on their own.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first.

You need:

- **Python `>= 3.10`** and **compliance-trestle**, NIST's OSCAL Python toolkit. Install it with `pip install compliance-trestle`. For OSCAL background, NIST's official site is https://pages.nist.gov/OSCAL/.
- The Lab 2.3 (or 2.4) module on disk, since you'll describe it in OSCAL.
- For the optional traversal at the end, a signed bundle in your Lab 2.5 vault (produced by the Lab 4.4 pipeline). The authoring and validation themselves need no cloud at all.

## Time and cost

- Time: 60 to 75 minutes.
- Cost: free. The tooling is open source and the only network call fetches the public NIST catalog.

## The five OSCAL models

A quick map so the vocabulary doesn't trip you:

| Model | What it describes | Built here? |
|---|---|---|
| **Catalog** | A library of controls (e.g., NIST 800-53 Rev 5). | No, you link to NIST's published one. |
| **Profile** | A chosen subset of controls from one or more catalogs. | Yes, a minimal one. |
| **Component Definition** | How a software component implements specific controls. | Yes, the centerpiece. |
| System Security Plan (SSP) | A whole system's controls and components. | Capstone stretch goal. |
| Assessment Plan / Results | What an auditor planned and found. | Out of scope. |

You're building the middle two: a component definition that says "here's what my module does and here's the proof," and a profile that says "here are the controls I'm claiming."

## Where these files live

```
cgep-labs/
├── oscal/                                 ← committed, capstone-shaped layout
│   ├── components/
│   │   └── compliant-s3.json              ← copied from trestle at the end
│   ├── profiles/
│   │   └── cge-p-minimum.json             ← copied from trestle at the end
│   └── README.md
├── evidence/lab-6-1/
│   └── trestle-validate.txt               ← filled in when you validate
└── .trestle-work/                         ← local authoring only (gitignored)
    ├── component-definitions/compliant-s3-v1/component-definition.json
    └── profiles/cge-p-minimum/profile.json
```

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates the committed layout up front; trestle will create its own working tree in the next step.

```bash
# from the repo root
mkdir -p oscal/components oscal/profiles evidence/lab-6-1

touch \
  oscal/components/compliant-s3.json \
  oscal/profiles/cge-p-minimum.json \
  oscal/README.md

grep -qxF '.trestle-work/' .gitignore || echo '.trestle-work/' >> .gitignore

find oscal evidence/lab-6-1 -type f | sort
```

You will author inside `.trestle-work/` (trestle's native layout), then copy the finished JSON into the empty `oscal/...` files above.

## Step-by-step walkthrough

### Step 1: Initialize a trestle workspace

Work under a temporary authoring directory so trestle's full layout doesn't collide with the simpler `oscal/components/` and `oscal/profiles/` paths your capstone expects. You'll copy the finished JSON into those paths at the end.

```bash
# from the repo root
pip install compliance-trestle
mkdir -p .trestle-work && cd .trestle-work
trestle init
```

Trestle lays down an OSCAL-shaped directory: `catalogs/`, `profiles/`, `component-definitions/`, and so on. It's opinionated about structure, which is helpful, because the schema is strict and trestle keeps you inside the lines.

### Step 2: Create the component-definition skeleton

```bash
# still inside .trestle-work/
trestle create -t component-definition -o compliant-s3-v1 -x json
```

This generates a minimal valid skeleton at **`.trestle-work/component-definitions/compliant-s3-v1/component-definition.json`**. Open that file and replace it with the real document in the next step.

### Step 3: Write the component definition

Open **`.trestle-work/component-definitions/compliant-s3-v1/component-definition.json`**. This document describes your `compliant-s3` module (the one at `terraform/primitives/compliant-s3`) in OSCAL terms: which controls it implements, which Terraform resource enforces each, and where the evidence lives.

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

Then add the same shape of `implemented-requirements` block for `ac-3`, `au-3`, and `cm-6`, each naming the Terraform resource that enforces it and linking to the same signed bundle.

Read the `sc-28` block slowly, because it's the whole idea in miniature. The `control-id` says which control. The `description` says how the module satisfies it. The `terraform-resource` prop says exactly which line of code does it. And the `links[rel=evidence]` href says where the proof lives. Four facts, machine-readable, and the last one is a live pointer into your vault.

> **Generate UUIDs the right way.** OSCAL requires version-4 UUIDs (the `4` and the `8/9/a/b` in specific positions matter). Don't hand-write them, or `trestle validate` will reject them with a regex error. You already need Python for trestle, so this is fine: `python3 -c "import uuid; print(uuid.uuid4())"`. On macOS/Linux you can also use `uuidgen | tr '[:upper:]' '[:lower:]'`.

### Step 4: Validate the component

```bash
trestle validate -f component-definitions/compliant-s3-v1/component-definition.json
```

You want:

```
VALID: Model .../component-definition.json passed the Validator
```

If it fails, the message usually points right at the missing or malformed field. The schema is strict but verbose, which works in your favor here.

### Step 5: Write the profile

A profile selects which catalog controls you're claiming. Create the skeleton, then open **`.trestle-work/profiles/cge-p-minimum/profile.json`** and replace its contents:

```bash
# still inside .trestle-work/
trestle create -t profile -o cge-p-minimum -x json
```

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

```bash
trestle validate -f profiles/cge-p-minimum/profile.json
```

### Step 6: Resolve the profile against the catalog

```bash
trestle profile-resolve -n cge-p-minimum -o cge-p-minimum-resolved
```

Trestle fetches the NIST catalog, applies your selection, and writes out a *resolved* profile: the flat list of controls you're responsible for, with their full text pulled in from the catalog. This is the artifact a System Security Plan would import. You've turned "I cover four controls" into a self-contained, machine-readable document.

### Step 7: Walk the traversal yourself

This is the part that makes OSCAL click. Take the `sc-28` requirement, follow its `links[rel=evidence].href` into the vault, and run the verify script from Lab 4.4:

> The command below uses `--profile default`. If you named your AWS CLI profile something else in Lab 2.3, replace `default` with that name.

```bash
# from the repo root; reuse VAULT/RUN_ID from Lab 4.4 if you still have them
EVIDENCE_VAULT="$VAULT" bash scripts/verify-evidence.sh "$RUN_ID" --profile default
```

When it prints `CHAIN INTACT`, you've just done what an assessor does: started from a control claim in a document, followed a link to a real artifact, and cryptographically confirmed the artifact is authentic and unaltered. Nobody had to log into a console, and you didn't have to be in the room. (If you're doing this lab standalone without a vault bundle handy, the authoring and validation in Steps 1 through 6 still stand on their own; this step is the live demonstration of the link resolving.)

## Verification

- `trestle validate` returns `VALID` for both the component definition and the profile.
- `trestle profile-resolve` produces a resolved profile.
- At least one evidence URI in the component definition points at a real signed object in your vault.

## Capture and commit

You're still inside `.trestle-work/`. Validate, then overwrite the empty scaffold files under `oscal/` at the repo root:

```bash
trestle validate -f component-definitions/compliant-s3-v1/component-definition.json \
  > ../evidence/lab-6-1/trestle-validate.txt 2>&1

cp component-definitions/compliant-s3-v1/component-definition.json ../oscal/components/compliant-s3.json
cp profiles/cge-p-minimum/profile.json ../oscal/profiles/cge-p-minimum.json

cd ..   # back to cgep-labs (repo root)
ls oscal/components oscal/profiles evidence/lab-6-1

# Fill the scaffolded README: which module each component describes and where its evidence lives
# Open oscal/README.md and write a short note, then:
git add oscal evidence/lab-6-1 .gitignore
git commit -m "Lab 6.1: OSCAL component definition + profile + validation"
git push
```

## Portfolio submission checklist

- [ ] `oscal/components/<your-component>.json` validated by trestle.
- [ ] `oscal/profiles/cge-p-minimum.json` validated.
- [ ] `evidence/lab-6-1/trestle-validate.txt` captured.
- [ ] A README in `oscal/` saying which module each component describes and where its evidence lives.

## Troubleshooting

- **`string does not match regex` on a UUID.** OSCAL requires v4 UUIDs. Generate them with `python3 -c "import uuid; print(uuid.uuid4())"` (or `uuidgen`), never by hand.
- **Validation fails on a missing field.** Run `trestle describe -t component-definition -n <name>` to see what the schema expects; it's strict but the errors are specific.
- **An evidence URI that doesn't resolve.** OSCAL won't check that hrefs actually resolve, so a broken link is a silently useless attestation. Wire a small check into CI (or your resolve step) that confirms each evidence href points at a real vault object.
- **Catalog import fails.** NIST's `main`-branch URLs occasionally move. Pin to a tag (e.g., `/v5.0.0/`) for stability.
- **Version mismatch.** The catalog, profile, and component must share an `oscal-version`. Check what trestle installed with `trestle version` and match it.

## Cleanup

OSCAL is just JSON in your repo. There's nothing in the cloud to tear down. Commit and move on.

## How this feeds the capstone

This component definition *is* your capstone's OSCAL layer. The capstone repo carries `oscal/components/<your-component>.json` (what you built) and `oscal/profiles/cge-p-minimum.json` (the controls you claim), and the component's evidence links point at the latest signed bundle in your vault, written by your Lab 4.3 + 4.4 pipeline. The chain ends in the vault. A grader is told to start at `oscal/components/`, follow the links, run `verify-evidence.sh`, and see `CHAIN INTACT`. That single traversal is the entire course demonstrated end to end, and you've now built every link in it.

# Lab 4.4: Evidence Management and Chain of Custody (AWS)

You have a pipeline that produces evidence (Lab 4.3) and a vault that can't be tampered with (Lab 2.5). This lab joins them with cryptographic signing, so the evidence isn't just stored, it's provably yours, provably unchanged, and provably timestamped. The shift in mindset is the whole lesson: the auditor no longer has to *trust* you. They run a command and the math tells them whether the chain is intact.

For the GRC folks, this is chain of custody turned from a paragraph in a policy into something a script verifies in seconds. For the technical folks, this is keyless signing with Sigstore wired into CI, in service of a property you may never have had to engineer before: evidence that defends itself.

## Before you begin

If this is your first lab, set up [your tools](../getting-started/tools.md) and [your repo](../getting-started/repo-structure.md) first. This lab continues directly from Labs 2.5 and 4.3.

You need:

- **Cosign** installed locally for verification (`cosign version` reports `>= 2.0`). Official install: https://docs.sigstore.dev/cosign/system_config/installation/
- Your Lab 4.3 workflow (`grc-gate.yml`) committed and working.
- The Lab 2.5 vault. On a fresh day it was destroyed, so redeploy it in Step 0 below.

> Commands below use `--profile default`. If you named your AWS CLI profile something else in Lab 2.3, replace `default` with that name.

> **Hashing tools differ by OS.** macOS ships `shasum -a 256`; Git Bash and Ubuntu (including GitHub Actions runners) ship `sha256sum`. The workflow and verify script below detect whichever is available, the same way Lab 2.5's `capture-evidence.sh` does.

## Time and cost

- Time: about 60 minutes.
- Cost: free. Sigstore is free; the S3 storage is fractions of a cent.

## Chain of custody, in four properties

Hold these four words in your head, because everything in this lab maps to one of them:

- **Authenticity:** the evidence came from who it claims to (a specific repo's workflow).
- **Integrity:** the evidence hasn't changed since it was produced.
- **Timeliness:** there's a trustworthy record of *when* it was produced.
- **Preservation:** it's still there, protected, when someone comes looking.

Lab 2.5 gave you preservation (Object Lock). This lab adds authenticity, integrity, and timeliness through signing. Miss any one and you have a story, not a chain.

## How keyless signing works (plain language)

Normally signing means managing private keys, which is its own security headache. Sigstore's "keyless" approach skips that. When your workflow signs the evidence, it proves its identity using the same GitHub OIDC token from Lab 4.3. Sigstore's certificate authority (Fulcio) issues a short-lived certificate tied to that identity, and Sigstore's public transparency log (Rekor) records the signature with a timestamp. There's no private key to store or leak. The signature is bound to "this repository's workflow, at this moment," and that binding lives in Sigstore's infrastructure, not in your AWS account, so even an admin on your AWS account can't forge it.

## Architecture

```
  PR run (Lab 4.3)
     │  produces evidence files
     ▼
  bundle into one tar.gz  ─▶  hash it (SHA-256)
     │
     ▼
  cosign sign-blob (keyless, via GitHub OIDC)
     │   Fulcio issues a short-lived cert
     │   Rekor logs the signature + timestamp
     ▼
  upload bundle + .sha256 + .sig.bundle + receipt.json
     to s3://VAULT/runs/<run_id>/   (Object Lock applies retention)
     │
     ▼
  auditor runs verify-evidence.sh <run_id>:
     ├── recompute SHA-256 matches          → integrity
     ├── cosign verify-blob succeeds         → authenticity + timeliness
     └── retention not expired               → preservation
     → "CHAIN INTACT"
```

## Where these files live

```
cgep-labs/
├── .github/workflows/
│   └── grc-gate.yml              ← edit: add Cosign + sign/upload + enforce-gate
├── scripts/
│   └── verify-evidence.sh        ← new in this lab
└── evidence/lab-4-4/
    └── receipt.json              ← filled in after a signed run
```

You already have `grc-gate.yml` from Lab 4.3 and the vault from Lab 2.5. This lab adds the verify script and extends the workflow.

### Scaffold this lab's empty files

Run this once from the repo root (`cgep-labs`). It creates the new paths; the workflow file should already exist from Lab 4.3.

```bash
# from the repo root
mkdir -p scripts evidence/lab-4-4 .github/workflows

touch scripts/verify-evidence.sh
chmod +x scripts/verify-evidence.sh

# Confirm the workflow you will edit is present
ls -la .github/workflows/grc-gate.yml scripts/verify-evidence.sh evidence/lab-4-4
```

## Step-by-step walkthrough

### Step 0: Redeploy the vault

On a fresh day your Lab 2.5 vault is gone, so stand it back up and record its name:

```bash
# from the repo root
cd terraform/primitives/evidence-vault
eval "$(aws configure export-credentials --profile default --format env)"
terraform init && terraform apply -auto-approve
VAULT=$(terraform output -raw vault_name)
cd ../../..
gh variable set EVIDENCE_VAULT --body "$VAULT" --repo <your-github-org>/cgep-labs
```

### Step 1: Add signing to the workflow

Two additions to **`.github/workflows/grc-gate.yml`** (the file from Lab 4.3 — open that existing file, don't create a second one). First, install Cosign (add it alongside the other tool-install steps):

```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3
  with:
    cosign-release: 'v2.2.4'
```

Then, after the `Copy plan into evidence` step, add the bundle/sign/upload step:

```yaml
- name: Bundle + sign + upload to vault
  id: sign
  if: always()
  env:
    VAULT: ${{ vars.EVIDENCE_VAULT }}
    RUN_ID: ${{ github.run_id }}
    SHA: ${{ github.sha }}
  run: |
    set -euo pipefail
    if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
    else echo "Need sha256sum or shasum" >&2; exit 2; fi

    BUNDLE="evidence-${RUN_ID}-${SHA}.tar.gz"
    ( cd evidence/lab-4-3 && tar czf "../../${BUNDLE}" . )
    $SHASUM "${BUNDLE}" | awk '{print $1}' > "${BUNDLE}.sha256"

    cosign sign-blob --yes --bundle "${BUNDLE}.sig.bundle" "${BUNDLE}"

    KEY_PREFIX="runs/${RUN_ID}"
    aws s3 cp "${BUNDLE}"            "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}"
    aws s3 cp "${BUNDLE}.sha256"     "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}.sha256"
    aws s3 cp "${BUNDLE}.sig.bundle" "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}.sig.bundle"

    VERSION_ID=$(aws s3api head-object --bucket "${VAULT}" --key "${KEY_PREFIX}/${BUNDLE}" --query VersionId --output text)
    cat > receipt.json <<EOF
    {
      "run_id":"${RUN_ID}",
      "vault":"${VAULT}",
      "bundle_key":"${KEY_PREFIX}/${BUNDLE}",
      "version_id":"${VERSION_ID}",
      "sha256":"$(cat ${BUNDLE}.sha256)",
      "commit":"${SHA}"
    }
    EOF
    aws s3 cp receipt.json "s3://${VAULT}/${KEY_PREFIX}/receipt.json"
    mkdir -p evidence/lab-4-4
    cp receipt.json evidence/lab-4-4/receipt.json
```

The `--bundle` flag packs the signature, Fulcio's certificate, and the Rekor log reference into one file. That single file is everything your verify script needs.

Also widen the existing upload-artifact step so the Lab 4.4 receipt is retained with the rest of the run evidence:

```yaml
- name: Upload evidence artifact
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: grc-evidence-${{ github.run_id }}
    path: |
      evidence/lab-4-3/
      evidence/lab-4-4/
    retention-days: 90
```

> **Sign even when the gate fails.** In Lab 4.3 the policy check could end the job before this step runs, which would mean a failed run leaves no signed evidence, exactly the runs you most want a record of. The fix is ordering: let the earlier gate steps *record* pass or fail without ending the job (they already use `if: always()` on the steps that follow), do the sign-and-upload, and put the actual build-failing decision in a final step:

```yaml
- name: Enforce gate
  if: always()
  run: |
    test "${{ steps.conftest.outcome }}" = "success" \
      && test "${{ steps.tfsec.outcome }}" = "success"
```

Now a violating PR still produces a signed, stored evidence bundle, and *then* the build goes red.

### Step 2: Let the role write to the vault

The Lab 4.3 role was read-only. Grant it a tight write scope on the vault and nothing else:

```bash
eval "$(aws configure export-credentials --profile default --format env)"
aws iam put-role-policy \
  --role-name cgep-grc-gate \
  --policy-name vault-write \
  --policy-document "$(cat <<EOF
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Action":["s3:PutObject","s3:GetObject","s3:GetBucketLocation"],
    "Resource":["arn:aws:s3:::${VAULT}","arn:aws:s3:::${VAULT}/*"]
  }]
}
EOF
)"
```

Two resources only: the vault and its objects. A role that can write evidence shouldn't be able to write anything else.

### Step 3: The verify script

This is the script an auditor runs. Three checks, three ways to fail, one line of success. Open **`scripts/verify-evidence.sh`** from the scaffold and paste:

```bash
#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
set -euo pipefail
RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHASUM "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }

# 2. Authenticity + timestamp
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"

# 3. Preservation
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired"; exit 1; }

echo "CHAIN INTACT for run ${RUN_ID}"
```

Each check maps to one of the four properties: the SHA comparison is integrity, `cosign verify-blob` is authenticity and timeliness together, and the retention check is preservation. If all three pass, the script prints `CHAIN INTACT`. If any fails, it exits non-zero with the reason.

### Step 4: Run a fresh PR and verify it

Commit the workflow changes, push, open a PR. The run produces signed bundles. Grab the run ID from the Actions tab (or `gh run list --limit 1`), then verify from your laptop without hand-copying vault paths:

```bash
RUN_ID=$(gh run list --workflow=grc-gate.yml --limit 1 --json databaseId --jq '.[0].databaseId')
EVIDENCE_VAULT="$VAULT" bash scripts/verify-evidence.sh "$RUN_ID" --profile default
```

You're looking for, at the very end:

```
Verified OK
...
CHAIN INTACT for run <run-id>
```

`Verified OK` is Cosign confirming the signature matches the bundle and the Rekor entry exists. `CHAIN INTACT` is your script confirming all three checks passed.

Pull a local copy of the receipt into your repo (the workflow also writes `evidence/lab-4-4/receipt.json` into the Actions artifact, but committing it from your laptop is what lands it in GitHub):

```bash
mkdir -p evidence/lab-4-4
aws s3 cp "s3://${VAULT}/runs/${RUN_ID}/receipt.json" evidence/lab-4-4/receipt.json \
  --profile default
```

### Step 5: The tamper test

This is the demonstration the whole lab builds toward, so do it and watch it fail. Download the bundle using the receipt (or list the prefix), change a single byte, and re-hash:

```bash
# reuse RUN_ID and VAULT from above
BUNDLE_KEY=$(aws s3api list-objects-v2 --bucket "$VAULT" --prefix "runs/${RUN_ID}/" \
  --query "Contents[?ends_with(Key, '.tar.gz')].Key | [0]" --output text --profile default)

aws s3 cp "s3://${VAULT}/${BUNDLE_KEY}" /tmp/bundle.tar.gz --profile default
echo "junk" >> /tmp/bundle.tar.gz
if command -v sha256sum >/dev/null 2>&1; then sha256sum /tmp/bundle.tar.gz
else shasum -a 256 /tmp/bundle.tar.gz; fi
# the value now differs from the .sha256 sidecar; verification fails
```

The hash no longer matches, and the signature, computed over the original bytes, disagrees with the altered file. Verification fails instantly. That's the point of the entire chapter in one command: chain of custody here is mathematical, not a matter of anyone's good word.

And notice what you *can't* do: you can't write the tampered bundle back over the original in the vault, because Object Lock refuses to overwrite the existing key. The only place a tampered copy can exist is your laptop. The vault stays clean, and the chain stays intact.

## Commit your work

```bash
# from the repo root
git add .github/workflows/grc-gate.yml scripts/verify-evidence.sh evidence/lab-4-4
git commit -m "Lab 4.4: Cosign signing + chain-of-custody verification"
git push
```

## Verification

- The vault holds a bundle, its `.sha256`, its `.sig.bundle`, and a `receipt.json` for at least one run.
- `verify-evidence.sh <run_id>` exits 0 with `CHAIN INTACT`.
- Tampering with the bundle and re-running exits non-zero on the integrity check.

## Portfolio submission checklist

- [ ] `grc-gate.yml` has the Cosign install, the bundle/sign/upload step, and the final enforce-gate step.
- [ ] `scripts/verify-evidence.sh` committed and executable.
- [ ] At least one run's full signed bundle visible in the vault.
- [ ] `evidence/lab-4-4/receipt.json` committed (copied from the signing step).
- [ ] A `WRITEUP.md` section mapping each of the four chain properties to the artifact that proves it.

## Cleanup

Don't clean the vault on purpose; the point of retention is that evidence outlives the PR that made it. Because Lab 2.5 deployed the vault in GOVERNANCE mode with 1-day retention, the lab bundles become deletable after 24 hours on their own, and you can then `terraform destroy` the vault. In production you'd use COMPLIANCE mode and a long retention, and you would never clean it.

## Troubleshooting

- **`cosign sign-blob: failed to get OIDC token` in CI.** The job needs `permissions: id-token: write`. Without it Sigstore can't issue a certificate.
- **`cosign verify-blob` fails on certificate identity.** The script uses a permissive `--certificate-identity-regexp '.*'`. For stricter checks, replace it with the exact workflow subject, for example `^https://github.com/OWNER/REPO/.github/workflows/grc-gate.yml@refs/heads/main$`.
- **Rekor lag.** The public transparency log can trail the signing call by about a second. Verifying microseconds after signing can miss the entry. CI naturally waits; this only bites on a laptop loop.
- **403 on the second upload.** Object Lock blocks overwriting an existing key. Each run lands under a unique `runs/<run_id>` prefix, so a fresh run avoids this; don't reuse a run ID.
- **`Need sha256sum or shasum`.** Neither hashing tool is on your PATH. Git Bash and Ubuntu include `sha256sum`; macOS includes `shasum`. Confirm with `command -v sha256sum` or `command -v shasum`.

## How this feeds the capstone

Every PR in your capstone repo now leaves a signed, timestamped, immutably-stored record of what was tested and what happened. An assessor who never speaks to you can reconstruct the whole chain: read your OSCAL component (Chapter 6), follow its evidence link to a vault object, run `verify-evidence.sh` against the run ID, and see `CHAIN INTACT`. That is the engineered assurance the capstone asks you to demonstrate, and you've now built every piece of it.

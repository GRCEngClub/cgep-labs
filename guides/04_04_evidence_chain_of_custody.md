# Lab 4.4: Evidence Management & Chain of Custody (AWS)

You have a pipeline. You have an immutable vault. This lab connects them with cryptographic signing so the evidence in the vault is provably yours, provably untampered, and provably timestamped. The auditor doesn't need to trust you. They verify.

## Learning objectives

- Define chain of custody as four properties: authenticity, integrity, timeliness, completeness.
- Extend the Lab 4.3 pipeline with keyless Cosign signing using GitHub OIDC.
- Upload signed bundles to the Lab 2.5 vault and verify the full chain end-to-end with a single script.

## Prerequisites

- Lab 2.5 vault deployed and live. You have its bucket name handy.
- Lab 4.3 pipeline working. Workflow runs on every PR.
- Cosign installed locally for verification (`cosign version` reports `>= 2.0`).

## Estimated time & cost

- 60 minutes.
- Free. Sigstore is free. Marginal S3 cost.

## Architecture

```
  PR opens
     │
     ▼
  workflow run  ─┬─▶  plan / policy / scan          (Lab 4.3)
                 │
                 ▼
                 bundle evidence files into tar.gz
                 │
                 ▼
                 cosign sign-blob --bundle (keyless via GitHub OIDC)
                 │             │
                 │             ▼
                 │       Sigstore Fulcio CA issues short-lived cert
                 │       Sigstore Rekor logs signature with timestamp
                 ▼
                 aws s3 cp bundle + .sha256 + .sig.bundle + receipt.json
                                 to s3://VAULT/runs/<run_id>/
                                 (Object Lock applies retention)
                 │
                 ▼
   auditor:  scripts/verify-evidence.sh <run_id>
             ├── recompute SHA-256 = expected         (integrity)
             ├── cosign verify-blob --bundle          (authenticity, timestamp)
             └── get-object-retention RetainUntilDate (preservation)
             "CHAIN INTACT"
```

## Step-by-step walkthrough

### Concept: Why signing matters

Lab 2.5 made the bundle immutable. Object Lock prevents deletion, but it doesn't prove who created the bundle or when. A determined insider with admin in the AWS account can stand up a *different* bucket, drop a tampered bundle, and point a sloppy auditor at it. Cosign closes that loop. The signature ties the bundle to a specific GitHub Actions run on a specific repository at a specific moment. The certificate Sigstore issues includes the OIDC subject (`repo:GRCEngClub/cgep-app-starter:ref:refs/pull/...`). The Rekor transparency log timestamps it. None of that is bypassable by anyone with admin in your AWS account, because none of it lives in your AWS account.

Three ways the chain breaks: mutable storage (Lab 2.5 fixed that), no signing (this lab), short retention (Lab 2.5 default-retention fixed that). Close all three or you have a story, not a chain.

### Step 1 Add Cosign to the workflow

The Lab 4.4 update to `.github/workflows/grc-gate.yml` is six changes: two new steps, three existing steps modified, and one brand-new step at the end of the job. Apply them all, or the gate's evidence-on-failure semantics break.

First, add the Cosign installer alongside the other tool installers (between `Install tfsec` and `Terraform plan`):

```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3
  with:
    cosign-release: 'v2.2.4'
```

Then, after `Copy plan into evidence`, the bundle/sign/upload step:

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
    BUNDLE="evidence-${RUN_ID}-${SHA}.tar.gz"
    ( cd evidence && tar czf "../${BUNDLE}" . )
    shasum -a 256 "${BUNDLE}" | awk '{print $1}' > "${BUNDLE}.sha256"

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
```

The `--bundle evidence.sig.bundle` flag packs the signature, the certificate Sigstore Fulcio issued, and the Rekor entry into one file. That file is what your verify script consumes.

> **Important**: in Lab 4.3 the policy gate exited the job on failure. Here we want to sign and store the evidence even when the gate fails, so the evidence trail is preserved. Move the pass/fail decision to the *last* step in the job, and stop exiting non-zero from the Conftest step itself.

Update the existing `Conftest policy gate` step from Lab 4.3 to drop the `sys.exit(...)` line. The step still records failures; it just doesn't abort the job:

```yaml
- name: Conftest policy gate
  id: conftest
  working-directory: ${{ env.TF_WORKING_DIR }}
  run: |
    mkdir -p ../evidence
    {
      echo "["
      FIRST=1
      for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6 ; do
        [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
        conftest test --policy ../policies --namespace "$ns" --output=json plan.json || true
      done
      echo "]"
    } > ../evidence/conftest-results.json
    python3 -c '
    import json, sys
    d = json.load(open("../evidence/conftest-results.json"))
    fails = sum(len(r.get("failures") or []) for results in d for r in results)
    print(f"conftest failures: {fails}")
    ' # do not exit on failure here; we want to sign and store the failed evidence too
```

Update the `Upload evidence artifact` step so the artifact also captures the signed bundle, sidecars, and receipt:

```yaml
- name: Upload evidence artifact
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: grc-evidence-${{ github.run_id }}
    path: |
      evidence/
      evidence-${{ github.run_id }}-*.tar.gz
      evidence-${{ github.run_id }}-*.sig.bundle
      evidence-${{ github.run_id }}-*.sha256
      receipt.json
    retention-days: 90
```

Update the `Comment on PR` step body to surface the sign step, vault location, and the verify command:

```yaml
- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: peter-evans/create-or-update-comment@v4
  with:
    issue-number: ${{ github.event.pull_request.number }}
    body: |
      ## GRC gate run #${{ github.run_id }}

      - Conftest: `${{ steps.conftest.outcome }}`
      - tfsec:    `${{ steps.tfsec.outcome }}`
      - Sign + vault upload: `${{ steps.sign.outcome }}`

      Bundle in vault: `s3://${{ vars.EVIDENCE_VAULT }}/runs/${{ github.run_id }}/`

      Verify locally:
      ```bash
      scripts/verify-evidence.sh ${{ github.run_id }}
      ```
```

Finally, add the `Decide pass/fail` step as the *last* step in the job. It re-reads the conftest results after signing has already happened and converts a failure count into a non-zero exit:

```yaml
- name: Decide pass/fail
  if: always()
  run: |
    python3 -c '
    import json, sys
    d = json.load(open("evidence/conftest-results.json"))
    fails = sum(len(r.get("failures") or []) for results in d for r in results)
    print(f"final conftest failures: {fails}")
    sys.exit(0 if fails == 0 else 1)
    '
```

The order matters: signing and uploading run unconditionally (`if: always()`), then the gate decision happens at the end. A red PR still produces a signed, uploaded bundle — the auditor sees both the failure and the receipt for it.

### Step 2 Grant the role write to the vault

The Lab 4.3 OIDC role had `ReadOnlyAccess`. Grant a tight write inline policy on the vault:

```bash
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
VAULT=<your-vault-bucket>
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
gh variable set EVIDENCE_VAULT --body "$VAULT" --repo OWNER/REPO
```

Two scopes only: the vault and its objects. Nothing else.

### Step 3 The verify script

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
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$(shasum -a 256 "${BUNDLE}" | awk '{print $1}')
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

Three checks, three exits if any fail. The output you want to see at the end is one line: `CHAIN INTACT`.

### Step 4 Trigger a fresh PR

Push the workflow update. The next PR run produces signed bundles. From your laptop:

```bash
EVIDENCE_VAULT=<your-vault> bash scripts/verify-evidence.sh <run_id> --profile <your-sandbox>
```

Reference run: bundle 18.8 KB, three files (`evidence-RUN_ID-SHA.tar.gz`, `.sha256`, `.sig.bundle`) plus `receipt.json`. Verify output:

```
=== 1. Integrity (SHA-256) ===
  OK (dd8a473f8c1dcd969e220296f180f8069d12564fa92ae9c488c40e2387e6adee)
=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ===
Verified OK
  OK (Cosign verified, Rekor entry exists)
=== 3. Preservation (Object Lock retention) ===
  OK (retain until 2026-04-27T18:30:33.696000+00:00)

CHAIN INTACT for run 24963918994
```

### Step 5 The tamper test

Download the bundle. Modify a single byte. Re-run `verify-evidence.sh`. The integrity step fails immediately. The signature, computed over the original bytes, now disagrees with the modified file's SHA. That failure is the lesson: chain of custody is mathematical, not aspirational.

```bash
aws s3 cp "s3://${VAULT}/runs/${RUN_ID}/evidence-${RUN_ID}-${SHA}.tar.gz" /tmp/bundle.tar.gz --profile <your-sandbox>
echo "junk" >> /tmp/bundle.tar.gz
shasum -a 256 /tmp/bundle.tar.gz
# value differs from the .sha256 sidecar; verify-evidence.sh exits 1
```

You can't write the tampered file *back* to the vault without changing the key. Object Lock blocks overwrite of the existing key. So the only place a tampered bundle lives is your laptop. The vault stays clean. The chain stays intact.

## Verification

- The vault contains a `bundle.tar.gz`, `bundle.tar.gz.sha256`, `bundle.tar.gz.sig.bundle`, and `receipt.json` for at least one run.
- `verify-evidence.sh <run_id>` returns 0 with `CHAIN INTACT`.
- Tampering the bundle and re-running returns non-zero with the specific failure (integrity).

## Portfolio submission checklist

- [ ] `.github/workflows/grc-gate.yml` updated with the Cosign install + bundle/sign/upload step.
- [ ] `scripts/verify-evidence.sh` committed and executable.
- [ ] At least one run's full bundle visible in the vault.
- [ ] `WRITEUP.md` section mapping each chain property (authenticity, integrity, timeliness, preservation) to the artifact that proves it.

## Troubleshooting

- **`cosign sign-blob: failed to get OIDC token`** in CI. The job needs `permissions: id-token: write`. Without it the action can't mint the OIDC token Sigstore needs to issue a cert.
- **`cosign verify-blob`** fails with cert-identity mismatch. The default `--certificate-identity-regexp '.*'` is permissive (any cert from the OIDC issuer). For stricter verification, replace with the exact subject pattern, e.g. `^https://github.com/GRCEngClub/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main$`.
- **Rekor propagation race.** The Sigstore Rekor public log can lag the signing call by ~1 second. If you call verify within milliseconds of signing, the log entry isn't there yet. CI naturally waits, this is a laptop-only race.
- **Object Lock rejects overwrite.** The bundle key includes `runs/<run_id>` so each run lands at a unique key. If you re-run a job and the `RUN_ID` is reused for some reason, you'll get a 403 on the second `s3 cp`. Trigger a fresh run instead.
- **`shasum: command not found`.** Linux ships `sha256sum`, macOS ships `shasum -a 256`. The reference script uses `shasum -a 256`. Swap to `sha256sum` on Linux runners if you adapt this for non-GitHub CI.

## Cleanup

Don't clean the vault. The whole point of a 365-day-retention vault is that the evidence outlives the PR that produced it. For lab purposes (Lab 2.5 deployed it in GOVERNANCE 1-day mode), the bundles will become deletable in 24 hours. Production: COMPLIANCE mode, longer retention, no clean.

## How this feeds the capstone

Every PR in your capstone repo now leaves behind a signed, timestamped, immutably-stored record of what was tested and what happened. An assessor who never meets you can reconstruct the chain in minutes:

1. Read your OSCAL component (Lab 6.1).
2. Follow the evidence URI to a specific object in the vault.
3. Run `verify-evidence.sh` against the run ID.
4. See `CHAIN INTACT`.

That is the engineered assurance the capstone is asking you to demonstrate. You just shipped it.

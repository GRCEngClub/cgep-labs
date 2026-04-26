#!/usr/bin/env bash
# scripts/verify-evidence.sh
# Auditor-friendly verification of an evidence bundle in the Object Lock vault.
#
# Usage:
#   verify-evidence.sh <run_id> [--vault <bucket>] [--profile <aws-profile>]
#
# Returns 0 on "CHAIN INTACT", non-zero with a specific failure if any of
# integrity, authenticity, or preservation checks fail.

set -euo pipefail

RUN_ID="${1:-}"
[[ -z "$RUN_ID" ]] && { echo "Usage: $0 <run_id> [--vault <bucket>] [--profile <p>]" >&2; exit 2; }
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

[[ -z "$VAULT" ]] && { echo "Set --vault <bucket> or EVIDENCE_VAULT env var" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

PREFIX="runs/${RUN_ID}"

echo "=== Fetching bundle from s3://${VAULT}/${PREFIX}/ ==="
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz 2>/dev/null | head -1)
[[ -z "$BUNDLE" ]] && { echo "FAIL: bundle not found in vault" >&2; exit 1; }

echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$(shasum -a 256 "${BUNDLE}" | awk '{print $1}')
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "FAIL: SHA-256 mismatch. expected=$EXPECTED actual=$ACTUAL" >&2; exit 1
fi
echo "  OK ($EXPECTED)"

echo "=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ==="
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}" >/dev/null
echo "  OK (Cosign verified, Rekor entry exists)"

echo "=== 3. Preservation (Object Lock retention) ==="
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text 2>/dev/null || echo "")
if [[ -z "$RETAIN_UNTIL" ]]; then
  echo "FAIL: no retention on the object"; exit 1
fi
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [[ "$RETAIN_UNTIL" < "$NOW" ]]; then
  echo "FAIL: retention has expired ($RETAIN_UNTIL < $NOW)"; exit 1
fi
echo "  OK (retain until $RETAIN_UNTIL)"

echo
echo "CHAIN INTACT for run ${RUN_ID}"

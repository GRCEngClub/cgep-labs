#!/usr/bin/env bash
# scripts/policy-gate.sh
#
# Run the Conftest policy gate against a Terraform plan. Used locally and by
# the GitHub Actions workflow in Lab 4.3.
#
# Usage:
#   policy-gate.sh --workspace <terraform-workspace> [--policy <policies-dir>]
#
# Exits 0 on pass, 1 on any policy failure. Always writes machine-readable
# output to evidence/lab-3-4/conftest-results.json.

set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }

mkdir -p "$EVIDENCE_DIR"

# Generate plan.json from a saved tfplan if present, otherwise from a fresh plan.
if [[ -f "$WORKSPACE/tfplan" ]]; then
  ( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )
else
  echo "No tfplan found in $WORKSPACE. Run terraform plan -out=tfplan first." >&2
  exit 2
fi

# Run all four namespaces. Capture JSON output even on failure.
EXIT=0
{
  echo "["
  FIRST=1
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6 ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json" || true)
    # Track failure if any namespace reports failures.
    if echo "$OUT" | grep -q '"failures"'; then
      if echo "$OUT" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)'; then
        :
      else
        EXIT=1
      fi
    fi
    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  echo "See $EVIDENCE_DIR/conftest-results.json for details."
fi

exit $EXIT

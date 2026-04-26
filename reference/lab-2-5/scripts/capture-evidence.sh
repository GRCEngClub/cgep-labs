#!/usr/bin/env bash
# capture-evidence.sh
# Bundle a Terraform workspace's evidence files, hash them, and upload to an
# S3 Object Lock vault. Outputs a single-line JSON receipt to stdout.
#
# Usage:
#   capture-evidence.sh --workspace <path> --run-id <id> --vault <bucket> [--profile <aws-profile>]

set -euo pipefail

PROFILE_ARG=""
WORKSPACE=""
RUN_ID=""
VAULT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --run-id)    RUN_ID="$2";    shift 2 ;;
    --vault)     VAULT="$2";     shift 2 ;;
    --profile)   PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$VAULT" ]] && {
  echo "Usage: $0 --workspace <path> --run-id <id> --vault <bucket> [--profile <p>]" >&2
  exit 2
}

[[ -d "$WORKSPACE" ]] || { echo "Workspace not found: $WORKSPACE" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Pick the right hashing tool.
if command -v sha256sum >/dev/null 2>&1; then
  SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHASUM="shasum -a 256"
else
  echo "Need sha256sum or shasum on PATH." >&2; exit 2
fi

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_DIR="$WORK/bundle-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

# 1. Terraform plan (if a tfplan file exists).
( cd "$WORKSPACE" && \
    [[ -f tfplan ]] && terraform show -json tfplan > "$BUNDLE_DIR/plan.json" 2>/dev/null || true )

# 2. Terraform state (if any state exists).
( cd "$WORKSPACE" && terraform state pull > "$BUNDLE_DIR/state.json" 2>/dev/null || true )

# 3. Latest git commit, if the workspace is in a repo.
( cd "$WORKSPACE" && git log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null || \
   echo "no git commit available" > "$BUNDLE_DIR/commit.txt" )

# 4. Terraform version.
terraform version > "$BUNDLE_DIR/version.txt"

# 5. Manifest with SHA-256 of every file.
{
  echo "["
  FIRST=1
  for f in "$BUNDLE_DIR"/*; do
    base=$(basename "$f")
    [[ "$base" == "manifest.json" ]] && continue
    HASH=$($SHASUM "$f" | awk '{print $1}')
    SIZE=$(wc -c < "$f" | tr -d ' ')
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    cat <<EOF

  {"filename":"$base","sha256":"$HASH","size":$SIZE,"captured_at_utc":"$CAPTURED_AT"}
EOF
  done
  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

# 6. Tar + upload.
BUNDLE_TGZ="$WORK/bundle-$RUN_ID.tar.gz"
( cd "$WORK" && tar czf "$BUNDLE_TGZ" "bundle-$RUN_ID" )

KEY="runs/$RUN_ID/bundle.tar.gz"
UPLOAD_OUT=$(aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" \
  --key "$KEY" \
  --body "$BUNDLE_TGZ" \
  --output json)

VERSION_ID=$(echo "$UPLOAD_OUT" | awk -F'"' '/"VersionId"/{print $4}')

# 7. Receipt to stdout.
printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","captured_at_utc":"%s"}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$CAPTURED_AT"

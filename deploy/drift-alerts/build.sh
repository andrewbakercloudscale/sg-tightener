#!/usr/bin/env bash
# Copy the five modules the drift-alert Lambda needs into deploy/drift-alerts/build/,
# for `aws cloudformation package`. Terraform zips them itself and does not need this.
set -euo pipefail

main() {
  local here root
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  root="$(cd "${here}/../.." && pwd)"
  rm -rf "${here}/build"
  mkdir -p "${here}/build"
  local files=(sg_drift_lambda.py sg_review.py sg_ipintel.py sg_securityhub.py sg_tightener.py)
  for f in "${files[@]}"; do
    cp "${root}/${f}" "${here}/build/${f}"
  done
  echo "build/ ready: ${files[*]}"
}

main "$@"

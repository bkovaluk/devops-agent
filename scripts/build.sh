#!/usr/bin/env bash
# Builds dist/devops-agent.zip for the Lambda python3.12 x86_64 runtime: the locked
# runtime dependencies as manylinux wheels plus the devops_agent package, including
# devops_agent/service_notes.toml when it exists.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${root}/build"
package="${build}/package"
zip_path="${root}/dist/devops-agent.zip"

rm -rf "${build}" "${zip_path}"
mkdir -p "${package}" "${root}/dist"

uv export --frozen --no-dev --no-hashes --no-emit-project \
  --project "${root}" --output-file "${build}/requirements.txt" >/dev/null

uv pip install \
  --quiet \
  --project "${root}" \
  --target "${package}" \
  --python-platform x86_64-manylinux2014 \
  --python-version 3.12 \
  --only-binary :all: \
  --requirement "${build}/requirements.txt"

cp -R "${root}/devops_agent" "${package}/devops_agent"
find "${package}" -type d -name __pycache__ -prune -exec rm -rf {} +

(cd "${package}" && zip -q -r -X "${zip_path}" .)

echo "${zip_path} ($(du -h "${zip_path}" | cut -f1))"

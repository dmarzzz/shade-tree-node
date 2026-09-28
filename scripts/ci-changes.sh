#!/usr/bin/env bash
# CI path gate: prints `run=true|false` to $GITHUB_OUTPUT for a `changes` job.
#
#   bash scripts/ci-changes.sh '<extended regex over repo-relative paths>'
#
# Pull requests run the gated job only when a changed file matches the regex. Every other
# event (push to main, schedule, dispatch) always runs it. A gated job that is skipped
# through `if:` still satisfies a required status check, so heavy jobs can be required
# without running on every docs-only PR.
set -euo pipefail

pattern="${1:?usage: ci-changes.sh <regex>}"
out="${GITHUB_OUTPUT:-/dev/stdout}"

if [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]; then
  echo "run=true" >> "$out"
  exit 0
fi

base="${BASE_SHA:?BASE_SHA must be the pull request base commit}"
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  # actions/checkout leaves a depth-1 clone; fetch just the base commit. Never pass --depth
  # to a full clone: it would make that clone shallow.
  if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
    git fetch --no-tags --depth=1 origin "$base" >/dev/null 2>&1
  else
    git fetch --no-tags origin "$base" >/dev/null 2>&1
  fi
fi
changed="$(git diff --name-only "$base" HEAD)"

if printf '%s\n' "$changed" | grep -Eq "$pattern"; then
  echo "run=true" >> "$out"
else
  echo "run=false" >> "$out"
fi
printf 'changed files:\n%s\n' "$changed"

#!/usr/bin/env bash
# Regenerate the Playwright visual baselines on the CI runner (never on a laptop: font and GPU
# rasterization differ) and put them in the working tree for review.
#
#   scripts/site-baselines.sh [branch]      # default: the current branch (must be pushed)
#
# Dispatches site-quality with update_snapshots=true on <branch>, waits for it, downloads the
# artifact site-baselines-<run id> into test/site-browser/__screenshots__/ and lists what changed.
# Review every changed image, commit the ones the change explains, and push; the normal
# site-quality run on the PR then compares against them. docs/RELEASING.md "Visual baselines".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
branch="${1:-$(git rev-parse --abbrev-ref HEAD)}"
dir=test/site-browser/__screenshots__
workflow=site-quality.yml

local_sha="$(git rev-parse "$branch")"
remote_sha="$(git ls-remote origin "refs/heads/$branch" | cut -f1)"
[ -n "$remote_sha" ] || { echo "branch $branch is not on origin; push it first" >&2; exit 1; }
[ "$local_sha" = "$remote_sha" ] || echo "note: origin/$branch is $remote_sha, local is $local_sha; the runner renders origin" >&2

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
gh workflow run "$workflow" --ref "$branch" -f update_snapshots=true
run=""
for _ in $(seq 1 30); do
  run="$(gh run list --workflow "$workflow" --branch "$branch" --event workflow_dispatch --limit 5 \
    --json databaseId,createdAt -q "[.[] | select(.createdAt >= \"$since\")][0].databaseId")"
  [ -n "$run" ] && break
  sleep 4
done
[ -n "$run" ] || { echo "could not find the dispatched run" >&2; exit 1; }
echo "run $run: $(gh run view "$run" --json url -q .url)"
gh run watch "$run" --exit-status --interval 20 >/dev/null || { echo "baseline run $run failed" >&2; exit 1; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gh run download "$run" -n "site-baselines-$run" -D "$tmp"
cp "$tmp"/*.png "$dir"/
echo "baselines from run $run copied into $dir; changed:"
git status --short -- "$dir"

# Releasing

How a ShadeNet release is built, rehearsed and published. The workflow is
`.github/workflows/release.yml`; the scripts it calls live in `scripts/release/`.

## Rehearse first

Run the release workflow by hand on the branch or commit you intend to tag:

```sh
gh workflow run release.yml --ref <branch>
```

A dispatch builds every target, smoke-tests the live binaries, signs macOS builds when
the Apple secrets exist, generates SBOMs, writes attestations, builds the client image and
runs it. It publishes nothing. The version reads `dev-<sha>`.

`publish-dry-run.yml` runs nightly and on manifest changes. It reports every crate and npm
workspace and fails only when a package that opts into publishing can't pass
`cargo publish --dry-run` or `npm publish --dry-run`.

## Cut the release

1. Move the CHANGELOG `Unreleased` section under `## <version>` and set the same version in
   `package.json` and every crate. CI asserts they agree.
2. Merge that through a pull request, then push an annotated `v<version>` tag on the merged
   commit. `scripts/release-check.mjs` refuses a tag that isn't on main or whose
   changelog section is empty.
3. The tag run publishes, for each of 7 default and 7 live targets:
   - `shadenet-<version>-<target>[-live]` and the same bytes under `shade-tree-…`
     (an alias kept for one minor release), each with `.sha256` and `.spdx.json`
   - build provenance and SBOM attestations
   - `shadenet.rb`, the Homebrew formula for this version
   - `ghcr.io/dmarzzz/shadenet:<version>` and `:latest`, built from the musl live
     binaries, with its own provenance attestation
   - `ghcr.io/dmarzzz/shadenet-node:<version>` (and `:latest` for a final release), the operator
     node image (Tor + node + heartbeat), with its own provenance attestation

   A version with a hyphen (`v0.7.0-rc.1`) is a prerelease: the GitHub Release is marked
   prerelease and never "Latest", the image gets no `:latest`, and the Homebrew tap is left
   on the last final release.

## Verify a download

```sh
gh attestation verify shadenet-<version>-<target>-live --repo dmarzzz/shade-tree-node
sha256sum -c shadenet-<version>-<target>-live.sha256
```

Windows binaries are not Authenticode-signed; the attestation is the verification path.
macOS binaries are signed and notarized when the credentials below are configured, and
are otherwise verified the same way.

## Visual baselines

`site-quality` compares the landing and stake pages with screenshots in
`test/site-browser/__screenshots__/`. When a change is meant to alter how a section looks (new
copy, a new layout), regenerate the baselines on the CI runner, not on a laptop: fonts and GPU
rasterization differ, and a Mac render fails on Linux. The `-macos` files are separate
local-only baselines.

```sh
git push -u origin <branch>
scripts/site-baselines.sh <branch>
```

The script dispatches `site-quality` with `update_snapshots: true` on the branch, waits, and
copies the artifact `site-baselines-<run id>` into the working tree.
- Open every changed image and keep only the sections your change explains.
- Commit them, push, and let the normal `site-quality` run on the PR compare against them.
- Without the script: `gh workflow run site-quality.yml --ref <branch> -f update_snapshots=true`,
  then `gh run download <run id> -n site-baselines-<run id>`.

## Credentials and one-time setup

| What | Where | Needed for |
|---|---|---|
| `APPLE_CERT_P12_BASE64`, `APPLE_CERT_PASSWORD`, `APPLE_SIGNING_IDENTITY` | repository secrets | Developer ID signing |
| `APPLE_NOTARY_KEY_P8_BASE64`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` | repository secrets | notarization (App Store Connect API key) |
| `dmarzzz/homebrew-shadenet` tap repository (exists since 2026-09-30) + `HOMEBREW_TAP_DEPLOY_KEY` (SSH deploy key with write access on the tap only; set) or `HOMEBREW_TAP_TOKEN` (fine-grained, contents:write on the tap only) | GitHub + repository secret | `brew install dmarzzz/shadenet/shadenet`; each final release commits its `shadenet.rb` to `Formula/`. Without a credential, copy it by hand |
| GHCR package visibility | package settings, after the first tag | make `ghcr.io/dmarzzz/shadenet` public |
| crates.io and npm tokens | repository secrets | real publishing, once packages opt in |

Without the Apple secrets, the signing step prints a notice and the release ships
unsigned macOS binaries.

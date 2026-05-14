# Phase 255 Plan 01 Summary

## Delivered

- Replaced the old SBOM-only release workflow with `.github/workflows/release.yml`, triggered by `v*` tags.
- Added repo-owned changelog generation in `tools/generate-changelog.sh` and wired the generated Markdown into GitHub release creation.
- Added multi-arch GHCR publishing, SBOM generation, cosign keyless signing, provenance attestation, and release artifact upload to the tagged workflow.
- Preserved explicit binary release-hardening proof through `tools/verify-release-hardening.sh`.

## Notes

- The workflow is repo-owned end to end: release notes, SBOM, image metadata, container publish, attestation, and GitHub release body all come from tracked repo files or repo-local scripts.

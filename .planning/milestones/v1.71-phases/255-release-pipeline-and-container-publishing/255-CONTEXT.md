# Phase 255 Context

## Goal

Automate tagged releases so the repo can publish versioned multi-arch images with SBOM, signing, provenance attestation, and a generated changelog.

## Starting Point

- The repo already had a local release-hardening verifier and an SBOM-only workflow, but tagged releases were not a full repo-owned publish path.
- Conventional-commit history existed in git, but release notes were still manual.

## Constraints

- The release workflow had to stay repo-owned and readable rather than hidden behind an external release service.
- The tagged path needed to preserve explicit binary hardening proof, SBOM output, container signing, and provenance metadata.
- The release automation had to avoid interactive steps because the target surface is GitHub Actions.

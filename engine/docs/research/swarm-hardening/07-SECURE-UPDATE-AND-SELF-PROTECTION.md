---
title: "07 -- Secure Update and Self-Protection"
series: Swarm Hardening (7 of 8)
version: "0.3"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# Secure Update and Self-Protection

## Analysis of the ClawdStrike Ambush Self-Defense Surface

> Research document for the self-protection, secure update, and runtime
> integrity subsystems of the Swarm Team Six runtime.
> Source: `crates/swarm-crypto/src/`, `crates/swarm-guard/src/`,
> `crates/swarm-spine/src/`, `crates/swarm-runtime/src/http/`,
> `rulesets/default.yaml`, `deny.toml`, `Cargo.toml`

> **Series Note**
> - This is the seventh document in the Swarm Hardening series.
> - It focuses on protecting the swarm binary itself: binary attestation,
>   configuration integrity, runtime self-monitoring, secure update channels,
>   key management, guard pipeline self-application, audit trail anti-tampering,
>   deployment hardening, and incident response for a compromised swarm.
> - It also covers dependency supply chain integrity, runtime memory and process
>   hardening, network self-protection, secrets at rest and in memory,
>   multi-instance trust bootstrap, and backup and recovery.
> - Series-wide status and reading order are maintained in
>   [00-OVERVIEW.md](00-OVERVIEW.md).

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Threat Model: Attacks Against the Swarm Itself](#2-threat-model-attacks-against-the-swarm-itself)
3. [Binary Attestation](#3-binary-attestation)
4. [Configuration Integrity](#4-configuration-integrity)
5. [Runtime Self-Monitoring](#5-runtime-self-monitoring)
6. [Secure Update Channel](#6-secure-update-channel)
7. [Key Management](#7-key-management)
8. [Guard Pipeline Self-Application](#8-guard-pipeline-self-application)
9. [Anti-Tampering for Audit Trail](#9-anti-tampering-for-audit-trail)
10. [Dependency Supply Chain](#10-dependency-supply-chain)
11. [Runtime Memory and Process Hardening](#11-runtime-memory-and-process-hardening)
12. [Network Self-Protection](#12-network-self-protection)
13. [Secrets at Rest and in Memory](#13-secrets-at-rest-and-in-memory)
14. [Multi-Instance Trust Bootstrap](#14-multi-instance-trust-bootstrap)
15. [Backup, Continuity, and Recovery](#15-backup-continuity-and-recovery)
16. [Deployment Hardening](#16-deployment-hardening)
17. [Incident Response for Compromised Swarm](#17-incident-response-for-compromised-swarm)
18. [Proposed Architecture](#18-proposed-architecture)
19. [Open Questions](#19-open-questions)
- [Cross-References](#cross-references)
- [References](#references)
- [Summary of All Gaps](#summary-of-all-gaps)

---

## 1. Abstract

A detection-and-response platform that cannot protect itself is a liability
masquerading as an asset. If an adversary can tamper with the ClawdStrike Ambush
binary, substitute a poisoned ruleset, patch the guard pipeline at runtime, or
corrupt the audit chain, then every detection it produces and every response it
authorizes is untrustworthy.

This document analyzes the self-protection surface of the Swarm Team Six runtime
across three broad categories:

1. **Integrity at rest** -- binary attestation, configuration signing,
   dependency supply chain, and secure update channels.
2. **Integrity at runtime** -- self-monitoring, memory hardening, guard pipeline
   self-application, network surface protection, secret management, and
   audit trail anti-tampering.
3. **Integrity across deployments** -- multi-instance trust bootstrap, backup
   and recovery, deployment hardening, and incident response for a
   compromised swarm instance.

Each section grounds findings in the current codebase (branch
`rescue/v1.39-snapshot`), references exact API signatures from `swarm-crypto`,
`swarm-guard`, `swarm-spine`, and `swarm-runtime`, and identifies gaps with
prioritized mitigations. Platform-specific mechanisms are marked where
applicable.

The document consolidates both the original self-protection research (binary
attestation through incident response) and the gap-fix analysis (dependency
supply chain through backup/recovery) into a unified treatment, because the
threat model demands a single view of the entire self-defense surface.

---

## 2. Threat Model: Attacks Against the Swarm Itself

### 2.1 Adversary Goals

An adversary targeting the swarm runtime (as opposed to the monitored
environment) has four primary goals:

| # | Goal | Impact |
|---|------|--------|
| G1 | **Blind the detector** -- suppress or degrade detection fidelity | Adversary operates undetected within the monitored perimeter |
| G2 | **Corrupt the response** -- cause the swarm to take wrong actions | False containment, denial of service to legitimate workloads |
| G3 | **Destroy the evidence** -- tamper with audit trail or spine chain | Incident reconstruction becomes impossible; legal/compliance exposure |
| G4 | **Weaponize the swarm** -- use its privileged position as a pivot | Lateral movement via response adapters; data exfiltration via SIEM sinks |

### 2.2 Attack Surfaces

| # | Surface | Entry Vector |
|---|---------|-------------|
| A1 | Binary on disk | Supply chain compromise, package repository substitution, local privilege escalation |
| A2 | Configuration | Unauthorized write to `rulesets/default.yaml` or `secret_dir` contents |
| A3 | Runtime memory | Process injection, debugger attachment, shared library interposition |
| A4 | Network interfaces | Operator HTTP surface, NATS JetStream substrate, SIEM/notification sinks |
| A5 | Dependency chain | Malicious crate update, compromised transitive dependency, typosquatting |

### 2.3 Attacker Tiers

| Tier | Description | Expected Capabilities |
|------|-------------|----------------------|
| T1 | **Script kiddie** | Pre-built exploit kits, no custom tooling |
| T2 | **Skilled operator** | Custom implants, OPSEC-aware, can bypass commodity EDR |
| T3 | **APT / state-sponsored** | Zero-day capability, supply chain infiltration, multi-stage campaigns |
| T4 | **Insider threat** | Legitimate access to deployment pipeline, configuration, secrets |

### 2.4 Trust Boundaries

```
                          +----------------------------+
                          |   Build/Release Pipeline   |
                          |  (cargo build, CI, signing)|
                          +----------------------------+
                                      |
                            Binary + Ruleset
                                      |
                          +----------------------------+
                          |      Deployment Host       |
                          |   +---------+---------+    |
                          |   | swarm   | config  |    |
                          |   | binary  | files   |    |
                          |   +---------+---------+    |
                          |   |   Runtime Process  |    |
                          |   +----+----+----+----+    |
                          |        |    |    |         |
                          |   NATS Operator  SIEM     |
                          |  Substrate Surface Sink   |
                          +----------------------------+
```

Every crossing of a trust boundary (build -> deployment, deployment -> runtime,
runtime -> external systems) is a potential integrity violation point. The
remainder of this document addresses protections at each boundary.

---

## 3. Binary Attestation

### 3.1 Goal

Verify at startup that the running binary has not been tampered with since it
was built and signed by the release pipeline. This defends against attack
surface A1 (binary on disk).

### 3.2 Current State

The codebase has no binary attestation mechanism. The swarm runtime starts
unconditionally without verifying its own integrity.

### 3.3 Proposed Design

**Startup self-verification** uses `Ed25519Signer` and
`verify_detached_signature` from `swarm-crypto` (`crates/swarm-crypto/src/lib.rs`):

- `Ed25519Signer::from_secret_material(secret: &str) -> Self` -- derives a
  deterministic signer via `sha256(secret.as_bytes())` -> `Keypair::from_seed`
- `Ed25519Signer::sign(&self, payload: &[u8]) -> DetachedSignature` -- signs
  payload, emitting a self-describing `DetachedSignature` (algorithm, key_id,
  public_key_hex, signature_hex)
- `verify_detached_signature(payload: &[u8], sig: &DetachedSignature) -> Result<(), CryptoError>`
  -- verifies algorithm, key_id binding, and Ed25519 signature

**Release pipeline** (CI):

1. Build: `cargo build --release --locked`
2. Hash: `sha256(binary_bytes)`
3. Sign: `Ed25519Signer::from_secret_material(release_key).sign(&hash)`
4. Ship `(binary, signature.json)` as a release artifact pair

**Startup verification** (runtime):

1. Locate binary via `std::env::current_exe()` (portable: Linux + macOS)
2. Hash: `swarm_crypto::hashing::sha256(&binary_bytes)`
3. Load `<binary_path>.sig`
4. Verify: `verify_detached_signature(&hash_bytes, &loaded_sig)`
5. On failure: Critical-severity event; refuse `live_response` mode
   (detect-only degraded mode permitted to avoid total coverage loss)

### 3.4 Underlying Keypair API

The `Keypair` type (`crates/swarm-crypto/src/signing.rs`) wraps
`ed25519_dalek::SigningKey` and exposes: `generate()`, `from_seed(&[u8; 32])`,
`from_hex(&str)`, `public_key()`, `sign(&[u8])`, and `to_hex()`. It
implements the `Signer` trait (`fn public_key() -> PublicKey` and
`fn sign(&[u8]) -> Result<Signature>`).

`verify_detached_signature` performs three checks: (1) algorithm must be
`"ed25519"`, (2) `key_id == sha256(public_key.as_bytes()).to_hex()` (binds
identity), (3) `public_key.verify(payload, &signature)` succeeds.

**Entropy warning:** `from_secret_material` derives keys via SHA-256 of the
input string. The derived key is only as strong as the input entropy. Release
signing material must have >= 256 bits of entropy.

### 3.5 Gap

**G-BA-1: No binary attestation exists.** The runtime does not verify its own
binary at startup. A T2+ attacker who gains write access to the binary on disk
can substitute a trojanized version that will execute without any integrity
check.

### 3.6 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-BA-1 | Implement startup binary self-verification using `Ed25519Signer` / `verify_detached_signature` | P1 |
| R-BA-2 | Add `--verify-only` CLI flag that exits 0/1 after attestation (for orchestrator health checks) | P2 |
| R-BA-3 | Use `std::env::current_exe()` for portability; document that symlink resolution behavior differs between Linux and macOS | P2 |

---

## 4. Configuration Integrity

### 4.1 Goal

Ensure that the loaded ruleset (`rulesets/default.yaml`) has not been modified
since it was approved. This defends against attack surface A2.

### 4.2 Current State

The runtime loads `rulesets/default.yaml` (or a path specified via CLI) as
plaintext YAML. There is no signature verification, no integrity check, and no
tamper detection watchdog. The configuration surface is large -- it controls
detection strategy, pheromone thresholds, policy rules, response adapter
selection, audit storage, and operator surface authentication.

### 4.3 Proposed Design: Signed Rulesets

**Signing** uses RFC 8785 canonicalization (`canonicalize(value: &Value) -> Result<String>` in `crates/swarm-crypto/src/canonical.rs`). The function
sorts object keys by UTF-16 code unit comparison, formats numbers per ES6
spec, escapes control characters, and produces a deterministic byte-identical
representation regardless of input formatting.

**Workflow:** (1) Parse YAML to `serde_json::Value`, (2) canonicalize,
(3) sign canonical bytes via `Ed25519Signer::sign`, (4) store
`DetachedSignature` as `rulesets/default.yaml.sig`.

**Verification at load time:** Parse -> canonicalize -> load `.sig` ->
`verify_detached_signature(canonical.as_bytes(), &sig)`. On failure: refuse
to start; emit Critical-severity audit event.

### 4.4 Tamper Detection Watchdog

Beyond startup verification, a runtime watchdog should periodically re-hash
the configuration file and compare against the loaded hash. This detects
hot-swap attacks where an attacker modifies the config file after the process
has started.

The `notify` crate (already a workspace dependency, version 7) provides
filesystem event watching. On `Modify` events for the ruleset path, the
watchdog re-verifies the signature. If verification fails:

1. Emit a Critical-severity spine envelope documenting the tamper attempt
2. Enter quarantine mode (cease all response actions; continue detection)
3. Notify operators via the notification channel

### 4.5 Gap

**G-CI-1: No configuration signing or integrity verification.** Any process
with write access to the ruleset file can silently alter detection thresholds,
disable guards, change response adapter selection, or weaken policy rules.

### 4.6 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-CI-1 | Implement signed ruleset verification at load time using RFC 8785 canonicalization + Ed25519 | P1 |
| R-CI-2 | Add a filesystem watchdog for runtime tamper detection of the loaded ruleset | P2 |
| R-CI-3 | Sign the specific YAML-to-JSON canonical representation, not the raw YAML, to avoid whitespace sensitivity | P2 |

---

## 5. Runtime Self-Monitoring

### 5.1 Goal

Detect attempts to tamper with the running swarm process through debugging,
injection, or library interposition. This defends against attack surface A3.

### 5.2 Binary Hash Verification

At startup, hash the running binary via `current_exe()` + `sha256(&bytes)`
to establish a baseline. `std::env::current_exe()` is portable: on Linux it
resolves `/proc/self/exe`; on macOS it uses `_NSGetExecutablePath`. Both
follow symlinks to the real binary.

Periodically (e.g., every 60 seconds) re-hash and compare. A mismatch
indicates on-disk binary replacement while the process is running.

### 5.3 Library Load Detection

**Platform: Linux only.**

Monitor `/proc/self/maps` for unexpected shared library loads. At startup,
snapshot the set of loaded `.so` files. Periodically diff against the current
set. New libraries that were not present at startup and are not on an
allowlist indicate potential `LD_PRELOAD` or `dlopen` injection.

**macOS alternative:** Use `dyld_image_count()` and `dyld_get_image_name()`
from the `mach_o` FFI to enumerate loaded dylibs. The approach is analogous
but requires platform-specific implementation.

### 5.4 Debugger Attachment Detection

**Platform: Linux only.**

Read `/proc/self/status` and parse the `TracerPid` field:

```
TracerPid:	0
```

A non-zero `TracerPid` indicates an active `ptrace` attachment (debugger,
strace, etc.). For a production security binary, this should:

1. Emit a Critical-severity audit event
2. Enter quarantine mode
3. Optionally terminate (configurable -- some environments use legitimate
   process tracing for observability)

**macOS alternative:** Use `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)`
and check the `P_TRACED` flag in `kp_proc.p_flag`. This requires
platform-specific FFI.

### 5.5 File Descriptor Monitoring

**Platform: Linux only.**

Enumerate `/proc/self/fd/` to detect unexpected file descriptors. At startup,
record the baseline set. Periodically check for new FDs that were not opened
by the runtime's own code. Unexpected FDs may indicate:

- Injected sockets (exfiltration channel)
- Hijacked file handles
- Leaked FDs from a compromised parent process

**macOS alternative:** `proc_pidinfo(getpid(), PROC_PIDLISTFDS, ...)` from
`libproc`. Similar concept, different syscall surface.

### 5.6 Gap

**G-SM-1: No runtime self-monitoring exists.** The running process does not
detect debugger attachment, library injection, binary replacement, or unexpected
file descriptor creation.

### 5.7 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-SM-1 | Implement periodic binary hash re-verification using `sha256` from `swarm-crypto` | P2 |
| R-SM-2 | Add `/proc/self/maps` library load monitoring (Linux); stub macOS dyld equivalent | P3 |
| R-SM-3 | Add `TracerPid` debugger detection (Linux); stub macOS `P_TRACED` equivalent | P2 |
| R-SM-4 | Add FD monitoring with baseline snapshot (Linux) | P3 |
| R-SM-5 | Define platform abstraction trait for self-monitoring so Linux/macOS implementations are swappable | P2 |

---

## 6. Secure Update Channel

### 6.1 Goal

Deliver binary and configuration updates to deployed swarm instances with
cryptographic integrity, rollback protection, and atomic installation.

### 6.2 TUF Analysis

The Update Framework (TUF) [1] provides a well-studied model for secure
software updates. Its role-based key architecture maps to the swarm deployment:

| TUF Role | Swarm Mapping | Key Storage | Rotation Frequency |
|----------|---------------|-------------|-------------------|
| Root | Release authority root of trust | Offline HSM or air-gapped machine | Annually or on compromise |
| Targets | Binary/ruleset signing key | CI pipeline secret (e.g., GitHub Actions secret) | Per release cycle |
| Snapshot | Repository state attestation | Automated CI signer | Per publish |
| Timestamp | Freshness guarantee | Automated CI signer | Hourly or per publish |

### 6.3 Update Protocol (10 Steps)

1. **Client checks timestamp metadata** -- fetch `timestamp.json` from the
   update server; verify signature and expiry
2. **Fetch snapshot metadata** -- verify against timestamp's snapshot hash
3. **Fetch targets metadata** -- verify against snapshot's targets hash
4. **Compare target version** -- if the available version matches the
   installed version, stop (no update needed)
5. **Download target** -- fetch the new binary/ruleset
6. **Verify target hash** -- compare `sha256(downloaded)` against the hash
   in `targets.json`
7. **Verify target signature** -- `verify_detached_signature(target, &sig)`
   using the targets key
8. **Rollback check** -- verify that the new version number is strictly
   greater than the installed version (prevents downgrade attacks)
9. **Atomic install** -- write the new binary to a temporary file, then
   `rename(2)` to the target path. On POSIX systems, `rename` is atomic
   within the same filesystem, ensuring the binary is never in a
   partially-written state
10. **Post-install verification** -- hash the installed binary and compare
    against the expected hash before signaling readiness

### 6.4 Rollback Protection

Version monotonicity is enforced by storing the last-installed version in a
signed metadata file. The update client refuses to install any version with
a version number less than or equal to the installed version.

TUF's timestamp role provides freshness: even if an attacker replays an old
`targets.json`, the expired timestamp will cause rejection.

### 6.5 Atomicity via rename(2)

Write the new binary to a temporary file on the same filesystem, set
permissions (`0o755`), then `fs::rename(temp, target)`. On POSIX systems,
`rename` is atomic within the same filesystem. Follow with `fsync` on the
parent directory to ensure durability. This ensures the binary is never in a
partially-written state.

### 6.6 Gap

**G-SU-1: No secure update channel exists.** Updates are manual file
replacement with no integrity verification, no rollback protection, and no
atomicity guarantee.

### 6.7 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-SU-1 | Implement a TUF-inspired update client with timestamp freshness checks | P3 |
| R-SU-2 | Use `rename(2)` for atomic binary installation | P2 |
| R-SU-3 | Store version monotonicity state in a signed local file | P3 |
| R-SU-4 | Integrate update verification with the startup binary attestation (section 3) | P3 |

---

## 7. Key Management

### 7.1 Key Hierarchy

The swarm runtime requires four distinct key roles:

| Key Role | Scope | Lifetime | Storage |
|----------|-------|----------|---------|
| **Root key** | Signs the key hierarchy itself; used to rotate other keys | Multi-year | Offline HSM or air-gapped |
| **Binary signing key** | Signs release binaries (section 3) | Per release cycle | CI pipeline secret |
| **Config signing key** | Signs rulesets (section 4) | Per deployment | Deployment secret (env var or file) |
| **Spine signing key** | Signs audit envelopes (section 9) | Per instance | Runtime-generated or provisioned |

### 7.2 HSM Support via Signer Trait

The `Signer` trait (`fn public_key() -> PublicKey` and
`fn sign(&[u8]) -> Result<Signature>`) provides an abstraction boundary for
key storage. The current `Keypair` implementation holds keys in process
memory. For HSM integration, a new `HsmSigner` can implement `Signer` by
delegating to a PKCS#11 or cloud KMS backend without changing calling code.

### 7.3 Key Rotation

Key rotation requires:

1. **New key generation** -- `Keypair::generate()` using `OsRng`
2. **Cross-signing** -- the old key signs a statement endorsing the new key's
   public key
3. **Distribution** -- the new public key is distributed to all verifiers
   (update clients, peer instances)
4. **Grace period** -- both old and new keys are accepted during rotation
5. **Revocation** -- the old key is removed from the trust set after the
   grace period

### 7.4 Entropy Guidance for from_secret_material()

`Ed25519Signer::from_secret_material` derives the keypair via
`sha256(secret_material.as_bytes())` -> `Keypair::from_seed`. The seed is
exactly the SHA-256 output (32 bytes = 256 bits). However, if the input
`secret_material` has less than 256 bits of entropy, the derived key is
correspondingly weak.

**Minimum requirements:**

- For release signing: `secret_material` must be a 256-bit random hex string
  or equivalent (e.g., `openssl rand -hex 32`)
- For runtime-derived keys: use `Keypair::generate()` (which uses `OsRng`)
  rather than `from_secret_material` to avoid entropy concerns
- For deterministic reproducibility (e.g., test fixtures): document that the
  derived key strength is bounded by input entropy

### 7.5 Gap

**G-KM-1: No key hierarchy exists.** All signing currently uses a single
`Keypair` per instance with no formal key management lifecycle.

### 7.6 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-KM-1 | Define the 4-key hierarchy and document key storage requirements per role | P2 |
| R-KM-2 | Implement an `HsmSigner` behind the `Signer` trait for production deployments | P3 |
| R-KM-3 | Implement cross-signing key rotation protocol | P3 |
| R-KM-4 | Document minimum entropy requirements for `from_secret_material` in the API docs and CONTRIBUTING.md | P1 |

---

## 8. Guard Pipeline Self-Application

### 8.1 Goal

Ensure that the guard pipeline -- the swarm's own safety mechanism -- is itself
protected against bypass, degradation, and panic-induced failure.

### 8.2 Guard Inventory

The guard pipeline is defined in `crates/swarm-guard/src/lib.rs` and consists
of four guards plus a path normalization utility:

#### 8.2.1 ForbiddenPathGuard -- Self-Protection Rating: **HIGH**

`ForbiddenPathGuard` (`crates/swarm-guard/src/forbidden_path.rs`) handles
`FileAccess` and `FileWrite` actions. It normalizes paths via
`normalize_path_for_policy`, checks against exception globs, then matches
against forbidden pattern globs.

Default forbidden patterns: `.ssh/*`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`,
`.aws/*`, `.env`, `.env.*`, `.git-credentials`, `.gitconfig`, `.gnupg/*`,
`.kube/*`, `.docker/*`, `.npmrc`, `.password-store/*`, `/etc/shadow`,
`/etc/passwd`, `/etc/sudoers`.

**Self-protection relevance:** If the swarm's own response adapters attempt to
read or write to sensitive paths (e.g., a misconfigured SIEM adapter writing
to `~/.ssh/`), this guard blocks the action. Rated HIGH because it prevents
the swarm from becoming a data exfiltration tool.

#### 8.2.2 ShellCommandGuard -- Self-Protection Rating: **MEDIUM**

`ShellCommandGuard` (`crates/swarm-guard/src/shell_command.rs`) handles
`ShellCommand` actions. It matches against forbidden regex patterns and
embeds a `ForbiddenPathGuard` for path-level checking of command arguments.

Default forbidden patterns: `rm -rf /`, `curl | bash`, `wget | bash`,
`nc -e` (reverse shell), `bash -i >& /dev/tcp/` (reverse shell),
`base64 | curl/wget/nc` (encoded exfiltration), `mkfs` (disk destruction),
`dd of=/dev/` (device write).

The guard also extracts candidate paths from shell command arguments and
delegates to `ForbiddenPathGuard` for path-level checking.

**Self-protection relevance:** If a response adapter executes shell commands
(e.g., a containment script), this guard prevents catastrophic commands. Rated
MEDIUM because shell command execution should ideally not exist in the
production response path.

#### 8.2.3 SecretLeakGuard -- Self-Protection Rating: **HIGH**

`SecretLeakGuard` (`crates/swarm-guard/src/secret_leak.rs`) handles
`FileWrite` and `ResponseAction` actions. It scans content against 12 compiled
regex patterns: AWS access keys (`AKIA...`), AWS secret keys, GitHub tokens
(`ghp_`, `ghs_`, `github_pat_`), OpenAI keys (`sk-...`), Anthropic keys
(`sk-ant-...`), PEM private keys, npm tokens, Slack tokens, Stripe secret
keys, plus generic API key and generic secret patterns.

The severity threshold (default: `Error`) allows low-severity generic patterns
to pass as warnings while blocking high-confidence patterns.

**Self-protection relevance:** Prevents the swarm from leaking its own secrets
(operator tokens, SIEM auth tokens, signing keys) through response actions or
file writes. Rated HIGH because secret leakage would directly enable adversary
goal G4 (weaponize the swarm).

#### 8.2.4 EgressAllowlistGuard -- Self-Protection Rating: **HIGH**

`EgressAllowlistGuard` (`crates/swarm-guard/src/egress_allowlist.rs`) handles
`NetworkEgress` actions. It evaluates domains against allow and block lists
using wildcard subdomain matching (`*.example.com`).

Default allow list: `*.openai.com`, `*.anthropic.com`, `api.github.com`,
`registry.npmjs.org`, `pypi.org`, `crates.io`, `static.crates.io`.

Default action: `Block` (deny-by-default for unlisted domains).

**Self-protection relevance:** Prevents the swarm from being used as a network
pivot. If a compromised response action attempts to contact an attacker-
controlled server, the guard blocks egress. Rated HIGH because it directly
defends against adversary goal G4.

#### 8.2.5 Path Normalization -- Self-Protection Rating: **IMPLICIT**

`normalize_path_for_policy(path: &str) -> String`
(`crates/swarm-guard/src/path_normalization.rs`) converts `\` to `/`,
collapses repeated separators, removes `.` segments, and resolves `..`
lexically without filesystem access. It does **not** implement the `Guard`
trait; it is called internally by `ForbiddenPathGuard::is_forbidden`.

**Self-protection relevance:** Prevents path traversal bypass of forbidden path
checks (e.g., `/etc/../etc/shadow` normalizes to `/etc/shadow`). Implicit
because it protects other guards rather than acting independently.

### 8.3 Pipeline Composition

`default_pipeline()` in `crates/swarm-guard/src/lib.rs` constructs the
four-guard pipeline in order: ForbiddenPathGuard, ShellCommandGuard,
SecretLeakGuard, EgressAllowlistGuard. Guards are evaluated sequentially; the
pipeline short-circuits on the first block. If all guards allow, it returns
`GuardResult::allow("pipeline")`.

### 8.4 Fail-Closed via catch_unwind

`GuardPipeline::evaluate` wraps each `guard.check()` call in
`catch_unwind(AssertUnwindSafe(|| ...))`. If a guard panics, the pipeline
returns `GuardResult::block` with `Severity::Critical`. It also validates
that guard results have a non-empty guard name, catching implementation
errors. This is a critical self-protection property: panics (from bugs,
adversarial input, or memory corruption) cause the pipeline to **block**
rather than silently allow.

**Tension with panic="abort":** The `catch_unwind` mechanism requires
`panic = "unwind"` in the release profile. If `panic = "abort"` is set,
`catch_unwind` will not catch panics -- instead, the entire process will
terminate. This tension is analyzed in section 11.

### 8.5 Gap

**G-GP-1: Guard pipeline configuration is not protected.** Guard configs
(forbidden patterns, allowlists, severity thresholds) are loaded from the
same unsigned ruleset analyzed in section 4. An attacker who modifies the
config can disable guards (`enabled: false`) or add exceptions that whitelist
their attack paths.

**G-GP-2: No guard self-test at startup.** The pipeline does not verify that
all expected guards are present and functional. A build-time regression or
configuration error that removes a guard from the pipeline would go undetected.

### 8.6 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-GP-1 | Protect guard configuration via signed rulesets (section 4) | P1 |
| R-GP-2 | Add a startup self-test that instantiates `default_pipeline()` and runs a canary check against known-bad inputs | P2 |
| R-GP-3 | Log pipeline composition at startup (guard names and enabled status) at INFO level | P1 |

---

## 9. Anti-Tampering for Audit Trail

### 9.1 Goal

Ensure that the audit trail -- spine envelopes, detection records, policy
decisions, and response receipts -- cannot be silently modified or deleted by
an adversary who has compromised the host. This defends against adversary
goal G3.

### 9.2 Spine Chain Verification

`verify_chain_link(envelope: &Value, known_head: Option<&IssuerChainHead>) -> SpineResult<ChainLinkVerdict>` (`crates/swarm-spine/src/chain.rs`) provides
per-issuer hash chaining. The `ChainLinkVerdict` enum has five variants:
`NewChain`, `ValidContinuation`, `HashMismatch`, `SequenceMismatch`, and
`InvalidChainHead`.

Each envelope contains: `issuer` (`swarm:ed25519:<pubkey_hex>`), `seq`
(monotonic per issuer), `prev_envelope_hash` (SHA-256 of previous; null for
first), `envelope_hash` (SHA-256 of canonical unsigned JSON), and `signature`
(Ed25519 over canonical content).

Validation checks: (1) issuer matches known head (case-insensitive hex),
(2) `seq == head.seq + 1` (no gaps/regressions), (3) `prev_envelope_hash`
matches head's `envelope_hash`, (4) first envelope requires `seq = 1` and
null `prev_envelope_hash`. Overflow protection: `head.seq == u64::MAX`
returns `InvalidChainHead` rather than panicking.

### 9.3 Signed Envelope Construction

`build_signed_envelope(keypair, seq, prev_hash, fact, issued_at)` in
`crates/swarm-spine/src/envelope.rs` constructs an unsigned JSON value
(schema, issuer, seq, prev_envelope_hash, issued_at, capability_token, fact),
canonicalizes via RFC 8785, hashes with `sha256_hex`, signs with
`keypair.sign`, and appends `envelope_hash` + `signature`.

`verify_envelope(envelope)` reconstructs the unsigned form by stripping
`envelope_hash` and `signature`, re-canonicalizes, re-hashes, and verifies
both hash equality and Ed25519 signature validity.

### 9.4 Merkle Tree for Batch Verification

`MerkleTree` (`crates/swarm-crypto/src/merkle.rs`) provides RFC 6962-compatible
construction with domain-separated hashing: `SHA256(0x00 || leaf)` for leaves,
`SHA256(0x01 || left || right)` for nodes. This prevents second pre-image
attacks where a leaf could be confused with an internal node.

Key APIs: `MerkleTree::from_leaves(&[T])`, `from_hashes(Vec<Hash>)`,
`root() -> Hash`, `inclusion_proof(leaf_index) -> Result<MerkleProof>`.
`MerkleProof` provides `verify(leaf_bytes, &expected_root) -> bool` and
`verify_hash(leaf_hash, &expected_root) -> bool`.

**Application to audit trail:** periodically build
`MerkleTree::from_hashes` over recent envelope hashes, sign the root via
`keypair.sign(root.as_bytes())`, and publish as a checkpoint envelope.
Third-party verifiers can request inclusion proofs and verify against the
published root.

### 9.5 Append-Only Storage

The audit trail must be append-only to prevent retroactive deletion:

- **File-backed store:** open with `O_APPEND` flag; disable truncation
- **JetStream-backed store:** configure the stream with `discard: old` and
  retention limits, but never allow explicit message deletion
- **In-memory store:** inherently volatile (see section 15 for continuity gaps)

### 9.6 Remote Attestation

For high-assurance environments, the signed Merkle root can be published to
an external transparency log (e.g., a blockchain anchoring service, a
Google-hosted Trillian instance, or a dedicated internal CT log). This provides
non-repudiation even if the swarm host is fully compromised.

### 9.7 Forward-Secure Logging

Once an audit event is written, an adversary who later compromises the signing
key should not be able to forge historical entries. Forward security is achieved
by key ratcheting:

```
K_0 = initial_seed
K_N = sha256(K_{N-1} || "ratchet")
```

Using `swarm_crypto::hashing::sha256` to compute the ratchet:
`sha256(&[current_seed, b"ratchet"].concat())` produces the next seed, which
is passed to `Keypair::from_seed`. After ratcheting, the previous seed is
zeroized. An adversary who obtains `K_N` can compute forward (`K_{N+1}`, ...)
but cannot recover `K_0 .. K_{N-1}`, preventing forgery of historical entries.

### 9.8 Gap

**G-AT-1: No Merkle tree checkpointing for the audit chain.** The spine chain
provides per-envelope integrity but no batch verification or third-party
attestation.

**G-AT-2: No forward-secure logging.** A single compromised signing key allows
forging the entire audit history.

**G-AT-3: Default audit store is in-memory.** See section 15 (G-REC-1).

### 9.9 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-AT-1 | Implement periodic Merkle tree checkpointing over envelope hashes | P2 |
| R-AT-2 | Implement key ratcheting for forward-secure audit logging | P3 |
| R-AT-3 | Add optional remote attestation via signed Merkle root publication | P4 |
| R-AT-4 | Enforce append-only semantics for file-backed audit stores | P2 |

---

## 10. Dependency Supply Chain

### 10.1 Current State

The workspace ships a `deny.toml` at the repository root. CI
(`.github/workflows/ci.yml`) runs `cargo deny check` on every PR against
`main`. `Cargo.lock` is committed, ensuring reproducible builds.

Key `deny.toml` settings:

| Section | Setting | Value | Assessment |
|---------|---------|-------|------------|
| `[advisories]` | `db-urls` | RustSec advisory-db | Good |
| `[advisories]` | `ignore` | `[]` (empty) | Good |
| `[advisories]` | vulnerability severity | *not set* -- defaults to warn | **Weak** |
| `[licenses]` | `allow` | MIT, Apache-2.0, BSD-3-Clause, BSL-1.0, Unicode-3.0, Unlicense, BSD-1-Clause | Good |
| `[licenses]` | `confidence-threshold` | 0.8 | Good |
| `[bans]` | `multiple-versions` | `"warn"` | Permissive |
| `[bans]` | `wildcards` | `"allow"` | **Weak** |
| `[sources]` | `unknown-registry` | `"warn"` | Acceptable |
| `[sources]` | `unknown-git` | `"warn"` | Acceptable |
| `[sources]` | `allow-registry` | `crates.io` only | Good |

### 10.2 Gaps

**G-SC-1: Advisory violations are warnings, not failures.** The `[advisories]`
section does not set `vulnerability = "deny"`. A crate with a known
vulnerability will produce a CI warning but will not block the PR. For a
security product this should be a hard gate.

**G-SC-2: `wildcards = "allow"` accepts `*` version specs.** Wildcard
dependency specifications undermine the lockfile's reproducibility guarantee.
A hardened configuration should set `wildcards = "deny"`.

**G-SC-3: No `cargo-audit` as a separate CI step.** While `cargo deny check`
subsumes advisory checking, the advisory policy (G-SC-1) means it is
effectively disabled. Adding an explicit `cargo-audit` step with
`--deny warnings` would provide defense in depth until `deny.toml` is
tightened.

**G-SC-4: No dependency pinning policy.** There is no documented policy on
when `cargo update` may run, who reviews lockfile changes, or whether lockfile
diffs require security review. Lockfile updates can silently introduce new
transitive dependencies.

**G-SC-5: No SBOM generation.** For SOC 2, FedRAMP, or customer security
questionnaire compliance, a Software Bill of Materials is increasingly
required. No `cargo-cyclonedx`, `cargo-sbom`, or equivalent is configured.

### 10.3 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-SC-1 | Add `vulnerability = "deny"` to `deny.toml [advisories]` | P0 |
| R-SC-2 | Set `wildcards = "deny"` in `deny.toml [bans]` | P0 |
| R-SC-3 | Add `cargo-audit --deny warnings` CI step | P1 |
| R-SC-4 | Document lockfile update policy (require dedicated PR, two-reviewer approval, diff audit) | P1 |
| R-SC-5 | Add `cargo-cyclonedx` to CI for SBOM generation; publish artifact alongside releases | P2 |
| R-SC-6 | Consider elevating `multiple-versions` to `"deny"` and listing known exceptions explicitly | P2 |

---

## 11. Runtime Memory and Process Hardening

### 11.1 Current State

The codebase is overwhelmingly safe Rust. `unsafe` blocks appear in:

| Location | Context | Production path? |
|----------|---------|------------------|
| `crates/swarm-ingest-tetragon/build.rs` | protobuf codegen | Build-time only |
| `crates/swarm-runtime/src/config.rs` | env-var manipulation in tests | Test only |
| `crates/swarm-runtime/src/http/core.inc` | env-var manipulation in tests | Test only |
| `crates/swarm-runtime/src/ingest.rs` | env-var manipulation in tests | Test only |

All production-path `unsafe` usage is confined to the Tetragon protobuf build
script. The guard pipeline (`swarm-guard`) uses `catch_unwind` to fail closed
on panics (section 8.4), which is a strong defensive measure.

Workspace-level clippy configuration denies `unwrap_used` and `expect_used`
(`Cargo.toml` `[workspace.lints.clippy]`), reducing panic surface in
production code.

### 11.2 Gaps

**G-MEM-1: Missing `// SAFETY:` annotations.** None of the `unsafe` blocks
carry the `// SAFETY:` comment explaining their soundness invariant. Clippy's
`undocumented_unsafe_blocks` lint is not enabled in the workspace lint
configuration.

**G-MEM-2: No release-profile hardening flags.** The workspace `Cargo.toml`
does not define a `[profile.release]` section. Security-relevant settings are
uncontrolled:

- `panic = "abort"` vs `"unwind"` -- abort prevents stack unwinding
  exploitation but loses `catch_unwind` guard protection. The guard pipeline's
  fail-closed behavior depends on `panic = "unwind"`. **This tension must be
  explicitly resolved.**
- `overflow-checks = true` -- enabled by default in debug but *disabled* by
  default in release. A security product should force this on.
- `lto = true` -- enables link-time optimization which also enables
  cross-crate dead code elimination, reducing attack surface.

**G-MEM-3: No allocator hardening analysis.** The runtime uses the system
allocator by default. For a security-critical binary, hardened allocators
(`mimalloc` with guard pages, `jemalloc` with `--enable-prof` and canary
values) offer additional defenses against heap corruption. The tradeoff
against binary size and portability should be documented.

**G-MEM-4: No documented panic strategy.** The workspace denies `unwrap_used`
and `expect_used` in clippy, and the guard pipeline catches panics, but there
is no explicit decision on whether the release binary should use
`panic = "abort"` or `panic = "unwind"`. Since the guard pipeline's
fail-closed behavior (`catch_unwind` in `GuardPipeline::evaluate`) depends on
unwinding, the current design implicitly requires `panic = "unwind"`. This
should be an explicit, documented decision.

Cross-reference: v1.41 HARD-01 requires panic-free critical paths. This
requirement lacks research backing -- the analysis above provides it.

### 11.3 The catch_unwind vs panic="abort" Tension

This deserves explicit treatment because it affects both security posture and
correctness:

| Property | panic="unwind" | panic="abort" |
|----------|---------------|---------------|
| `catch_unwind` works | Yes | No |
| Guard fail-closed on panic | Yes (blocks) | No (process dies) |
| Stack unwinding exploits | Possible (unwind tables) | Eliminated |
| Binary size | Larger (unwind tables) | Smaller |
| Process continuity | Guard panics do not kill process | Guard panics kill process |

**Recommendation:** Use `panic = "unwind"` and rely on the guard pipeline's
`catch_unwind` for fail-closed behavior. Complement with:
- Workspace clippy lints (`unwrap_used = "deny"`, `expect_used = "deny"`)
  to minimize panic sources
- `overflow-checks = true` to catch integer overflow as panics (which are
  then caught by `catch_unwind` and treated as blocks)
- Panic-free critical paths for the detection fast path (swarm-whisker)

### 11.4 Recommendations

| ID      | Action | Priority |
|---------|--------|----------|
| R-MEM-1 | Add `// SAFETY:` annotations to all `unsafe` blocks; enable `undocumented_unsafe_blocks = "deny"` in workspace clippy lints | P1 |
| R-MEM-2 | Add explicit `[profile.release]` with `overflow-checks = true`, `panic = "unwind"` (with documented rationale), and `lto = true` | P1 |
| R-MEM-3 | Evaluate allocator alternatives; document the decision even if the system allocator is retained | P2 |
| R-MEM-4 | Document the panic strategy: `unwind` is required for guard `catch_unwind`; verify HARD-01 panic-free paths do not conflict | P1 |

---

## 12. Network Self-Protection

### 12.1 Current State

The operator HTTP surface (`crates/swarm-runtime/src/http/`) uses bearer token
authentication via the `require_bearer_auth` axum middleware (line 1805 of
`core.inc`). The middleware extracts the `Authorization: Bearer <token>`
header, compares against the expected token (from `OperatorAuthState`), and
returns `OperatorApiError::unauthorized` on mismatch.

The token is read from an environment variable configured as
`operator_surface.auth.token_env` (default: `SWARM_OPERATOR_TOKEN`). Protected
routes are mounted under `/v1/operator/*` with the auth layer applied via
`middleware::from_fn_with_state`.

The `/metrics` endpoint is mounted *outside* the auth layer (line 739 of
`core.inc`) and is unauthenticated -- intentionally, for Kubernetes probe and
Prometheus scrape compatibility.

The `reqwest` dependency uses `rustls-tls` (no OpenSSL dependency). v1.41
requirement HARD-03b specifies optional TLS via `tokio-rustls` with optional
mTLS when `tls.client_ca_cert` is set.

The operator surface serves HTML for the review workbench (render module).

### 12.2 Gaps

**G-NET-1: No rate limiting on the HTTP API.** Policy rate limiting exists for
response actions (`max_actions_per_scope_per_minute` in the policy gate,
notification rate limits), but the HTTP API itself has no request rate
limiting. An attacker who obtains or brute-forces the bearer token could flood
the API with requests, causing resource exhaustion. Cross-reference: SC-08
documents rate-limiting patterns for distributed agents that could be adapted
here.

**G-NET-2: No token rotation mechanism.** The bearer token is a static
environment variable. There is no token expiry, no support for multiple valid
tokens during a rotation window, and no documented rotation procedure. Secret
hot-reload (`@secret:file-name` with file-watch) exists for adapter secrets
but is not wired to the operator surface token.

**G-NET-3: mTLS is planned but unresearched.** HARD-03b is a requirement
specification, not a threat model analysis. Before implementation, the
following questions need answers:

- Who connects to the operator surface? (Operators from corporate network,
  CI/CD pipelines, Kubernetes probes.)
- What trust boundaries exist? (Same-node, same-cluster, cross-network.)
- Is mTLS sufficient, or is it defense-in-depth on top of bearer tokens?
- What is the certificate lifecycle? (Issuance, rotation, revocation.)
- How does mTLS interact with Kubernetes Ingress/Service Mesh?

**G-NET-4: No browser security headers on the review workbench.** The operator
surface serves HTML via the `render` module. Browser-facing surfaces require:

- `Content-Security-Policy` to prevent XSS
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- CSRF protection for state-mutating POST endpoints (e.g., maintenance
  actions, threat-intel upserts, approval verdicts)

None of these are present.

**G-NET-5: Health/metrics endpoint information leakage.** The `/metrics`
endpoint exposes Prometheus metrics without authentication. While necessary for
Kubernetes probes, these metrics may reveal:

- Number of active detections and findings
- Policy decision rates
- Guard pipeline throughput
- Internal component health states

Mitigation options: bind health/metrics to a separate listen address (common
K8s pattern), or use a separate non-sensitive health probe endpoint while
keeping full metrics behind auth.

### 12.3 Recommendations

| ID      | Action | Priority |
|---------|--------|----------|
| R-NET-1 | Add `tower::limit::RateLimitLayer` or equivalent to the operator HTTP router; configure per-IP and global limits | P1 |
| R-NET-2 | Wire operator token to `@secret:file-name` hot-reload; support overlapping token validity during rotation | P1 |
| R-NET-3 | Write mTLS threat model analysis as research input to HARD-03b before implementation | P1 |
| R-NET-4 | Add security response headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`) to HTML responses; add CSRF tokens to mutating forms | P1 |
| R-NET-5 | Evaluate separate listen address for metrics/health; at minimum document what the metrics endpoint reveals | P2 |

---

## 13. Secrets at Rest and in Memory

### 13.1 Current State

The project supports two secret resolution strategies:

- `@secret:env:VARIABLE_NAME` -- reads from an environment variable
- `@secret:file-name` -- reads from a file under `runtime.secret_dir`

Secret resolution is implemented in `crates/swarm-runtime/src/config.rs`.
Phase 118 shipped independent file-watch for hot secret rotation. The
`SecretLeakGuard` in `swarm-guard` detects credential patterns (AWS keys,
bearer tokens, etc.) in outbound content.

### 13.2 Gaps

**G-SEC-1: No in-memory secret zeroization.** After resolving a `@secret:`
reference, the plaintext token lives in heap memory as a Rust `String`. There
is no use of the `zeroize` or `secrecy` crates to ensure secrets are wiped
from memory when no longer needed. The `signing_key` field in
`swarm_crypto::Keypair` holds an `ed25519_dalek::SigningKey` which does
implement `Zeroize` on drop (via `ed25519-dalek`'s own dependency), but
resolved adapter tokens, SIEM auth tokens, and notification tokens do not
benefit from this. Notably, `zeroize` is already used in the reference vendor
code (`vendor/reference/clawdstrike/libs/hush-core/Cargo.toml`) and could be
adopted with minimal friction.

The workspace `Cargo.toml` does not list `zeroize` or `secrecy` as workspace
dependencies.

**G-SEC-2: No encryption at rest for secret files.** `@secret:file-name`
reads plaintext files from `secret_dir`. In Kubernetes deployments (HELM-01a),
these map to K8s Secrets which are base64-encoded by default, not encrypted,
unless the cluster has etcd encryption-at-rest configured. The runtime has no
mechanism to detect whether the underlying storage is encrypted.

**G-SEC-3: No secret access auditing.** When a secret is resolved or
hot-reloaded, there is no audit log entry recording which secret was accessed,
by which component, at what time. For incident reconstruction, knowing when a
SIEM token was rotated or when a signing key was loaded is valuable.

**G-SEC-4: Hardcoded test secrets.** Test code in `swarm-response` and
`swarm-runtime` uses string literals like `"secret"`, `"splunk-secret"`,
`"notify-secret"` for adapter configuration. While test-only, these patterns
may be copied into production configurations. The boundary between test
fixtures and production secret handling should be explicit.

### 13.3 Recommendations

| ID      | Action | Priority |
|---------|--------|----------|
| R-SEC-1 | Add `zeroize` as a workspace dependency; wrap resolved secrets in `Zeroizing<String>` with `Drop`-based clearing | P1 |
| R-SEC-2 | Document the encryption-at-rest responsibility boundary: Kubernetes cluster operator must enable etcd encryption; the runtime should log a warning at startup if `secret_dir` is world-readable | P2 |
| R-SEC-3 | Emit structured `tracing` events at `INFO` level on secret resolution and rotation, including secret name (not value), component, and timestamp | P1 |
| R-SEC-4 | Add a clippy `#[cfg(not(test))]` guard or naming convention (`test_*`) for fixture secrets; document the boundary in contributor guidelines | P2 |

---

## 14. Multi-Instance Trust Bootstrap

### 14.1 Current State

The runtime is single-instance. The pheromone substrate supports an in-memory
backend and a NATS JetStream backend. The `signed_by` field on pheromone
deposits exists, and `swarm-crypto` provides Ed25519 signing via
`ed25519-dalek` (`crates/swarm-crypto/src/signing.rs`). The `Keypair` type
supports generation, seed import, hex roundtrip, and signing/verification.

The sentinel-convergence series (SC-01, SC-04, SC-06, SC-07) extensively
designs multi-agent consensus, partition tolerance, and distributed
coordination for Phase 6+.

The `issuer_from_keypair` function in `swarm-spine/src/envelope.rs` provides
a canonical identity format: `swarm:ed25519:<pubkey_hex>` (64 hex chars, no
prefix). The `parse_issuer_pubkey_hex` function validates this format and
rejects malformed issuers.

### 14.2 Gaps

**G-TRUST-1: No instance-to-instance authentication.** If multiple swarm
instances share a JetStream backend, there is no mechanism for one instance to
verify that pheromone deposits came from a legitimate peer. The `signed_by`
field exists but there is no trust root, no key distribution story, and no
peer identity registry.

**G-TRUST-2: No anti-replay between instances.** Sequence numbers are
per-issuer within the spine envelope chain, but there is no global ordering or
deduplication across instances sharing a substrate. A compromised instance
could replay another instance's signed deposits.

**G-TRUST-3: No minimum viable multi-instance trust specification.** SC-01
proposes Ed25519 identity + mTLS for Sybil resistance, but the
swarm-hardening series needs to specify the minimum trust story for the
single-node-first deployment model. What is the smallest key distribution and
mutual authentication scheme that allows two instances to share a JetStream
substrate safely, before full BFT consensus?

**Proposed minimum viable trust model:**

1. Each instance generates an Ed25519 keypair at first boot
2. The operator registers each instance's public key in a shared
   configuration file (analogous to SSH `authorized_keys`)
3. All pheromone deposits and spine envelopes are signed with the instance key
4. Receiving instances verify signatures against the registered key set
5. Unknown signers are rejected and logged at Critical severity

This is not Byzantine fault tolerant, but it provides authenticity and
non-repudiation for a two-to-four instance deployment.

### 14.3 Recommendations

| ID        | Action | Priority |
|-----------|--------|----------|
| R-TRUST-1 | Define a trust root for multi-instance deployments: a shared CA or a pinned set of peer public keys in config | P3 |
| R-TRUST-2 | Add substrate-level nonce or JetStream sequence verification to prevent cross-instance replay | P3 |
| R-TRUST-3 | Write a "Minimum Viable Multi-Instance Trust" specification as bridge between this document and SC-01; defer full BFT to sentinel-convergence governance track | P3 |

---

## 15. Backup, Continuity, and Recovery

### 15.1 Current State

A disaster recovery runbook exists (`docs/DR-RUNBOOK.md`) covering four
failure modes: JetStream connection loss, dead-letter disk full, circuit
breaker stuck open, and policy denial storm. The audit trail uses in-memory
or file-backed stores (`audit.bundle_store.kind: memory` in
`rulesets/default.yaml`). The pheromone substrate can use in-memory or
JetStream backends.

### 15.2 Gaps

**G-REC-1: Audit trail defaults to in-memory.** The default configuration
(`rulesets/default.yaml`) sets `audit.bundle_store.kind: memory`. If the
process restarts, all audit history is lost. There is no documented backup or
rotation strategy for file-backed audit stores.

**G-REC-2: No pheromone state snapshot/restore.** The in-memory pheromone
backend has no durability. JetStream provides some durability, but there is no
documented backup or point-in-time recovery procedure for pheromone state.

**G-REC-3: DR runbook does not cover corruption.** The four scenarios in
`docs/DR-RUNBOOK.md` address availability failures. There is no procedure for
detecting or recovering from data corruption in the audit chain, pheromone
substrate, or dead-letter journal. The audit chain uses SHA-256 hashing
(`swarm_crypto::hashing::sha256`) and Ed25519 signing for integrity, but no
verification-on-read or corruption detection is documented.

**G-REC-4: No RTO/RPO targets.** The DR runbook has no stated recovery time
objective (RTO) or recovery point objective (RPO) for any data store.

**G-REC-5: No configuration change history beyond git.** Runtime config
changes (hot-reloaded `@secret:` files, potential future API-driven config
mutations) have no change tracking outside of git commits.

### 15.3 Proposed RTO/RPO Framework

| Data Store | RPO Target | RTO Target | Rationale |
|------------|-----------|-----------|-----------|
| Audit trail | <= 1 bundle | <= 5 minutes | Compliance evidence must survive restart |
| Pheromone substrate | <= evaporation cycle | <= detection latency SLA | Pheromone data is ephemeral by design |
| Dead-letter journal | 0 (append-only) | <= 5 minutes | Evidence of delivery failures must survive |
| Configuration | Last git commit | <= 1 minute (reload) | Git is the source of truth |

### 15.4 Recommendations

| ID      | Action | Priority |
|---------|--------|----------|
| R-REC-1 | Change default `audit.bundle_store.kind` to `file` in `rulesets/default.yaml`; document backup rotation for file-backed stores | P1 |
| R-REC-2 | Design a pheromone state snapshot/restore mechanism for the JetStream backend; for in-memory, document that durability is explicitly waived | P2 |
| R-REC-3 | Extend DR runbook with corruption recovery scenarios: audit chain hash verification failure, pheromone deposit signature mismatch, dead-letter journal truncation | P2 |
| R-REC-4 | Define RTO/RPO targets per data store (see table above) | P2 |
| R-REC-5 | Emit structured log on every hot-reload config change; consider a config change ledger for non-git mutations | P2 |

---

## 16. Deployment Hardening

### 16.1 Filesystem Permissions

The swarm binary and its configuration should be owned by a dedicated service
account with minimal permissions:

```
# Binary: owned by root, read+execute only for the service user
-r-xr-x--- 1 root swarm-svc /opt/swarm/bin/swarm

# Configuration: owned by root, readable by service user
-r--r----- 1 root swarm-svc /opt/swarm/rulesets/default.yaml
-r--r----- 1 root swarm-svc /opt/swarm/rulesets/default.yaml.sig

# Secret directory: owned by root, readable only by service user
drwx------ 2 root swarm-svc /opt/swarm/secrets/

# Audit directory: owned by service user (must write), not world-readable
drwxr-x--- 2 swarm-svc swarm-svc /opt/swarm/audit/

# Dead-letter journal: same as audit
drwxr-x--- 2 swarm-svc swarm-svc /opt/swarm/dead-letter/
```

### 16.2 seccomp Profile

**Platform: Linux only.**

A seccomp-BPF profile should restrict the swarm process to only the syscalls
it needs. The default action should be `SCMP_ACT_ERRNO` (deny), with an
explicit allow list covering: file I/O (`read`, `write`, `openat`, `close`,
`fstat`, `rename`, `unlink`), memory management (`mmap`, `mprotect`, `munmap`,
`brk`), networking (`socket`, `connect`, `bind`, `listen`, `accept4`,
`sendto`, `recvfrom`), async runtime (`epoll_create1`, `epoll_ctl`,
`epoll_wait`, `timerfd_create`, `timerfd_settime`, `futex`, `eventfd2`),
process lifecycle (`clone`, `exit_group`, `exit`), signals (`rt_sigaction`,
`rt_sigprocmask`, `rt_sigreturn`), and crypto (`getrandom`). The profile
should be shipped as a JSON file in the repository for use with Docker or
Kubernetes `securityContext.seccompProfile`.

### 16.3 AppArmor Profile

**Platform: Linux only.**

An AppArmor profile should enforce: binary is read+execute only, rulesets
and secrets are read-only, audit and dead-letter directories are
read+write+append, network is restricted to `inet stream` and `inet dgram`,
and all other filesystem writes are denied. Critical denials: `/proc/*/mem`
(rw), `/proc/kcore` (r). The profile should be shipped in the repository.

### 16.4 Capability Dropping

The swarm binary should start with the minimal Linux capability set:

```
CAP_NET_BIND_SERVICE  # Only if binding to ports < 1024
CAP_DAC_READ_SEARCH   # Only if reading files owned by other users
```

All other capabilities should be dropped. In Kubernetes, configure the pod
security context with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
`allowPrivilegeEscalation: false`, and `capabilities.drop: ["ALL"]`.

### 16.5 Network Namespace Isolation

For maximum isolation, the swarm runtime should run in a dedicated network
namespace with only the required network paths:

- Outbound to NATS JetStream (pheromone substrate)
- Outbound to SIEM endpoint (if configured)
- Outbound to notification endpoints (if configured)
- Inbound on the operator surface bind address
- Outbound to the update server (if auto-update is enabled)

All other network access should be blocked at the namespace level, providing
defense-in-depth on top of the `EgressAllowlistGuard`.

### 16.6 Gap

**G-DH-1: No deployment hardening guidance exists.** The project has no
documented seccomp profile, AppArmor profile, capability dropping guidance,
or filesystem permission recommendations.

### 16.7 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-DH-1 | Ship a reference seccomp profile in the repository | P2 |
| R-DH-2 | Ship a reference AppArmor profile | P3 |
| R-DH-3 | Document filesystem permission requirements in deployment guide | P1 |
| R-DH-4 | Add Kubernetes pod security context to Helm chart (HELM-01a) | P2 |
| R-DH-5 | Document minimal capability set for production deployment | P2 |

---

## 17. Incident Response for Compromised Swarm

### 17.1 Detection Indicators

How do you detect that the swarm itself has been compromised? Key indicators:

| Indicator | Detection Method |
|-----------|-----------------|
| Binary hash mismatch | Runtime self-monitoring (section 5) |
| Config signature invalid | Configuration integrity check (section 4) |
| Debugger attached | TracerPid monitoring (section 5) |
| Unexpected library loaded | /proc/self/maps monitoring (section 5) |
| Spine chain integrity violation | `verify_chain_link` returns `HashMismatch` or `SequenceMismatch` |
| Audit Merkle root mismatch | Merkle checkpoint verification (section 9) |
| Unexpected outbound connections | EgressAllowlistGuard blocks + network monitoring |
| Guard pipeline disabled | Startup self-test (section 8) |
| Signing key compromise | Spine envelopes signed by unknown key |

### 17.2 Automated Containment

When a compromise indicator fires, the swarm should execute an automated
containment sequence:

**Phase 1: Immediate (< 1 second)**

1. **Key zeroize** -- if `zeroize` is available (R-SEC-1), wipe all signing
   keys from memory to prevent further signed actions under the compromised
   identity
2. **Distress signal** -- emit a spine envelope of type
   `swarm.incident.self_compromise` signed with the (about-to-be-zeroized)
   key, containing:
   - Indicator that triggered containment
   - Instance identity
   - Timestamp
   - Last known-good audit chain head

**Phase 2: Quarantine (< 5 seconds)**

3. **Quarantine mode** -- cease all response actions; continue detection in
   read-only mode
4. **Disable operator surface** -- close the HTTP listener to prevent an
   attacker from using the API
5. **Notify operators** -- send critical notification to all configured
   channels

**Phase 3: Evidence Preservation (< 30 seconds)**

6. **Flush audit trail** -- write all in-memory audit bundles to disk
7. **Snapshot pheromone state** -- dump current pheromone concentrations
8. **Write process diagnostics** -- memory map, open FDs, environment
   variables (redacted), loaded libraries

### 17.3 Recovery Procedures

After containment, recovery requires human intervention:

1. **Isolate the host** -- remove from network or terminate the container
2. **Preserve forensic evidence** -- copy audit trail, dead-letter journal,
   pheromone snapshots, core dumps
3. **Investigate root cause** -- determine how the compromise occurred
   (binary tampering, config modification, credential theft, etc.)
4. **Rotate all keys** -- generate new signing keys for all four key roles
   (section 7)
5. **Rebuild from known-good** -- redeploy from a verified binary with
   verified configuration
6. **Verify the audit chain** -- replay the spine chain from genesis using
   `verify_chain_link` and `verify_envelope` to identify the first tampered
   entry
7. **Restore service** -- bring the new instance online in `detect_only`
   mode first, then promote to `live_response` after verification

### 17.4 Gap

**G-IR-1: No automated incident response for self-compromise exists.** There
is no quarantine mode, no distress signal mechanism, no automated key
zeroization, and no documented recovery procedure for a compromised swarm
instance.

### 17.5 Recommendations

| ID     | Action | Priority |
|--------|--------|----------|
| R-IR-1 | Implement quarantine mode that disables response actions while continuing detection | P2 |
| R-IR-2 | Implement distress signal spine envelope emission on compromise detection | P2 |
| R-IR-3 | Add automated key zeroization on compromise indicators (requires R-SEC-1) | P2 |
| R-IR-4 | Document recovery procedures in the DR runbook | P1 |

---

## 18. Proposed Architecture

### 18.1 Architecture Diagram

```
+------------------------------------------------------------------+
|                    SWARM RUNTIME PROCESS                          |
|                                                                  |
|  +------------------+    +------------------+                    |
|  | STARTUP SEQUENCE |    | RUNTIME MONITORS |                    |
|  | 1. Binary attest |    | - Binary re-hash |                    |
|  | 2. Config verify |    | - Library watch   |                    |
|  | 3. Key load      |    | - TracerPid check |                    |
|  | 4. Guard self-test|   | - FD monitoring   |                    |
|  | 5. Chain verify   |   | - Config watchdog |                    |
|  | 6. Audit init    |    +--------+---------+                    |
|  | 7. Self-monitor  |             |                              |
|  | 8. Service start |    +--------+---------+                    |
|  +------------------+    | QUARANTINE GATE  |                    |
|                          | (if any monitor  |                    |
|                          |  fires: disable  |                    |
|                          |  response, keep  |                    |
|                          |  detection)      |                    |
|                          +------------------+                    |
|                                                                  |
|  +-----------+  +-----------+  +-----------+  +-----------+     |
|  |  DETECT   |  |  POLICY   |  |  GUARDS   |  |  RESPOND  |     |
|  | (whisker) |->|  (policy) |->| (pipeline)|->| (response)|     |
|  +-----------+  +-----------+  +-----------+  +-----------+     |
|                                     |                            |
|                              catch_unwind                        |
|                              fail-closed                         |
|                                                                  |
|  +-------+  +--------+  +---------+  +----------+  +--------+  |
|  | SPINE |  | MERKLE |  | CRYPTO  |  | SECRETS  |  | UPDATE |  |
|  | chain |  | tree   |  | Ed25519 |  | zeroize  |  | TUF    |  |
|  | verify|  | ckpt   |  | SHA-256 |  | hot-load |  | client |  |
|  +-------+  +--------+  +---------+  +----------+  +--------+  |
+------------------------------------------------------------------+
```

### 18.2 Hardened Startup Sequence (8 Phases)

| Phase | Action | Failure Mode |
|-------|--------|-------------|
| 1 | Binary attestation: hash running binary, verify `.sig` file | Refuse live_response; allow detect_only with warning |
| 2 | Configuration integrity: canonicalize ruleset, verify signature | Refuse to start |
| 3 | Key material load: load or generate instance keypair | Refuse to start |
| 4 | Guard self-test: instantiate `default_pipeline()`, run canary checks | Log warning; refuse live_response |
| 5 | Chain verification: verify last known spine chain head | Log warning; start new chain if unrecoverable |
| 6 | Audit initialization: open audit store, verify append-only properties | Refuse to start if file-backed store is corrupted |
| 7 | Self-monitoring: snapshot binary hash, library list, FD set, TracerPid | Start monitoring loop |
| 8 | Service start: bind operator surface, connect to NATS, begin detection | Normal operation |

### 18.3 Crate Placement

| Component | Crate | New or Existing |
|-----------|-------|----------------|
| Binary attestation | `swarm-runtime` (startup module) | New module in existing crate |
| Config integrity | `swarm-runtime` (config module) | Extension to existing module |
| Self-monitoring | `swarm-runtime` (new `selfcheck` module) | New module |
| Guard self-test | `swarm-guard` (test harness) | New module |
| Merkle checkpointing | `swarm-spine` (new `checkpoint` module) | New module |
| Key management | `swarm-crypto` (extend `Signer` trait) | Extension to existing crate |
| Update client | `swarm-update` (new crate) | New crate |
| Quarantine mode | `swarm-runtime` (runtime mode) | Extension to existing module |
| Secret zeroization | `swarm-runtime` (config module) | Extension |

### 18.4 Implementation Priority

| Priority | Component | Justification |
|----------|-----------|---------------|
| **P0** | Supply chain hardening (R-SC-1, R-SC-2) | Trivial config change with immediate security benefit |
| **P1** | Binary attestation, config integrity, panic strategy, secret zeroization, rate limiting, token rotation | Core self-protection; blocks most T2 attacks |
| **P2** | Runtime self-monitoring, Merkle checkpointing, deployment hardening, incident response, backup/recovery | Defense-in-depth; blocks T3 attacks and enables forensics |
| **P3** | Secure update channel, HSM integration, key rotation, multi-instance trust | Operational maturity; required for multi-instance deployment |
| **P4** | Remote attestation, forward-secure logging | High-assurance environments only |

---

## 19. Open Questions

### 19.1 Cross-Platform Self-Monitoring

The self-monitoring mechanisms (sections 5.3-5.5) are Linux-specific. macOS
alternatives exist but require platform-specific FFI. Questions:

- Should the self-monitoring module be behind a `#[cfg(target_os)]` feature
  gate?
- Is a trait-based abstraction (with Linux and macOS implementations) worth
  the complexity for a product that primarily deploys to Linux containers?
- Should macOS be supported only for development with a warning that
  self-monitoring is degraded?

### 19.2 TPM Integration

Trusted Platform Module (TPM) 2.0 provides hardware-backed attestation:

- **Measured boot:** the binary hash is extended into a PCR register during
  boot, providing tamper-evident startup
- **Sealed storage:** signing keys can be sealed to a TPM PCR state, so they
  are only accessible when the system is in a known-good configuration
- **Remote attestation:** a third party can verify the platform state via
  TPM quotes

TPM integration is complex and deployment-specific. It should be tracked as
a future research topic.

### 19.3 Multi-Instance Consensus

When does the swarm need Byzantine fault tolerance (BFT)?

- 2-4 instances sharing JetStream: minimum viable trust (section 14.2) is
  sufficient
- 5+ instances with adversarial threat model: BFT consensus (SC-01 design)
  is required
- Single instance: trust is moot; focus on host-level self-protection

The transition from minimum viable trust to BFT should be driven by deployment
scale, not implemented speculatively.

### 19.4 Canary Configurations

The runtime supports canary detection rollout (see `rulesets/default.yaml`
canary/promotion sections). Should this mechanism be extended to self-
protection features?

- Canary a new guard before enabling it for all traffic
- Canary a new self-monitoring check before making it a hard gate
- Roll back self-protection changes that increase false-positive containment

This requires a "self-protection canary" framework that is distinct from the
detection canary.

### 19.5 Panic="abort" for Non-Guard Paths

Section 11.3 resolves the tension in favor of `panic = "unwind"` for the
guard pipeline. Should the non-guard fast path (swarm-whisker detection)
use a separate compilation unit with `panic = "abort"` for maximum hardening?
Cargo does not support per-crate panic strategies, but `cdylib` separation
or process isolation could achieve this.

---

## Cross-References

| This Document Section | Related Artifact | Relationship |
|-----------------------|-----------------|--------------|
| Section 3 (Binary attestation) | `crates/swarm-crypto/src/lib.rs` | `Ed25519Signer`, `verify_detached_signature` APIs |
| Section 3 (Binary attestation) | `crates/swarm-crypto/src/signing.rs` | `Keypair`, `Signer` trait, `PublicKey::verify` |
| Section 4 (Config integrity) | `crates/swarm-crypto/src/canonical.rs` | RFC 8785 canonicalization |
| Section 4 (Config integrity) | `rulesets/default.yaml` | Configuration being protected |
| Section 5 (Self-monitoring) | `crates/swarm-crypto/src/hashing.rs` | `sha256` for binary hashing |
| Section 8 (Guard pipeline) | `crates/swarm-guard/src/lib.rs` | `GuardPipeline`, `default_pipeline()`, `catch_unwind` |
| Section 8 (Guard pipeline) | `crates/swarm-guard/src/forbidden_path.rs` | `ForbiddenPathGuard` |
| Section 8 (Guard pipeline) | `crates/swarm-guard/src/shell_command.rs` | `ShellCommandGuard` |
| Section 8 (Guard pipeline) | `crates/swarm-guard/src/secret_leak.rs` | `SecretLeakGuard` |
| Section 8 (Guard pipeline) | `crates/swarm-guard/src/egress_allowlist.rs` | `EgressAllowlistGuard` |
| Section 8 (Guard pipeline) | `crates/swarm-guard/src/path_normalization.rs` | `normalize_path_for_policy` |
| Section 9 (Audit trail) | `crates/swarm-spine/src/chain.rs` | `verify_chain_link`, `ChainLinkVerdict` |
| Section 9 (Audit trail) | `crates/swarm-spine/src/envelope.rs` | `build_signed_envelope`, `verify_envelope` |
| Section 9 (Audit trail) | `crates/swarm-crypto/src/merkle.rs` | `MerkleTree`, `MerkleProof` |
| Section 10 (Supply chain) | `deny.toml` | Analyzes current config |
| Section 10 (Supply chain) | `.github/workflows/ci.yml` | Documents CI coverage |
| Section 11 (Process hardening) | `Cargo.toml` workspace lints | Grounds clippy policy |
| Section 11 (Process hardening) | v1.41 HARD-01 | Provides research backing for panic-free paths |
| Section 12 (Network) | `crates/swarm-runtime/src/http/core.inc` | Grounds auth analysis |
| Section 12 (Network) | v1.41 HARD-03a/b | Provides research backing for auth + TLS |
| Section 12 (Network) | SC-08 | Rate-limiting patterns to adapt |
| Section 13 (Secrets) | `crates/swarm-runtime/src/config.rs` | Secret resolution code |
| Section 13 (Secrets) | `crates/swarm-guard/src/secret_leak.rs` | SecretLeakGuard |
| Section 14 (Multi-instance) | `crates/swarm-crypto/src/signing.rs` | Ed25519 primitives |
| Section 14 (Multi-instance) | SC-01, SC-07 | Distributed trust designs |
| Section 14 (Multi-instance) | SC-13 | ContingencyLease type proposal (terminology note: maps to `CapabilityLease` in current code) |
| Section 15 (Continuity) | `docs/DR-RUNBOOK.md` | Existing runbook |
| Section 15 (Continuity) | `rulesets/default.yaml` | Default audit/pheromone config |
| Section 16 (Deployment) | HELM-01a | Kubernetes deployment requirements |
| Cross-cutting | [01-ADVERSARIAL-EVASION-AND-DETECTION-ROBUSTNESS.md](01-ADVERSARIAL-EVASION-AND-DETECTION-ROBUSTNESS.md) | Detection hardening (complementary) |
| Cross-cutting | [04-PERFORMANCE-CHARACTERIZATION-UNDER-LOAD.md](04-PERFORMANCE-CHARACTERIZATION-UNDER-LOAD.md) | Performance impact of self-protection overhead |
| Cross-cutting | sentinel-convergence SC-07, SC-08, SC-12, SC-13 | Distributed coordination and rate-limiting designs |

---

## References

1. **The Update Framework (TUF)** -- Cappos, J. et al., "Diplomat: Using
   Delegations to Protect Community Repositories," NSDI 2016.
   https://theupdateframework.io/

2. **MITRE ATT&CK -- Defense Evasion** -- Tactic TA0005: techniques for
   evading detection and bypassing security controls.
   https://attack.mitre.org/tactics/TA0005/

3. **MITRE ATT&CK -- Execution** -- Tactic TA0002: techniques for running
   adversary-controlled code.
   https://attack.mitre.org/tactics/TA0002/

4. **RFC 6962** -- Laurie, B., Langley, A., and E. Kasper, "Certificate
   Transparency," IETF, June 2013.
   https://datatracker.ietf.org/doc/html/rfc6962

5. **RFC 8785** -- Rundgren, A., Jordan, B., and S. Erdtman, "JSON
   Canonicalization Scheme (JCS)," IETF, June 2020.
   https://datatracker.ietf.org/doc/html/rfc8785

6. **Signal Protocol -- Double Ratchet Algorithm** -- Marlinspike, M. and
   Perrin, T., "The Double Ratchet Algorithm," November 2016.
   https://signal.org/docs/specifications/doubleratchet/

7. **ed25519-dalek** -- ISIS Agora Lovecruft and Henry de Valence,
   "ed25519-dalek: Fast and efficient ed25519 signing and verification in
   Rust." https://github.com/dalek-cryptography/curve25519-dalek

8. **cargo-deny** -- EmbarkStudios, "cargo-deny: Cargo plugin for linting
   your dependencies." https://github.com/EmbarkStudios/cargo-deny

9. **RustSec Advisory Database** -- https://rustsec.org/

10. **seccomp-BPF** -- Edge, J., "A seccomp overview," LWN.net, 2015.
    https://lwn.net/Articles/656307/

11. **AppArmor** -- https://apparmor.net/

12. **Linux Capabilities** -- Kerrisk, M., "capabilities(7)," Linux man-pages.
    https://man7.org/linux/man-pages/man7/capabilities.7.html

13. **NIST SP 800-57 Part 1** -- Recommendation for Key Management: Part 1.
    https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final

14. **zeroize crate** -- RustCrypto, "zeroize: Securely zero memory while
    avoiding compiler optimizations."
    https://github.com/RustCrypto/utils/tree/master/zeroize

15. **PKCS#11** -- OASIS, "PKCS #11 Cryptographic Token Interface Standard."
    http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html

16. **Kubernetes Secrets** -- Kubernetes documentation: Secrets.
    https://kubernetes.io/docs/concepts/configuration/secret/

17. **SOC 2 Type II** -- AICPA Trust Services Criteria.
    https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services

18. **CycloneDX SBOM** -- OWASP CycloneDX.
    https://cyclonedx.org/

---

## Summary of All Gaps

| Gap ID | Domain | Summary | Priority |
|--------|--------|---------|----------|
| G-BA-1 | Binary attestation | No binary self-verification at startup | P1 |
| G-CI-1 | Configuration | No signed ruleset verification | P1 |
| G-SM-1 | Self-monitoring | No runtime self-monitoring | P2 |
| G-SU-1 | Secure update | No secure update channel | P3 |
| G-KM-1 | Key management | No key hierarchy | P2 |
| G-GP-1 | Guard pipeline | Guard config not protected | P1 |
| G-GP-2 | Guard pipeline | No guard self-test at startup | P2 |
| G-AT-1 | Audit trail | No Merkle tree checkpointing | P2 |
| G-AT-2 | Audit trail | No forward-secure logging | P3 |
| G-AT-3 | Audit trail | Default audit store is in-memory | P1 |
| G-SC-1 | Supply chain | Advisory violations are warnings | P0 |
| G-SC-2 | Supply chain | `wildcards = "allow"` in deny.toml | P0 |
| G-SC-3 | Supply chain | No cargo-audit CI step | P1 |
| G-SC-4 | Supply chain | No lockfile update policy | P1 |
| G-SC-5 | Supply chain | No SBOM generation | P2 |
| G-MEM-1 | Process hardening | Missing `// SAFETY:` annotations | P1 |
| G-MEM-2 | Process hardening | No release-profile hardening flags | P1 |
| G-MEM-3 | Process hardening | No allocator hardening analysis | P2 |
| G-MEM-4 | Process hardening | No documented panic strategy | P1 |
| G-NET-1 | API surface | No HTTP rate limiting | P1 |
| G-NET-2 | API surface | No token rotation | P1 |
| G-NET-3 | API surface | mTLS planned but unresearched | P1 |
| G-NET-4 | API surface | No browser security headers | P1 |
| G-NET-5 | API surface | Health/metrics information leakage | P2 |
| G-SEC-1 | Secrets | No in-memory zeroization | P1 |
| G-SEC-2 | Secrets | No encryption at rest | P2 |
| G-SEC-3 | Secrets | No secret access auditing | P1 |
| G-SEC-4 | Secrets | Hardcoded test secrets pattern | P2 |
| G-TRUST-1 | Multi-instance | No instance-to-instance auth | P3 |
| G-TRUST-2 | Multi-instance | No anti-replay between instances | P3 |
| G-TRUST-3 | Multi-instance | No minimum viable trust specification | P3 |
| G-REC-1 | Continuity | Audit trail defaults to in-memory | P1 |
| G-REC-2 | Continuity | No pheromone state backup | P2 |
| G-REC-3 | Continuity | DR runbook missing corruption scenarios | P2 |
| G-REC-4 | Continuity | No RTO/RPO targets | P2 |
| G-REC-5 | Continuity | No config change history beyond git | P2 |
| G-DH-1 | Deployment | No deployment hardening guidance | P1 |
| G-IR-1 | Incident response | No automated self-compromise response | P2 |

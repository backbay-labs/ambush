# Ambush: Configuration Reference

> Canonical runtime configuration surface, tuning parameters, and environment
> variables.  
> Last updated: 2026-04-13

---

## Hunt Mission YAML Format

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

Hunt missions are defined in YAML files under `rulesets/`. The runtime
assembles from config, not code: telemetry inputs, detector selection,
pheromone policy, response and notification adapters, async lanes, identity,
operator surfaces, and rollout paths are all declared in repo-owned YAML.

The config is loaded at startup and validated fail-closed: invalid configuration rejects at load time, not at runtime. Unknown fields are rejected (`deny_unknown_fields`).

Operator packaging references:

- [docs/QUICKSTART.md](QUICKSTART.md) for the first-run Docker Compose path
- [docs/DEPLOYMENT.md](DEPLOYMENT.md) for Docker, Compose with NATS, Helm, and
  bare-metal packaging

## Canonical Runtime Configuration Surface

The live Rust runtime reads these repository-owned sections today:

```yaml
schema_version: 1

runtime:
  mode: detect_only | live_response
  telemetry_sources:
    - name: synthetic-process
      subject: telemetry.synthetic.process
    - name: cloudtrail-primary
      bridge:
        kind: cloud_trail
        path: data/cloudtrail.jsonl
    - name: generic-json-primary
      bridge:
        kind: generic_json
        path: data/generic-events.jsonl
        mapping:
          event_id_path: "/meta/id"
          timestamp_path: "/meta/timestamp"
          host_id_path: "/meta/host"
          payload:
            kind: process_start
            parent_process_path: "/proc/parent"
            process_name_path: "/proc/name"
            command_line_path: "/proc/cmd"
  max_in_flight_actions: 4
  drain_timeout_ms: 30000
  require_durable_live_response: true
  max_heap_pressure: 0.90
  temporal_event_window:
    retention_ms: 900000
    max_events: 512
    max_match_span_ms: 300000
    max_predicates_per_match: 8
  governance_degraded_tick_threshold: 3
  partition_contingency_lease_ttl_ms: 300000
  partition_contingency_blast_radius_cap: 1
  # NOTE: `rulesets/default.yaml` does NOT carry this block. That file is
  # digest-signed (`rulesets/default.yaml.sig.json`) and the signing key is not
  # in the repository, so it cannot be edited without breaking its own gate --
  # the same constraint tracked as task #23. Every key below is
  # `#[serde(default)]`, so the shipped ruleset still loads; a deployment that
  # wants a durable lease store has to add the block to its own config.
  containment:
    lease_ttl_ms: 900000
    sweep_interval_ms: 30000
    lease_store_path: ./data/containment-leases.json
  secret_dir: /var/run/swarm-secrets

detection:
  strategy: suspicious_process_tree  # or dns_exfiltration, lateral_movement,
                                     # credential_access, suspicious_scripting,
                                     # persistence, supply_chain, network_connect,
                                     # infrastructure_anomaly, fileless_execution,
                                     # behavioral_anomaly, kill_chain_sequence
  high_confidence_threshold: 0.90
  medium_confidence_threshold: 0.70
  profiles:
    kill_chain_sequence:
      rules_path: sequences/kill-chain-v1.yaml
    fileless_execution:
      min_region_size_bytes: 8192
      privileged_target_processes: [lsass, winlogon]
    behavioral_anomaly:
      min_host_observations: 6
      baseline_half_life_secs: 7200
      rare_role_tools: [powershell.exe, wmic.exe]
    suspicious_process_tree:
      office_parents: [winword, excel, outlook]
    dns_exfiltration:
      suspicious_query_patterns: ["*.evil.invalid"]
    lateral_movement:
      monitored_tools: [wmic.exe, psexec.exe]
    credential_access:
      suspicious_targets: [lsass, sam]
    suspicious_scripting:
      suspicious_interpreters: [powershell.exe, pwsh.exe]
    persistence:
      monitored_registry_roots: [HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
    supply_chain:
      monitored_parent_processes: [msbuild.exe, installutil.exe]
    network_connect:
      suspicious_ports: [4444, 5555]
    infrastructure_anomaly:
      min_sustained_high_cpu_samples: 2
      correlation_window_secs: 120
    kill_chain_sequence:
      rules_path: sequences/kill-chain-v1.yaml

pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
  backend:
    kind: in_memory | local_journal
    path: data/pheromones.jsonl   # local_journal only
  response_playbook:
    rules:
      - threat_class: execution
        severity: HIGH
        min_confidence: 0.90
        max_confidence: 1.0
        actions:
          - type: escalate
            summary: analyst review required for high-confidence execution
            urgency: HIGH
        branches:
          - name: incident_containment
            when:
              min_confidence: 0.97
              modes: [incident]
            actions:
              - type: block_egress
                target: 203.0.113.10
              - type: isolate_host
                host_id: host-1

policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000

response_adapter:
  kind: sandbox | http_edr | webhook
  endpoint: https://edr.example/api/actions   # http_edr only
  url: https://hooks.example/swarm           # webhook only
  auth_token: "@secret:edr-token"            # or @secret:env:SWARM_WEBHOOK_TOKEN
  timeout_ms: 5000
  dead_letter_path: ./dead-letter.jsonl

siem_forward:
  kind: splunk_hec | elk_bulk | chronicle
  endpoint: https://siem.example/ingest
  auth_token: "@secret:siem-token"           # Splunk and Chronicle
  index: swarm-findings                      # elk_bulk only
  customer_id: customer-123                  # chronicle only
  timeout_ms: 5000
  dead_letter_path: ./siem-dead-letter.jsonl

notification_channels:
  pager:
    target_url: https://hooks.example/swarm/pager
    auth_token: "@secret:notify-token"
    request_signature:                    # optional HMAC-SHA256 signing
      header: X-Swarm-Signature
      secret: "@secret:notify-hmac"
    timeout_ms: 5000
    rate_limit:
      max_notifications: 5
      window_ms: 60000
    quiet_hours:
      start_hour_utc: 0
      end_hour_utc: 6
    dead_letter_path: ./notification-pager.jsonl

notification_routing:
  dedup_window_ms: 1000
  rules:
    - min_severity: HIGH
      threat_class: execution
      channels: [pager]

audit:
  bundle_store:
    kind: memory | local_files
    directory: data/replay        # local_files only
  recent_decisions_limit: 20

investigation:
  enabled: false
  worker_count: 1
  max_pending_jobs: 16
  time_budget_ms: 250
  bundle_store:
    kind: memory | local_files
    directory: data/investigations

correlation:
  enabled: false
  time_window_ms: 300000
  min_shared_keys: 1
  candidate_limit: 32
  incident_store:
    kind: memory | local_files
    directory: data/incidents

deception:
  enabled: false
  lifecycle_results_dir: data/deception-lifecycle
  rotation_interval_secs: 86400
  cleanup_grace_secs: 3600
  interaction_fitness_weight: 0.15
  playbook:
    entries:
      - name: finance-canary-file
        decoy_type: canary_token
        target_zone: finance
        host_profile: linux-app
        placement_strategy: high_value_path
        monitoring:
          file_paths:
            - /srv/data/finance/payroll.xlsx
          threat_class: initial_access
          severity: HIGH
          confidence: 0.99
```

### Investigation

- `enabled`: turns the async investigation queue on or off without affecting the hot path.
- `worker_count`: concurrency limit for background investigation workers.
- `max_pending_jobs`: queue depth before new submissions degrade visibly as async failures instead of blocking response execution.
- `time_budget_ms`: hard timeout per investigation job.
- `bundle_store`: where durable investigation bundles are written for later review and correlation.

### Correlation

- `enabled`: turns incident assembly on or off.
- `time_window_ms`: maximum age difference allowed between investigation bundles considered for one incident.
- `min_shared_keys`: minimum overlapping correlation keys required for inclusion.
- `candidate_limit`: how many recent investigation bundles to scan when assembling one incident.
- `incident_store`: where correlated incidents are persisted for operator review.

### Shipped Detector Profile Matrix

The signed `rulesets/default.yaml` bootstrap bundle must stay byte-for-byte
stable to preserve its checked-in signature, so the full shipped detector
profile matrix is documented here as the canonical operator reference.

| Strategy | Representative profile keys |
| --- | --- |
| `suspicious_process_tree` | `office_parents` |
| `dns_exfiltration` | `suspicious_query_patterns` |
| `lateral_movement` | `monitored_tools` |
| `credential_access` | `suspicious_targets` |
| `suspicious_scripting` | `suspicious_interpreters` |
| `persistence` | `monitored_registry_roots` |
| `supply_chain` | `monitored_parent_processes` |
| `network_connect` | `suspicious_ports`, `process_port_allowlist` |
| `infrastructure_anomaly` | `min_sustained_high_cpu_samples`, `correlation_window_secs` |
| `fileless_execution` | `min_region_size_bytes`, `privileged_target_processes` |
| `behavioral_anomaly` | `min_host_observations`, `baseline_half_life_secs`, `rare_role_tools` |
| `kill_chain_sequence` | `rules_path` |

### Pheromone Response Playbooks

- `pheromone.response_playbook.rules[*]` defines the top-level match band. A
  rule still anchors on one `threat_class`, one exact `severity`, and one
  inclusive confidence range.
- `rules[*].actions` is now the fallback ordered action sequence. The runtime
  uses it only when the rule matches and no branch-specific selector overrides
  it.
- `rules[*].branches[*]` adds bounded conditional composition under one matched
  rule. Branches are evaluated in YAML order, and the first matching branch
  wins.
- `branches[*].when` may refine execution by `threat_class`,
  `min_severity`, `max_severity`, `min_confidence`, `max_confidence`, and
  `modes` (`normal`, `alert`, or `incident`).
- Each branch must declare at least one `actions` entry, and branch names are
  optional but must be unique within a rule when present.
- A rule must declare fallback `actions`, at least one branch, or both. This
  keeps the playbook deterministic and fail-closed instead of allowing empty
  matches.
- Branch and fallback actions still route through the normal Pounce -> policy
  -> governance -> executor path. The playbook schema does not introduce a
  second orchestration surface or bypass approval requirements.

### Deception / Calico

- `deception.enabled`: registers `CalicoAgent` in serve mode and enables baseline decoy deployment plus decoy-hit pheromone publication.
- `deception.lifecycle_results_dir`: root directory for the durable Calico decoy inventory and lifecycle snapshot.
- `deception.rotation_interval_secs` and `deception.cleanup_grace_secs`: how long one decoy generation remains active before rotation, and how long rotated assets remain tracked before cleanup.
- `deception.interaction_fitness_weight`: bounded positive blend weight Kitten applies when live decoy interactions should raise candidate fitness.
- `deception.playbook.entries[*].decoy_type`: the asset type routed through the existing `DeployDecoy` response action.
- `target_zone` and `host_profile`: capture where the decoy should be placed and what legitimate workload profile it should emulate.
- `placement_strategy`: repo-owned intent for why the decoy exists. Current values are `baseline`, `high_value_path`, `network_segment`, and `investigation_zone`.
- `monitoring.file_paths`, `monitoring.honeypot_ports`, and `monitoring.canary_credentials`: monitored tripwires. At least one is required per playbook entry.
- `monitoring.threat_class`, `monitoring.severity`, and `monitoring.confidence`: the signed high-confidence Calico finding emitted when a decoy interaction matches. Confidence must stay between `0.95` and `1.0`, and those interactions now feed the durable Kitten evolution score path.

### Schema Versioning

- `schema_version` is now required for repo-owned runtime config. The current compiled schema is `1`.
- The loader still migrates the immediate legacy config shape that omitted `schema_version`, and it logs the migration steps through structured runtime logging.
- Future or unrecognized schema versions are rejected fail closed before the runtime starts.

### Runtime Lifecycle

- `drain_timeout_ms`: maximum time the serve-mode runtime waits for accepted ingest work to finish after entering drain mode.
- `max_heap_pressure`: readiness threshold for `swarm_heap_pressure_ratio`. When the measured ratio exceeds this value, `/readyz` returns HTTP 503.
- `temporal_event_window.retention_ms`: maximum age of retained accepted telemetry available to later sequence detectors. The shipped default is `900000` (15 minutes).
- `temporal_event_window.max_events`: hard cap on retained telemetry records in the shared window. When the cap is exceeded, the oldest retained events are dropped first.
- `temporal_event_window.max_match_span_ms`: maximum temporal span one ordered predicate query may request from the shared window. This must stay less than or equal to `retention_ms`.
- `temporal_event_window.max_predicates_per_match`: hard cap on ordered predicates per query so later sequence rules cannot widen matching cost without an operator-visible config change.
- `detection.profiles.kill_chain_sequence.rules_path`: repo-owned YAML rule pack used by the sequence detector. The shipped detector profile points at `sequences/kill-chain-v1.yaml`.
- `governance_degraded_tick_threshold`: number of consecutive degraded governance-health observations before Tom marks the committee as degraded instead of healthy.
- `partition_contingency_lease_ttl_ms`: default lifetime for pre-staged contingency leases that can be redeemed only while the committee is partitioned.
- `partition_contingency_blast_radius_cap`: maximum number of distinct scopes or hosts one contingency lease can authorize before further destructive actions fail closed.
- `containment.lease_ttl_ms`: how long a containment (`quarantine_file`, `isolate_host`, `suspend_process`, `terminate_user_session`) may hold before the sweep releases it. Must be greater than zero: this bound is what makes autonomous containment reversible rather than permanent.
- `containment.sweep_interval_ms`: how often expired leases are checked for. A containment can therefore outlive its TTL by at most `lease_ttl_ms + sweep_interval_ms`.
- `containment.lease_store_path`: where open leases are persisted. **Set this for any `mode: live_response` deployment.** Omitting it keeps leases in memory only, so a restart forgets every open containment and no sweep will ever release those hosts; an operator has to release them by hand. `detect_only` needs no store, because nothing it does takes effect.

- `secret_dir`: optional directory used for file-backed `@secret:` references. Relative paths resolve relative to the config file location.
- `anti_tamper.enabled`: turns the runtime self-monitor on or off. The shipped default is `true`.
- `anti_tamper.check_interval_ms`: polling interval for Linux anti-tamper checks.
- `anti_tamper.fail_closed_live_response`: when `true`, a Linux live-response runtime drains and shuts down after anti-tamper detects a debugger attach, probe failure, or unexpected library load.
- `anti_tamper.allowed_library_prefixes`: path prefixes allowed to appear after the initial shared-library baseline without being treated as tamper.

### Releasing a containment early

A containment normally ends when its lease expires and the sweep releases it. An
operator can end one sooner:

```bash
swarmctl quarantine list
swarmctl quarantine release <lease_id>
```

Both talk to a RUNNING `swarm_detect --serve` over HTTP
(`GET /v1/operator/containment/leases`,
`POST /v1/operator/containment/leases/{lease_id}/release`) rather than touching
the lease store locally. That is deliberate and
`docs/decisions/0010-containment-release-goes-through-the-daemon.md` states why:
the daemon holds the lease store as an in-process `Arc` and the governance
receipt chain in memory, so a second writer would fork both. What this costs is
that a release needs the daemon up; with it down, the lease's own TTL is the
only thing that will end the containment.

Requirements:

- `operator_surface.enabled: true`, and `operator_surface.runtime_base_url`
  pointing at the daemon's `--bind` address (or pass `--daemon-url`).
- an `operator_surface.auth` principal granting the `maintenance` scope, with
  its bearer token exported in the named env var. `swarmctl` refuses before
  sending if no principal grants `maintenance`, and says so separately from
  "the token env is unset", because those are different mistakes.
- `runtime.containment.lease_store_path`, in practice. Without it the daemon's
  leases live only in its own memory, which still works for release while the
  process is up but is lost on restart.

Every release — manual or by TTL — goes through the same
`swarm_runtime::containment::release_lease` and is co-signed on the governance
receipt chain by the same authority that authorized the containment. `swarmctl
quarantine release` prints whether that attestation verified, and exits non-zero
if the inverse did not land and the lease is therefore still open.
`swarm_detect` now also evaluates startup attestation before live-response mode can activate:

- repo ruleset attestation lives at `rulesets/attestation.json` and signs the full checked-in `rulesets/**/*.yaml` set with the repo attestation key
- binary attestation lives beside the launched executable as `<binary>.attestation.json` and signs that exact binary digest plus size
- `detect_only` continues to start if attestation fails, but `/startupz` and `/readyz` surface the failed `startup_attestation` component so operators can see why the runtime is unverified
- `live_response` fails closed before the server starts unless both the binary sidecar and the repo ruleset manifest verify

Serve mode now exposes separate lifecycle routes:

- `/startupz`: startup-only checks for schema compatibility, substrate readiness, and telemetry-source presence
- `/readyz`: steady-state readiness, including detector health, substrate/replay health, drain mode, and heap-pressure gating
- `/livez`: simple liveness that stays green while the process is running
- `/healthz`: legacy readiness-compatible status surface with component detail
- `/prestop`: Kubernetes-friendly drain hook that stops new ingest work, waits for in-flight work up to `drain_timeout_ms`, and then triggers clean shutdown

The startup and readiness surfaces now include `checks.startup_attestation` or `components.startup_attestation` with:

- `required`: whether the current runtime mode enforces fail-closed attestation (`true` only for `live_response`)
- `effective_ready`: whether the attestation result currently blocks runtime admission or readiness
- `binary` and `rulesets`: per-artifact verification status, statement path, and failure details

The steady-state readiness and runtime-status surfaces now also include anti-tamper state:

- Linux checks read `TracerPid` from `/proc/self/status` and compare newly mapped shared objects from `/proc/self/maps` against the startup baseline
- `/readyz` and `/healthz` expose `components.anti_tamper` with `ready`, `required`, `effective_ready`, `debugger_attached`, `tracer_pid`, and `unexpected_library_loads`
- `/v2/api/runtime/status` carries the same `anti_tamper` report for operator-visible runtime status
- when `anti_tamper.fail_closed_live_response` is enabled, only supported Linux live-response runtimes fail closed; unsupported platforms surface `status: unsupported` without creating a readiness bypass

When governance is active, `/healthz` and `/readyz` also expose a `governance` component that reports partition state, quorum counts, active contingency leases, and the latest reconciliation report marker. The complete authority state is persisted as a Tom/primary-signed envelope at `governance-partition-state.json` beside the configured `identity.agent_key_dir`, with an adjacent Tom/primary-signed `governance-partition-state.sequence.json` high-water checkpoint. Signed authority state includes the display-to-consensus governor mapping, exact unhealthy-agent observations, healthy/quorum counts, partition state, peers, leases, authorization ledgers, human holds, activity, reports, and receipt chain. This keeps both files on the same stable volume as the identity root in the shipped deployment and prevents a restart from clearing a health veto or changing the operator-visible quorum state.

Startup derives the expected signer from the Tom/primary key loaded from the key store and admitted by the identity registry before it reads governance state. It never trusts an envelope signer or peer identity merely because the state file names it. Existing Tom keys require both files: unsigned legacy JSON, a signed payload from the earlier incomplete schema that lacks health or identity-binding fields, a missing or corrupt file, a wrong signer, or a state sequence older than its checkpoint aborts startup. A valid signed envelope one sequence or more ahead of a lagging checkpoint is the recoverable state-first/checkpoint-second crash case; startup advances the checkpoint. A checkpoint ahead of the envelope fails closed.

The signed state envelope rename is the runtime commit point. If that rename succeeds but the checkpoint write fails, the policy retains the committed in-memory mutation and records a checkpoint-lag condition. Peer admission, health observations, and human hold/binding staging accurately retain their committed result. Receipt issuance is withheld, and receipt consumption, contingency-lease redemption, human-authorization consumption, and release attestation refuse their external effect while retaining the conservative committed ledger/chain mutation. A subsequent governed effect first repairs the signed checkpoint; restart accepts the newer valid state and performs the same repair. Before the first checkpoint exists, initialization is different: a checkpoint failure removes the unanchored state file and fails bootstrap instead of treating it as an established stream.

Fresh automatic initialization is allowed only when the Tom key file is atomically created during the same bootstrap. `RegistryAdmission::Added` is insufficient because registry state is mutable: deleting a registry row while retaining an existing key cannot turn an existing installation into a fresh one.

### Governance State Migration And Rekey

Ordinary daemon startup and `--reinitialize-governance-state` never create a
missing permanent governance lock beside existing anchors. For an upgrade from
the immediately preceding signed schema, or a PVC restore whose copied lock has
a different device/inode, stop every process using the state root and run:

```bash
swarmctl --config /path/to/swarm.yaml identity migrate-governance-lock \
  --confirm-offline \
  --state-path /var/lib/swarm/governance-partition-state.json
```

The command loads (but never creates) the Tom/primary key, verifies its exact
active registry admission, authenticates the old state and checkpoint, then
creates/reuses and fsyncs the permanent lock. It re-signs the unchanged authority
payload with only the new lock binding at state sequence `N+1`, then writes the
checkpoint at `N+1`. Lock-only and state-first/checkpoint-second failures are
safe to retry; a completed retry is idempotent. Unsigned, corrupt, wrong-signer,
checkpoint-ahead, unknown-field, and older signed payloads that omit health or
authorization inputs fail closed. A pre-lock daemon cannot advertise an advisory
owner, so `--confirm-offline` is a real operator assertion, not cosmetic syntax.

Unsigned governance state is deliberately not upgraded in place. Stop every daemon using the state root, preserve the directory for audit, restore the trusted permanent lock if necessary, and run:

```bash
swarm-detect --config /path/to/swarm.yaml --reinitialize-governance-state
```

The command archives any prior envelope/checkpoint with a `.discarded-<timestamp>-<pid>` suffix and creates an empty state signed by the admitted Tom/primary key. On a partial archive or failed replacement initialization it restores the prior files and returns an error; an underlying filesystem failure that also prevents restoration is reported explicitly. A missing checkpoint is still an explicit offline-recovery case and may be reinitialized; ordinary daemon startup never does this implicitly. The command does not copy governor health observations or counts, peer membership, active contingency leases, pending or consumed action authorizations, human-approval holds, partition activity, reconciliation reports, receipt counters, or chain hashes. Those authorities must be re-established after restart.

Do not use `swarmctl identity rotate --role tom`: the command refuses Tom rotation because it cannot atomically re-sign governance history. A future Tom rekey flow must run offline, verify the old envelope against the old admitted key, bind old and new identities through an independently authenticated rotation procedure, and write a new envelope/checkpoint before changing the active key. Other role rotations retain their existing behavior.

The signed checkpoint rejects forged raises, lowers, signer substitutions, and metadata edits, and detects replay of an older state envelope while the checkpoint remains current. It is not a hardware monotonic counter: an attacker able to roll back both signed files to a previously valid pair can evade this local check. Strong joint-file rollback resistance requires an external monotonic store or independently authenticated peer/operator anchor; the shipped local-only runtime claims neither.

### Config Signature Verification

File-backed runtime config now also requires an adjacent detached-signature sidecar:

- config files are verified from `<config-path>.sig.json` before YAML parsing becomes trusted runtime state
- the signed statement currently binds `config_file_name`, `sha256`, and `size_bytes` for the exact config bytes on disk
- `swarm_detect` startup and full config reload both fail closed when the sidecar is missing, signed by an untrusted key, or no longer matches the config bytes
- secret-only reloads remain scoped to `runtime.secret_dir` changes and do not re-sign or re-verify the YAML file

This applies to the shipped repo config too:

- [default.yaml](../rulesets/default.yaml)
- [default.yaml.sig.json](../rulesets/default.yaml.sig.json)

Operationally:

- treat the config file and `.sig.json` sidecar as one deployment unit
- update the sidecar whenever the YAML changes, before restarting `swarm_detect` or asking the runtime to reload from disk
- expect `swarmctl validate`, `swarm_detect`, and any runtime-owned file loader using the shared config loader to reject unsigned or tampered config files

### Supply Chain Hardening And SBOM

The repository now treats dependency hygiene and release inventory as part of the same integrity story:

- `Cargo.toml` now pins every first-party workspace dependency to an explicit internal version instead of inheriting wildcard path requirements through `[workspace.dependencies]`
- `deny.toml` now denies wildcard dependency requirements, broadens the explicit license allowlist to match the shipped transitive graph, and documents the two currently accepted RustSec advisories that do not yet have safe upstream replacements in the current shipped stack
- `tools/check-supply-chain.sh` first runs quiet `cargo metadata --locked --format-version 1`, refusing stale manifest resolution before Cargo.lock becomes policy input. It then runs the metadata and lock-identity gate over `deny.toml` plus `Cargo.lock`, followed by ONE `cargo deny --locked check -D advisory-not-detected -D unmatched-skip -D unnecessary-skip advisories licenses bans sources` — `bans` with duplicates ENFORCED, so a new duplicate fails and an accepted one has to be an exact `<crate>@<SemVer 2.0>` `[[bans.skip]]` entry — and a hard `cargo audit --deny warnings`. Cargo-audit 0.22.0 exposes no locked option, so the script retains a byte snapshot and fails if metadata, cargo-deny, or cargo-audit changes Cargo.lock. An executable disposable fixture changes a path dependency's manifest version while retaining its old locked dependency row, then proves the first locked metadata invocation refuses that stale resolution without changing lock bytes
- `tools/negative-registry-ast` is an independently locked executable graph, so the same supply gate validates its locked metadata and immutable lock bytes, then runs a separate zero-waiver `cargo-deny` policy plus `cargo audit --deny warnings`. Its manifest, lock, deny policy, and Rust source are included in the enforcement-surface inventory; root-graph coverage is not treated as coverage of this nested tool.
- every waiver in `deny.toml` carries parsed metadata, and the gate fails without it: `last-checked <YYYY-MM-DD>` and a `clears-when:` clause on both kinds of entry, plus `expires <YYYY-MM-DD>` and a `blast-radius:` note on an `[advisories] ignore`. An `expires` date in the past FAILS the build rather than warning, and the last-checked..expires window is capped at 180 days so a deadline cannot be written far enough out to stop being one. Duplicate waivers carry no expiry because two independent checks make the exact pin self-invalidating. The custom metadata stage owns full textual identity: it splits at the final `@`, requires a non-empty name and valid exact SemVer 2.0, and makes exact `Cargo.lock` name matching authoritative, thereby accepting Cargo-valid leading-underscore and Unicode-XID names without a second name grammar. It requires the complete textual version including `+build`, and rejects every selector when multiple lock rows share its exact name and build-stripped core-plus-prerelease identity. Ambiguity errors list registry/git sources and label source-less rows path/local while stating Cargo.lock omits their filesystem path. Cargo-deny owns duplicate applicability in its scanned graph: `unmatched-skip`, `unnecessary-skip`, and ordinary duplicate errors are denied, so a locked waiver that stops applying fails instead of lingering
- `deny.toml` is the SINGLE SOURCE OF TRUTH for advisory exceptions. The `cargo audit --ignore` flags are read out of `[advisories] ignore` at run time rather than written down a second time, and a literal RustSec id anywhere else on an enforcement surface — a workflow, a `tools/*.sh`, a cargo-audit `audit.toml` — fails the gate as a second list being born. That is also why the currently accepted advisories are not named in this document: read them out of `deny.toml`
- `.github/workflows/ci.yml` fans out repo CI into parallel `fmt`, `panic-contract`, `build`, `clippy`, `test`, `fixture-freshness`, `platform-contract`, `proof-surfaces`, `solver-z3`, `jetstream`, `benchmark`, and `supply-chain` jobs while reusing a shared target cache for the commit under test
- the `solver-z3` CI lane is the only place the optional `z3` feature is compiled at all: every other job builds default features, so `#[cfg(feature = "z3")] evaluate_custom_z3_invariant_impl` and the three tests that exercise it were previously unlinted and unrun anywhere in CI. The lane clippies `--all-targets` AND runs `cargo test -p swarm-runtime --features z3`, so the solver executes rather than merely type-checking; `z3-sys`'s `gh-release` feature downloads a prebuilt solver at build time instead of needing a system libz3
- `promotion.require_solver_result_for_promotion` (default **true**) refuses to promote a candidate whose assurance lineage carries no `proved` solver result. `disabled` and a missing status are rejected identically -- both are the same amount of evidence, none -- while the error's `recorded_status` still distinguishes a stub from an absence. The gate sits DOWNSTREAM of the assurance waiver check and performs no waiver lookup: a bounded operator waiver can excuse a known coverage shortfall, but it cannot manufacture a proof. The curated `rulesets/default.yaml` omits the key (it is frozen by the signed attestation), so the serde default is what makes the shipped configuration fail closed -- writing `#[serde(default)]` instead of `#[serde(default = "...")]` there would silently ship the gate off, which `tracked_default_ruleset_resolves_the_promotion_solver_gate_to_enabled` exists to catch
- every production promotion report carries a solver line unconditionally: either `Solver result: <status> | required_for_promotion=<bool>` or the exact literal `Solver result: NO SOLVER RESULT RECORDED`, so an operator reading a report cannot mistake "never asked" for "proved"
- the solver's DECIDING budget is z3's `rlimit` (`SWARM_EVOLUTION_Z3_RLIMIT`, default 10,000,000 resource units), which counts solver work rather than elapsed time and so reaches the same verdict on a fast and a slow machine. `SWARM_EVOLUTION_Z3_TIMEOUT_MS` (default 30,000) remains as a wall-clock backstop for a solver that hangs outside its own accounting, but it no longer decides anything: a run that ends on the resource budget is recorded as `resource_limit`, a run that ends on the wall clock as `timeout`, and NEITHER is a refutation. `duration_ms` stays on the solver artifact as informational and is deliberately excluded from the artifact's attestation hash, so two runs of the same query attest identically
- `evolution.assurance.allowed_solver_statuses` accepts `resource_limit` alongside `proved`, `counterexample`, `timeout`, `disabled` and `error`. The enum is serialized and its parent is `deny_unknown_fields`, so variants may be added but never renamed or removed. NOTE that the curated `rulesets/default.yaml` lists `disabled` among the allowed statuses -- i.e. it accepts a candidate whose solver never ran. That file is frozen by the ed25519-signed `rulesets/attestation.json` and cannot be edited here; what changed instead is that a proof whose solver was disabled now stamps `proof_system: formal_safety_gate_v2+z3_smt_v1_not_run` rather than claiming `+z3_smt_v1`
- THAT ENTRY IS NOT A HOLE, AND THE REASON IS ENFORCED RATHER THAN ARGUED. `allowed_solver_statuses` governs ASSURANCE (may this proposal continue through the evolution lane?), and `promotion.require_solver_result_for_promotion` governs PROMOTION (may this candidate become production?). The promotion gate hardcodes `proved` and reads `allowed_solver_statuses` nowhere, so a `disabled` status that assurance permits is still refused at the production boundary through the same `SolverResultMissing` variant as an absent one. `the_assurance_allow_list_cannot_authorize_a_promotion` in `crates/swarm-runtime/tests/promotion_solver_gate.rs` is what keeps that true: it hands the gate a lineage whose recorded `allowed_statuses` contains `disabled`, with a config whose allow-list contains it too, and requires the refusal anyway. Rewiring `promotion_solver_block` to consult the assurance allow-list -- the field whose name invites exactly that -- makes only that test fail, which is why it exists separately from the three obligation tests beside it
- THE SHIPPED CONSEQUENCE, stated here because an operator hits it before reading anything else: with the curated ruleset exactly as shipped, production promotion refuses EVERY candidate. The bundle it names declares no `custom_z3` invariant, solver artifacts come only from the `custom_z3` arms, so `solver.status` is always `None`; `enable_z3: false` closes it a second time. Automated promotion of evolved detectors is therefore OFF by default, deliberately. `docs/EVOLUTION.md` carries the recipe for enabling it in a deployment-owned config and records what needs the attestation signing key
- the `jetstream` CI lane uses the repo-owned `tools/with-nats-jetstream.sh` harness so the ignored JetStream substrate tests run against a real containerized NATS instance instead of remaining a local-only proof surface
- `tools/check-hot-path-regression.sh` runs the Criterion hot-path benchmark in CI, compares the emitted p99 sample against `docs/benchmarks/fast-detection-baseline.json`, and fails when the regression threshold is exceeded
- `tools/check-platform-openapi.sh` runs in the `platform-contract` job. It asserts, as two independently reported checks, that `docs/openapi/v2-platform-openapi.json` is a valid OpenAPI 3.1 document and that it is byte-identical to what `generate_platform_openapi` emits. `clients/python/` is generated from that spec, so drift there ships a wrong client
- `tools/check-stigmergic-feedback-benchmark.sh` and `tools/check-adversary-emulation-coverage.sh` run in the `proof-surfaces` job. Each runs its named tests, asserts they actually executed — a libtest name filter that matches nothing exits 0 — and compares every published number against `docs/benchmarks/stigmergic-feedback-baseline.json` and `docs/benchmarks/adversary-emulation-baseline.json` respectively
- `tools/check-worktree-clean.sh` carries the phase-284 clean-tree contract (four assertions: tracked-file mutation, crate-local store roots, untracked/ignored residue outside `target/`, stray empty directories) and runs in three jobs: `test`, `solver-z3` and `proof-surfaces`, each passing its own label so a failure names the lane that dirtied the tree
- `tools/check-gates-wired.sh` runs in the `panic-contract` job. It parses `.github/workflows/*.yml` structurally and fails when any `tools/check-*.sh` or `tools/verify-*.sh` is named by no step's `run:` command. Three gate scripts had drifted out of CI entirely before this existed
- `tools/verify-release-hardening.sh` runs in the `release-hardening` job of `.github/workflows/release.yml`, which `publish-container` depends on. It builds the two shipped binaries in release mode with `-v` and asserts `-C panic=abort` and `-C overflow-checks=on` appear on their rustc invocations, so the image that gets Cosign-signed and attested is verified hardened rather than assumed to be
- `tools/generate-sbom.sh` generates one CycloneDX JSON SBOM per workspace crate and stages the files into a chosen output directory
- `tools/generate-changelog.sh` renders a release changelog from conventional commit history for the tagged release range
- `.github/workflows/release.yml` handles tagged releases end to end: it generates the changelog, verifies the release hardening flags reach the shipped binaries, publishes the multi-arch GHCR image, signs the image with keyless Cosign, pushes build provenance attestation, and attaches the generated `*.cdx.json` SBOM set plus `CHANGELOG.md` to the GitHub release

Operator workflow:

- before shipping a release candidate locally, run `bash tools/check-supply-chain.sh`, `bash tools/check-hot-path-regression.sh`, `bash tools/verify-release-hardening.sh`, and `bash tools/generate-sbom.sh artifacts/sbom`
- generate the release notes preview with `bash tools/generate-changelog.sh --tag vX.Y --to HEAD --output artifacts/CHANGELOG.md` before cutting a tag if you want to review the conventional-commit rendering locally
- tagged releases publish the generated `artifacts/sbom/*.cdx.json` files and `CHANGELOG.md` alongside the signed multi-arch image so operators can compare the shipped dependency inventory with startup attestation, config signatures, and any downstream approval requirements
- treat the SBOM artifact set as release metadata; it complements binary and config attestation, but it does not replace those runtime verification contracts

### Bridge-Backed Telemetry Sources

- A source may define either `subject` for the existing runtime ingest path or `bridge` for a bridge-backed source.
- `bridge.kind: cloud_trail` loads CloudTrail JSON or JSON Lines records from `path` and normalizes them into shared telemetry.
- `bridge.kind: generic_json` loads arbitrary JSON records from `path` and maps them through JSON Pointer fields declared under `mapping`.
- `mapping.payload.kind` currently supports `process_start`, `network_connect`, `dns_query`, `registry_access`, `registry_persistence`, `file_persistence`, and `authentication_event`.
- JSON Pointer paths must start with `/`; invalid pointers are rejected at config load time.

### Adapter Secrets

`http_edr.auth_token`, `webhook.auth_token`, `siem_forward.auth_token`, `notification_channels.*.auth_token`, and `notification_channels.*.request_signature.secret` support direct values or `@secret:` references:

- `@secret:file-name` reads `file-name` from `runtime.secret_dir`
- `@secret:env:VARIABLE_NAME` reads the token from the named environment variable

Mounted secret files are trimmed for trailing newlines so Kubernetes-style projected secrets work without wrapper scripts. When `runtime.secret_dir` is configured, serve mode watches that directory and reloads adapter secrets without process restart.

For Providence-native delivery, configure the `providence_webhook` notification channel with both a bearer token and an HMAC secret. In Phase 150, that channel is no longer treated as a generic one-shot notification sink: Swarm uses it as the Providence incidents endpoint, sends signed `POST /incidents` and `PUT /incidents/:id` lifecycle requests, retries failed writes with exponential backoff, dead-letters terminal failures, and reports Providence readiness on `/healthz` and `/readyz`.

Swarm signs the canonical JSON request body as `X-Swarm-Signature: sha256=<hex>`, and Providence verifies that header before accepting the request.

That same `providence_webhook.request_signature` configuration now covers Swarm's signed Providence ingress: `POST /v1/providence/feedback` and `POST /v1/providence/callback` both require the canonical-body HMAC header. Feedback persists a durable summary of the Swarm-signed evidence deposit on the incident audit trail, while callbacks persist reconciliation state and can pause outbound lifecycle sync when Providence and Swarm require manual review.

For bidirectional SOAR sync, configure a separate `soar_verdict_webhook` notification channel with a request-signature secret. `POST /v1/soar/verdicts` uses the same canonical-body HMAC scheme, accepts bounded Splunk SOAR, Sentinel SOAR, and Chronicle SOAR verdict payloads, and routes them onto the existing false-positive and evolution-feedback path while persisting durable source-system lineage on the incident audit trail.

Phase 152 extends that integration with an embeddable `/v1/demo/widget` surface and short-lived context tokens. Swarm signs those read-only drilldown tokens with the dedicated context-token secret from `operator_surface.auth.context_token_env`, embeds them in Providence links, and accepts them as an alternative to bearer+API-key auth only for scoped `GET /v2/api/findings` and `GET /v2/api/incidents` reads.

Example:

```yaml
schema_version: 1
runtime:
  mode: live_response
  telemetry_sources:
    - name: synthetic-process
      subject: telemetry.synthetic.process
  max_in_flight_actions: 4
  drain_timeout_ms: 30000
  require_durable_live_response: true
  max_heap_pressure: 0.90
  secret_dir: ./secrets

response_adapter:
  kind: webhook
  url: https://hooks.example/swarm
  auth_token: "@secret:env:SWARM_WEBHOOK_TOKEN"
```

### SIEM Finding Forwarding

- `siem_forward` is optional and additive. It does not replace the existing `response_adapter` path for live response actions.
- `kind: splunk_hec` wraps the canonical `swarm_finding` payload in a Splunk HEC event envelope and uses `Authorization: Splunk ...`.
- `kind: elk_bulk` emits NDJSON bulk-index records and supports an optional bearer token plus a required target `index`.
- `kind: chronicle` posts the same canonical `swarm_finding` payload inside the Chronicle transport envelope with optional `customer_id`.
- Every variant reuses the existing retry, circuit-breaker, and dead-letter behavior from `swarm-response`.

### Notification Routing

- `notification_channels` is a named map of webhook-like notification sinks owned by repo config.
- Each channel declares `target_url`, optional `auth_token`, `timeout_ms`, in-memory `rate_limit`, optional UTC `quiet_hours`, and a per-channel dead-letter journal path.
- `notification_routing.rules` matches findings by minimum severity, optional `threat_class`, and optional UTC hour window, then fans matching findings out to one or more named channels.
- Findings with the same `strategy_id` and `ThreatClass` are deduplicated for `dedup_window_ms` and emitted as one `swarm_notification` aggregate containing count, time range, highest severity, and a sample canonical finding.
- Suppressed notifications are written to the channel dead-letter journal and can be listed or replayed through the authenticated operator endpoint `GET|POST /v1/notifications/dead-letter/{channel}`.

### Disaster Recovery

The production recovery procedures for JetStream loss, dead-letter disk-full, stuck-open circuit breakers, and blanket policy deny are documented in [docs/DR-RUNBOOK.md](DR-RUNBOOK.md).

### Operator Review Surface

`RuntimeService::operator_review_status` combines the original hot-path report with:

- investigation queue state, including `last_failure_reason`
- recent persisted investigation summaries and status
- recent incidents and linked hunt IDs
- bounded analyst false-positive rollups derived from the latest signed Providence feedback per reviewed finding, with detector and host summaries over the recent incident window
- bounded advisory alert-tuning recommendations derived from those measured false-positive patterns, including host-scoped exclusion review and detector-threshold review guidance
- freshness markers for hot-path decisions, investigation updates, and incidents

Degraded investigation or incident stores surface as warnings in the operator report. They do not block startup in this milestone.

### Operator Control CLI

The repo now ships a CLI-backed control surface in `swarmctl` for runtime review and stable-ID artifact lookup.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- status --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- --json replay --receipt-id receipt-123 --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- investigation --hunt-id evt-123 --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- incident --incident-id incident:evt-123:1 --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- validate --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- validate --config rulesets/default.yaml --check-endpoints --json
cargo run -p swarm-runtime-http --bin swarmctl -- readiness --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- first-run --config rulesets/default.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- playbook-preview --config rulesets/default.yaml --threat-class execution --severity HIGH --confidence 0.97 --mode incident --json
cargo run -p swarm-runtime-http --bin swarmctl -- init --mode detect_only
cargo run -p swarm-runtime-http --bin swarmctl -- init --mode live_response --output rulesets/custom-live.yaml
```

The CLI labels output by origin:

- `live_runtime_status`: current operator review report from the configured runtime stack
- `config_diagnostic`: repo-owned readiness diagnostics derived from config, substrate health, and first-run telemetry or detector probes
- `guided_first_run`: the bounded onboarding walkthrough that joins readiness, synthetic replay, approval artifacts, and proof export in one report
- `persisted_runtime_artifact`: replay, investigation, or incident artifacts loaded from durable runtime stores
- `offline_replay_artifact`: reserved for the offline replay workflows added in later milestones

The repo-owned control outputs now also carry one explicit top-level envelope
version:

- JSON output from `swarmctl status`, `readiness`, `first-run`,
  `playbook-preview`, `replay`, `investigation`, and `incident` includes
  `schema_version: 1` beside the existing `kind`, `origin`, and payload fields.
- Text output prints the same value as `Schema version: 1` near the report
  header so humans and machine parsers are grounded on the same contract.
- `swarmctl ... --output-schema-version 1` is accepted explicitly today, and
  unsupported values fail closed before rendering output.

Deployment bootstrap commands:

- `swarmctl validate` reuses the runtime config loader, including schema migration, detector-profile validation, and `@secret:` resolution.
- `--check-endpoints` adds 5-second TCP reachability probes for configured response-adapter, SIEM, and notification-channel URLs.
- `--json` emits one structured validation report suitable for CI gates.
- `swarmctl init --mode detect_only|live_response` writes a complete `rulesets/custom.yaml` template with inline comments and prints the matching `swarmctl readiness --config ...` follow-up command. The live-response template defaults to a durable local-journal pheromone backend.
- `swarmctl readiness` runs the first-run readiness diagnostic and fails non-zero when telemetry sources, detector activation, or substrate readiness are not good enough for onboarding. Subject-backed telemetry sources are reported as configuration-validated, while bridge-backed sources are probed or validated according to their transport.
- `swarmctl first-run` reruns the readiness gate, then launches one detect-only sandboxed walkthrough that rehearses policy evaluation and emits a proof bundle for the resulting incident. It does not mint a human-approval receipt or a live governance authorization and therefore requires no voter or evidence signing key. The command can take `--scenario path/to/custom.yaml` when the built-in process-start sample is not appropriate for the active detector mix.
- `swarmctl quickstart` collapses validate, readiness, built-in telemetry injection, and first-finding proof into one command. The signed detect-only bootstrap uses in-memory incident state, so quickstart prints the finding summary directly and only suggests `swarmctl incident` follow-ups when the active config already has durable incident storage enabled.
- `swarmctl playbook-preview` evaluates the checked-in `pheromone.response_playbook` config with one explicit `--threat-class`, `--severity`, `--confidence`, and `--mode` tuple, then returns the matched rule or branch, typed rehearsal blast-radius and rollback metadata for each ordered action, and the approval verdict summary that would govern the live path. The command is side-effect free: it does not call live executors, mint governance receipts, or mutate durable runtime state.
- `swarmctl status` now carries `false_positive_tracking` in JSON and prints the recent reviewed-finding count plus the top detector and host false-positive rates in text mode. The rollup is bounded to the same recent-incident window used by the operator review surface.
- `swarmctl status` now also carries `alert_tuning` in JSON and prints the current recommendation count plus the highest-priority advisory recommendation in text mode. These recommendations remain advisory; the CLI does not write exclusions or detector thresholds automatically.

### Helm Deployment

The repo now ships a base Helm chart at `deploy/helm/swarm-team-six/` for `swarm_detect --serve`.

The chart renders the runtime config from Helm values, mounts secret files into `runtime.secret_dir`, wires the existing `/startupz`, `/readyz`, `/livez`, and `/prestop` surfaces, and includes a declared `charts/nats` dependency for JetStream-backed pheromone storage.

There are now two distinct chart entrypoints:

- `values.yaml`: bootstrap or local integration defaults
- `values-production.yaml`: the supported secure production profile for `v1.53`

Use the production profile for supported deployments:

```bash
helm template swarm-team-six deploy/helm/swarm-team-six \
  -f deploy/helm/swarm-team-six/values-production.yaml

helm install swarm-team-six deploy/helm/swarm-team-six \
  -f deploy/helm/swarm-team-six/values-production.yaml \
  --set image.repository=ghcr.io/example/swarm-team-six \
  --set image.tag=latest
```

The supported production profile is intentionally narrow:

- one detect-server deployment
- one runtime PVC rooted at `/var/lib/swarm`
- one optional bundled NATS StatefulSet with JetStream storage rooted at `/data`
- runtime TLS and secret material mounted from Kubernetes Secrets
- non-root execution, read-only root filesystem, explicit writable scratch volume, and `automountServiceAccountToken: false`
- `operator_surface.enabled: false` until the operator-access milestone ships a supported non-loopback access model

State-root contract for the supported production profile:

- Runtime config: `/etc/swarm/config.yaml` from a read-only ConfigMap mount
- Runtime secret root: `/var/run/swarm-secrets` from a Secret mount and wired to `runtime.secret_dir`
- Runtime TLS root: `/var/run/swarm-tls` from a Secret mount and wired to top-level `tls.*`
- Runtime durable state root: `/var/lib/swarm` from the runtime PVC
- Runtime-owned durable subpaths:
  - `/var/lib/swarm/replay`
  - `/var/lib/swarm/investigations`
  - `/var/lib/swarm/incidents`
  - `/var/lib/swarm/agent-keys`
  - `/var/lib/swarm/agent-identity`
  - `/var/lib/swarm/pheromones/pheromones.jsonl` when the runtime uses `local_journal` instead of JetStream
- Dependency durable state root: `/data` on the bundled NATS JetStream StatefulSet PVC when `nats.enabled=true`

Supported durability matrix:

| Surface | Backing store | Backup expectation | Restore source |
| --- | --- | --- | --- |
| `deploy/helm/swarm-team-six/values-production.yaml` and rendered `/etc/swarm/config.yaml` | Git plus Helm release history | Required, but backed up as repo and release metadata rather than PVC contents | Re-render with Helm, then reapply the release |
| `/var/run/swarm-secrets` and `/var/run/swarm-tls` | Kubernetes Secret objects | Required | Restore the Secret objects before restarting the pod |
| `/var/lib/swarm` runtime state root | Runtime PVC | Required | Restore the runtime PVC snapshot or clone before bringing the deployment back |
| `/var/lib/swarm/pheromones/pheromones.jsonl` in bootstrap `local_journal` mode | Runtime PVC | Required when `nats.enabled=false` | Restored as part of the runtime PVC |
| `/data` JetStream store | NATS StatefulSet PVC | Required when `nats.enabled=true` | Restore the JetStream PVC independently from the runtime PVC |
| `/tmp` scratch volume | `emptyDir` | Not required | Recreated automatically on pod start |

Operationally, this gives two supported durability topologies:

- Bootstrap or local-journal: one durable runtime PVC under `/var/lib/swarm`; pheromone state is restored together with replay, investigation, incident, and identity state.
- Supported production profile: one durable runtime PVC under `/var/lib/swarm` plus one separate JetStream PVC under `/data`; restore them independently and only treat the runtime PVC as sufficient when the deployment is not using JetStream.

Repeatable backup, restore, upgrade, and rollback drills for these two topologies are defined in [docs/DR-RUNBOOK.md](DR-RUNBOOK.md).

### Measured SLO And Capacity Envelope

The supported runtime envelope now comes from the shipped benchmark and the
runtime health surfaces, not from detector-only microbenchmarks or static agent
count heuristics.

Reference host and benchmark commands:

- Apple M1 Max, 10 CPU cores, 32 GiB RAM, Darwin 26.4 (kernel 25.4.0)
- steady-state envelope:
  `cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`
- readiness-shed ceiling:
  `STS_E2E_BENCH_MODE=ramp_until_shed STS_E2E_BENCH_MAX_HEAP_PRESSURE=0.00335 STS_E2E_BENCH_MAX_CONCURRENCY=16 cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`
- 25 warmup requests, 25 events per request
- `detect_only`, `suspicious_process_tree`, `local_journal`, replay
  `local_files`, no async lanes or outbound adapters

Reference measured envelope on that host:

| Contract slice | Result |
| --- | --- |
| Fixed-profile p50 ingest request latency | 6.64 ms |
| Fixed-profile p95 ingest request latency | 8.14 ms |
| Fixed-profile p99 ingest request latency | 9.75 ms |
| Fixed-profile sustained accepted-event throughput | 3,645.23 events/sec |
| Fixed-profile post-run readiness | `/readyz`, `/healthz`, and `/metrics` all `200 OK` |
| Highest stable ramp stage before shed | concurrency `2`, p95 `16.79 ms`, `4,394.19` events/sec |
| First readiness-shedding stage | concurrency `4`, peak heap pressure `0.003383636474609375`, `/readyz` returns `503` |

Hot-path detector-only reference on the same host:

| Contract slice | Result |
| --- | --- |
| p50 hot-path latency | 103.04 us |
| p95 hot-path latency | 109.29 us |
| p99 hot-path latency | 139.21 us |
| Throughput | 8,401.69 events/sec |

Interpret the two tables differently:

- `docs/benchmarks/fast-detection.md` is the Criterion regression guard for the
  bounded ingest -> detect -> deposit -> escalate hot path only
- the `fixed` `end_to_end_ingest_bench` profile is the steady-state operator
  envelope for the shipped HTTP ingest path on the measured host class
- the `ramp_until_shed` `end_to_end_ingest_bench` profile captures the highest
  stable accepted-event rate before `/readyz` sheds for the configured
  `runtime.max_heap_pressure`
- the Helm production profile switches the pheromone substrate to JetStream, so
  re-run both profiles with `STS_E2E_BENCH_BACKEND=jet_stream`,
  `NATS_URL=...`, and the deployment-specific `runtime.max_heap_pressure` or
  cgroup memory limit before treating the local-journal ceiling as a durable
  production ceiling
- the reference ramp run intentionally lowers `runtime.max_heap_pressure` to
  `0.00335` so heap-pressure shedding is observable in a single-process loopback
  harness on a 32 GiB developer machine; treat that as a reproducible sizing
  fixture, not a universal production default

Alert baselines tied directly to shipped surfaces:

| Signal | Source of truth | Warn | Page |
| --- | --- | --- | --- |
| Ingest request latency | `histogram_quantile(0.95, sum(rate(swarm_ingest_request_latency_microseconds_bucket[5m])) by (le))` | over `12,000` us for 15m | over `16,000` us for 5m |
| Accepted ingest rate on the reference host | `rate(swarm_ingest_events_total{status="accepted"}[5m])` | over `2,500` events/sec | over `3,200` events/sec or coupled with latency breach |
| Detector hot-path latency | `histogram_quantile(0.95, sum(rate(swarm_detect_latency_microseconds_bucket[5m])) by (le))` | over `125` us | over `250` us |
| Heap pressure | `swarm_heap_pressure_ratio` and `/readyz` | over `0.75` | `>= runtime.max_heap_pressure` or `/readyz` returns `503` |
| Substrate durability and readiness | `/readyz`, `/healthz`, `components.substrate.effective_ready` | n/a | anything other than ready |
| Bridge intake health | `swarm_bridge_ready`, `swarm_bridge_lag_seconds` | lag rising for one scrape window | any required bridge reports `ready=0` or misses its intake SLA |

These thresholds are reference-host defaults from the steady-state `fixed`
profile, not universal constants. When the detector mix, batch size, substrate,
or `runtime.max_heap_pressure` changes, re-run the benchmark profiles and reset
the alert numbers to the new measured baseline.

Key value surfaces:

- `swarmConfig.runtime.mode`
- `swarmConfig.detection.strategy` or `swarmConfig.detection.strategies`
- `swarmConfig.pheromone.backend`
- `swarmConfig.response_adapter`
- `swarmConfig.siem_forward`
- `swarmConfig.notification_channels`
- `runtimePaths.stateRoot`
- `secrets.files`
- `tls.enabled` and `tls.existingSecret`
- `nats.enabled`

### Durable Agent Identity

Serve mode now persists one Ed25519 seed per runtime agent slot and derives the runtime-facing identity from the public key.

```yaml
identity:
  agent_key_dir: data/agent-keys
```

- Relative paths resolve from the active config file, so checked-in configs remain portable.
- `swarm_detect --serve` reuses the same persisted keys after restart.
- Runtime agent IDs use the stable `swarm:ed25519:<hex>` format in serve mode, while signed pheromone deposits also carry explicit `agent_identity` and `agent_role` metadata.

### Governance And Identity Admission

The active governance contract is defined by a small set of repo-owned config
keys rather than a broad abstract autonomy schema:

- `policy.human_gate_severity`: severity threshold where destructive actions
  must stop for human approval. It applies to the static fallback gate only.
  `policy.rules` is evaluated first, in file order, and the first matching rule
  decides `allow` or `deny` outright; the human gate is reached only when no rule
  matches. A matching `allow` rule therefore passes the policy layer without
  human confirmation, but it cannot replace dispatcher governance admission -
  which is exactly the policy behavior the shipped
  `command-and-control-emergency-block` rule relies on. See
  `docs/CONSENSUS.md` "Human Approval Boundary".
- `policy.lease_ttl_ms`: lifetime of ordinary capability leases minted by the
  policy gate.
- `runtime.governance_degraded_tick_threshold`: number of degraded-health
  observations before governance is reported as degraded.
- `runtime.partition_contingency_lease_ttl_ms` and
  `runtime.partition_contingency_blast_radius_cap`: the bounded contingency
  lease contract for partition-era destructive response.
- `runtime.containment.lease_ttl_ms`, `runtime.containment.sweep_interval_ms`
  and `runtime.containment.lease_store_path`: the bounded, reversible
  containment contract. A `live_response` runtime REFUSES a containment it
  cannot lease, before it executes, so these keys gate whether the four
  containment actions run at all.
- `identity.agent_key_dir`: persisted Ed25519 key root for runtime-owned agent
  identities.
- `identity.registry_dir`: persisted admission registry and rotation continuity
  root.

These keys map directly onto the governance states surfaced by `/healthz` and
`/readyz`. They do not create a second operator-only governance model.

### Governance Degradation And Partition Signals

When multi-instance governance is active, the serve surfaces report a dedicated
`governance` component with:

- current partition state
- total and healthy governor counts
- quorum threshold
- active contingency lease count
- unauthorized partition-action count
- last reconciliation report marker

Interpretation rules:

- `degraded` means quorum still exists, but governors are unhealthy
- `partitioned` means destructive actions fail closed unless a staged lease is
  redeemed successfully
- `healing` means quorum has returned and reconciliation is still in progress

These signals are operator-facing contract, not implementation detail.

### Evolution And Rollout Contract

The active rollout ladder is anchored by four config families:

- `evolution.*` for drafting, mutation, validation, proof, ranking, and durable
  status paths
- `canary.*` for the bounded live canary lane
- `promotion.*` for the bounded production observation lane
- `operator_surface.*` for the local read, review, widget, and export surfaces
  that inspect these artifacts

Read these keys as one state machine:

`evolution -> proof -> canary -> promotion -> review`

The config does not imply automatic fleet rollout or review-surface authority.
It defines where the bounded runtime stores and surfaces each stage.

#### `evolution.fitness_weights`

Multi-objective weights used to rank evolved detector candidates.

```yaml
evolution:
  fitness_weights:
    detection_rate: 0.40
    false_positive_cost: 0.30
    speed: 0.15
    threat_class_coverage: 0.15
```

Three of these four are applied:

- `detection_rate`: candidate catch rate over the pinned corpus
- `false_positive_cost`: `1 - false_positive_rate` against the benign controls
- `threat_class_coverage`: fraction of canonical threat-class templates matched

Each is a count or a rate over fixture content, so the ranking a bundle produces
is the same on every machine.

`speed` is **accepted for compatibility and no longer contributes**. It weighted
an objective computed as `1 / (1 + measured_detect_latency_us / budget)`, where
the measurement is a wall-clock `Instant` delta around the detect stage. That
made a candidate's rank a function of the machine and build profile that happened
to measure it: two operators replaying the identical bundle on different hardware
ranked the same population differently and could promote different detectors,
with a green suite on both.

The objective was removed outright rather than weighted to zero. Fitness is not
the only consumer of the objective vector -- Pareto dominance compares the
objectives component-wise, with no weights at all, to decide which candidates
survive selection. A zero weight would have removed latency from the score while
leaving it deciding survivorship.

Compatibility and behavior:

- a `speed:` entry in an existing weights block still loads and is still
  validated as finite and non-negative; the field is not removable because the
  weights block is `deny_unknown_fields` and `rulesets/default.yaml` carries the
  key under the signed `rulesets/attestation.json`
- the configured `speed` share is **redistributed proportionally** across the
  three applied weights, so the total weight -- and the scale that `fitness` is
  compared and blended on, including the evasion-pressure blend against a 0..1
  closure rate -- is whatever you configured. Only the split changes.
- **rankings change** relative to releases that scored `speed`. That is the
  intent: they stop depending on the machine. A candidate that is perfect on
  every fixture-determined objective now scores the full configured weight total
  instead of being held short of it by a clock reading.
- a weights block whose only non-zero entry is `speed` is now **rejected at
  config validation**. It used to pass and produce a working ranking; under the
  applied weights it would produce a fitness of exactly zero for every candidate,
  a silent total tie. It fails closed at load instead.

The latency measurement is still taken and still recorded. Each population
candidate carries a non-gating `observations` block with the measured
`max_detect_latency_us`, the corpus `advisory_detect_latency_budget_us`, and
`within_advisory_detect_latency_budget` as a recorded fact rather than a verdict.
The autonomous benchmark reports likewise keep `max_detect_latency_us`,
`latency_budget_us`, and `latency_fitness`; the last of these is now a recorded
normalized measurement that no longer feeds `measured_fitness`.

A fitness term for cost that can be trusted has to count work rather than read a
clock. That is a cost model, and it is not this change.

### Authenticated Local Operator Surface

The repo now ships a scoped authenticated operator HTTP surface above the existing CLI.
It stays intentionally bounded, but it is no longer limited to one loopback-only shared bearer token.

Supported contract:

- `operator_surface.bind_addr` may be loopback for local admin use or a non-loopback service address for a dedicated operator deployment
- `operator_surface.auth.principals` defines distinct operator identities, each with one bearer-token env var and one or more scopes
- `operator_surface.auth.context_token_env` separately signs Providence widget and drilldown context tokens; it is read-only and does not grant approval or maintenance authority
- the operator HTTP surface and `/v2/api/*` reuse the same operator principal catalog instead of defining a second identity plane
- external OIDC, SSO, or cloud-IAM federation are still out of scope here; the repo-owned contract is bearer principals plus optional TLS or mTLS at the transport layer

Supported scopes:

- `read`: read-only operator pages and JSON APIs, plus bearer access to `/v2/api/*` when combined with a scoped platform API key
- `rehearse`: rehearsal-proof export from the review surface
- `approve`: approval-set creation and signed approval vote submission
- `maintenance`: threat-intel and threat-class mutation, dead-letter replay, review-driven reverify handoff, and direct maintenance actions

Enable it in repo config:

```yaml
operator_surface:
  enabled: true
  bind_addr: "0.0.0.0:7766"
  runtime_base_url: "https://detect.example"
  public_base_url: "https://operator.example"
  allowed_embed_origins:
    - https://providence.example
  max_list_results: 50
  widget_token_ttl_secs: 900
  auth:
    context_token_env: SWARM_OPERATOR_CONTEXT_TOKEN
    principals:
      - operator_id: operator-readonly
        token_env: SWARM_OPERATOR_READ_TOKEN
        scopes: ["read"]
      - operator_id: operator-rehearse
        token_env: SWARM_OPERATOR_REHEARSE_TOKEN
        scopes: ["read", "rehearse"]
      - operator_id: swarm:ed25519:7d1f...
        token_env: SWARM_OPERATOR_APPROVE_TOKEN
        scopes: ["read", "approve"]
      - operator_id: operator-maintenance
        token_env: SWARM_OPERATOR_MAINT_TOKEN
        scopes: ["read", "maintenance"]
```

- `runtime_base_url` is the detect-server base URL used by the Providence widget, scoped drilldown links, and governed-approval resume. Because resume forwards the authenticated operator bearer, this URL must use HTTPS except for local development on an exact loopback host: `localhost`, any `127.0.0.0/8` address, or `::1`. Plaintext private, link-local, unspecified, remote, credential-bearing, and lookalike hostnames are rejected during configuration validation. Both public `LocalOperatorSurface` config constructors run the complete validation contract before creating stores, clients, or callbacks. Outer whitespace is accepted by validation and then removed from the stored callback URL, so subsequent routing uses exactly the validated target.
- Governed-resume callbacks use one dedicated client that ignores process proxy settings, never follows redirects, and has a 10-second total request timeout. A non-success response is reported using only its HTTP status; its body is neither buffered nor copied into operator diagnostics. A `3xx` is returned as an error without contacting its redirect target, so that refusal leaves the held action pending. A timeout or other transport error can be ambiguous after delivery; operators must inspect the persisted hold before retrying, and the one-time consume contract prevents a retry from executing an already consumed approval again.
- `public_base_url` remains the operator-surface base URL for replay, audit-trail, and review links.
- `allowed_embed_origins` drives `Content-Security-Policy: frame-ancestors` and `X-Frame-Options` for `/v1/demo/widget`.
- `widget_token_ttl_secs` controls the lifetime of the signed read-only context tokens included in Providence links.
- `auth.context_token_env` should be a dedicated signing secret in production; local development may reuse one principal token, but production should keep context-token signing separate from mutable operator credentials.
- every entry in `auth.principals` must use a distinct token env so one bearer secret maps to exactly one operator identity.
- approval voters must authenticate as the same signer-derived operator ID they submit in `voter_id`, and approval sets may only list principals that grant `approve`.

Library compatibility note: the public `RequestResponseRouter::restore_human_preflight`
method now accepts only `(&GovernedHumanAuthorizationHold, &str)`; the former
caller-selected `now_ms` argument was removed. Downstream router implementations
must update their signature for this release. The resume dispatcher samples its
host clock after all awaited artifact loading and side-effect-free preflight work,
then uses that same trusted time for pack freshness, durable governance
consumption, lease construction, audit context, and execution.

Optional TLS for both `swarm_detect --serve` and `swarmctl serve` is configured once at the top level:

```yaml
tls:
  cert_path: /etc/swarm/tls/server-cert.pem
  key_path: /etc/swarm/tls/server-key.pem
  client_ca_cert: /etc/swarm/tls/client-ca.pem # optional; enables mTLS when set
```

The versioned detect-server platform API now requires both a `read`-scoped operator bearer token and a scoped platform API key:

```yaml
platform_api:
  keys:
    - name: primary-reader
      key_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      scopes: ["read"]
```

Start it through the existing repo-owned binary:

```bash
export SWARM_OPERATOR_CONTEXT_TOKEN=replace-me-with-a-readonly-context-secret
export SWARM_OPERATOR_READ_TOKEN=replace-me-with-a-readonly-secret
export SWARM_OPERATOR_REHEARSE_TOKEN=replace-me-with-a-rehearse-secret
export SWARM_OPERATOR_APPROVE_TOKEN=replace-me-with-an-approve-secret
export SWARM_OPERATOR_MAINT_TOKEN=replace-me-with-a-maintenance-secret

cargo run -p swarm-runtime-http --bin swarmctl -- serve \
  --config rulesets/default.yaml \
  --evolution-portfolio-results-dir data/evolution-portfolios \
  --evolution-governance-review-packet-results-dir data/evolution-governance-review-packets \
  --evolution-packet-set-results-dir data/evolution-packet-sets \
  --evolution-portfolio-history-results-dir data/evolution-portfolio-history \
  --strategy-memory-results-dir data/strategy-memory \
  --operator-maintenance-results-dir data/operator-maintenance-actions \
  --evidence-results-dir data/evidence-bundles \
  --evidence-verification-results-dir data/evidence-verifications \
  --promotion-evidence-results-dir data/promotion-evidence-packets \
  --review-session-results-dir data/review-sessions \
  --review-session-export-results-dir data/review-session-exports \
  --review-session-readiness-results-dir data/review-session-readiness \
  --review-session-handoff-results-dir data/review-session-handoffs \
  --review-capsule-results-dir data/review-capsules \
  --review-capsule-import-results-dir data/review-capsule-imports \
  --review-delegation-results-dir data/review-delegations
```

Supported reference architecture:

- run `swarm_detect --serve` as the primary runtime service
- run `swarmctl serve` as a separate operator deployment, admin pod, or private service mounting the same state root and artifact directories
- keep the approval set, ledger, verdict, and receipt-pack directories shared and
  durable across both services. `swarm_detect --serve` defaults them to
  `data/approval-sets`, `data/approval-ledgers`, `data/approval-verdicts`, and
  `data/approval-receipt-packs`; its matching override flags are
  `--approval-set-results-dir`, `--approval-ledger-results-dir`,
  `--approval-verdict-results-dir`, and
  `--approval-receipt-pack-results-dir`. Governed human resume fails closed if
  the verdict or receipt-pack store is not configured or the referenced pack is
  absent
- front the non-loopback operator address with TLS; prefer mTLS or a private network boundary if it leaves localhost
- keep operator bearer secrets and the context-token signer in the mounted secret bundle, not in repo config

Example authenticated reads:

```bash
curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  http://127.0.0.1:7766/v1/operator/status

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/replay?receipt_id=receipt-123"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/evolution/portfolios/portfolio:red"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/evolution/governance-packets/packet:red:ready"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/evolution/packet-sets?cohort=red&limit=10"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/evolution/portfolio-histories?cohort=red&limit=10"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/evidence/bundles?subject_kind=production_promotion&limit=10"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/evidence/verifications/EVIDENCE_VERIFICATION_ID"

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  http://127.0.0.1:7766/v1/operator/review

curl \
  -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  -H "x-api-key: ${SWARM_PLATFORM_API_KEY}" \
  https://127.0.0.1:9090/v2/api/runtime/status
```

Response-envelope contract:

- authenticated operator JSON reads under `/v1/operator/*` that return the
  repo-owned control envelope now include top-level `schema_version: 1`
  alongside `origin`, `generated_at_ms`, `config_name`, and `data`
- platform reads under `/v2/api/findings`, `/v2/api/incidents`,
  `/v2/api/assets/{host_id}/posture`, and `/v2/api/runtime/status` now include
  top-level `schema_version: 1` alongside `data` and optional `cursor`
- clients can negotiate the current response contract explicitly with
  `X-Swarm-Schema-Version: 1`; unsupported values fail closed with `400 Bad Request`
- this keeps one bounded compatibility lane for existing operator and CLI
  consumers while future breaking response changes can add a later negotiated
  schema instead of silently changing the envelope shape

`GET /v2/api/runtime/status` now includes `false_positive_tracking` and `alert_tuning` beside the existing detector, anti-tamper, and async-lane fields. `false_positive_tracking` reports recent reviewed findings, false-positive findings, overall rate, and grouped detector or host rates derived from signed analyst feedback persisted on incidents. `alert_tuning` turns that bounded measured state into advisory host-exclusion, detector-threshold, or detector-rule review recommendations without mutating runtime config automatically.

When `tls.client_ca_cert` is set, both HTTP servers require a client certificate signed by that CA before any request reaches the router.

Example authenticated maintenance flow:

```bash
curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_MAINT_TOKEN}" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:7766/v1/operator/maintenance/actions \
  -d '{
    "action": "refresh_portfolio_history",
    "packet_set_id": "packet_set:red:1",
    "reason": "refresh local review snapshot"
  }'

curl -H "Authorization: Bearer ${SWARM_OPERATOR_READ_TOKEN}" \
  "http://127.0.0.1:7766/v1/operator/maintenance/actions?status=blocked&limit=10"
```

Example rehearsal and approval flows:

```bash
curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_REHEARSE_TOKEN}" \
  http://127.0.0.1:7766/v1/operator/review/rehearsals/BUNDLE_ID/export

curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_APPROVE_TOKEN}" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:7766/v1/operator/approval-sets \
  -d '{
    "eligible_voters": ["swarm:ed25519:7d1f..."],
    "threshold_required": 1,
    "promotion_evidence_ref": "promotion_evidence:promotion:red"
  }'
```

Maintenance actions now inherit the authenticated operator principal from the bearer token instead of a global config-wide operator ID. Every maintenance request must include a non-empty `reason`, and every applied or blocked attempt is written to `data/operator-maintenance-actions/` as a stable-ID audit record. Approval votes keep the signer-derived `voter_id`, but the authenticated bearer principal must match that same operator identity.

Current authenticated surface:

- `/v1/operator/review`
- `/v1/operator/review/sessions` `GET`, `POST`
- `/v1/operator/review/sessions/{session_id}`
- `/v1/operator/review/sessions/{session_id}/export` `POST`
- `/v1/operator/review/sessions/{session_id}/capsules` `POST`
- `/v1/operator/review/sessions/{session_id}/promotion-readiness` `POST`
- `/v1/operator/review/sessions/{session_id}/handoffs/reverify` `POST`
- `/v1/operator/review/exports/{export_id}`
- `/v1/operator/review/capsules/{capsule_id}`
- `/v1/operator/review/capsules/{capsule_id}/delegations` `POST`
- `/v1/operator/review/capsule-imports` `POST`
- `/v1/operator/review/capsule-imports/{import_id}`
- `/v1/operator/review/capsule-imports/{import_id}/delegations` `POST`
- `/v1/operator/review/delegations/{delegation_id}`
- `/v1/operator/review/promotion-readiness/{readiness_id}`
- `/v1/operator/review/promotion-readiness/{readiness_id}/capsules` `POST`
- `/v1/operator/review/handoffs/{handoff_id}`
- `/v1/operator/review/evidence?subject_kind=&verification_status=&limit=`
- `/v1/operator/review/evidence/{bundle_id}`
- `/v1/operator/review/verifications/{verification_id}`
- `/v1/operator/review/promotion-packets?recommendation=&limit=`
- `/v1/operator/review/promotion-packets/{packet_id}`
- `/v1/operator/status`
- `/v1/operator/replay`
- `/v1/operator/investigation`
- `/v1/operator/incident`
- `/v1/operator/evolution/portfolios/{portfolio_id}`
- `/v1/operator/evolution/portfolios?cohort=&review_state=&limit=`
- `/v1/operator/evolution/governance-packets/{packet_id}`
- `/v1/operator/evolution/packet-sets/{packet_set_id}`
- `/v1/operator/evolution/packet-sets?cohort=&limit=`
- `/v1/operator/evolution/portfolio-histories/{history_id}`
- `/v1/operator/evolution/portfolio-histories?cohort=&limit=`
- `/v1/operator/evidence/bundles/{bundle_id}`
- `/v1/operator/evidence/bundles?subject_kind=&limit=`
- `/v1/operator/evidence/verifications/{verification_id}`
- `/v1/operator/evidence/promotion-packets/{packet_id}`
- `/v1/operator/maintenance/actions` `GET`, `POST`
- `/v1/operator/maintenance/actions/{action_id}` `GET`

### Cross-Lane Evidence Workbench

`v1.21` extends the local review shell into a cross-lane evidence workbench above the authenticated operator API:

- review sessions are durable repo-owned artifacts assembled from existing `evidence_bundle`, `evidence_verification`, and `promotion_evidence_packet` stable IDs plus lane refs for `promotion_review`, `canary_run`, and `production_promotion`
- one session can now compare governance-prep, canary, and production evidence lanes, export the reviewed state with lane summaries and unresolved gaps, derive an advisory promotion-readiness review, and still launch a bounded maintenance handoff without reading raw files
- review-driven writes stay narrow: the workbench can re-verify evidence bundles through the existing maintenance audit trail, but it still cannot bypass rollout, promotion, or governance
- the surface stays on the same bearer-token middleware and does not introduce cookies, browser-only auth, or multi-user control

`v1.22` makes that review lane portable and continuity-aware:

- one cross-lane session or promotion-readiness artifact can now produce a signed portable review capsule
- foreign review capsules can be imported back into the local workbench with explicit local trust status, remote signer lineage, and preserved related stable refs
- advisory-only delegation packets can preserve review continuity across trust boundaries without granting rollout, promotion, or governance authority

Example review pages and bounded handoff routes:

```bash
curl -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  http://127.0.0.1:7766/v1/operator/review

curl -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  http://127.0.0.1:7766/v1/operator/review/sessions

curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  http://127.0.0.1:7766/v1/operator/review/sessions \
  -d "title=red+cross-lane+review&artifact_refs=promotion_review%3APROMOTION_REVIEW_ID%0Acanary_run%3ACANARY_RUN_ID%0Aproduction_promotion%3APRODUCTION_PROMOTION_ID"

curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  http://127.0.0.1:7766/v1/operator/review/sessions/REVIEW_SESSION_ID/promotion-readiness

curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  http://127.0.0.1:7766/v1/operator/review/sessions/REVIEW_SESSION_ID/capsules

curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  http://127.0.0.1:7766/v1/operator/review/capsule-imports \
  -d "source_path=/tmp/review_capsule.json"

curl -X POST \
  -H "Authorization: Bearer ${SWARM_OPERATOR_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  http://127.0.0.1:7766/v1/operator/review/sessions/REVIEW_SESSION_ID/handoffs/reverify \
  -d "reason=re-verify+selected+evidence&selected_artifact_refs=evidence_bundle%3AEVIDENCE_BUNDLE_ID"
```

`swarmctl` exposes the same repo-owned artifacts directly:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- review-session-create \
  --title "red cross-lane review" \
  --artifact-ref "promotion_review:PROMOTION_REVIEW_ID" \
  --artifact-ref "canary_run:CANARY_RUN_ID" \
  --artifact-ref "production_promotion:PRODUCTION_PROMOTION_ID"

cargo run -p swarm-runtime-http --bin swarmctl -- review-session-list

cargo run -p swarm-runtime-http --bin swarmctl -- review-session-export \
  --session-id REVIEW_SESSION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- review-capsule-create \
  --session-id REVIEW_SESSION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- review-capsule-create \
  --readiness-id REVIEW_SESSION_READINESS_ID

cargo run -p swarm-runtime-http --bin swarmctl -- review-capsule-import \
  --source-path /tmp/review_capsule.json

cargo run -p swarm-runtime-http --bin swarmctl -- review-delegation-create \
  --import-id REVIEW_CAPSULE_IMPORT_ID \
  --reason "preserve signed review continuity for external inspection"

cargo run -p swarm-runtime-http --bin swarmctl -- review-session-promotion-readiness \
  --session-id REVIEW_SESSION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- review-session-promotion-readiness-result \
  --readiness-id REVIEW_SESSION_READINESS_ID

cargo run -p swarm-runtime-http --bin swarmctl -- review-session-handoff-reverify \
  --session-id REVIEW_SESSION_ID \
  --reason "re-verify selected evidence before maintenance review" \
  --artifact-ref "evidence_bundle:EVIDENCE_BUNDLE_ID"
```

Review-session artifacts now default to:

- sessions: `data/review-sessions/`
- exports: `data/review-session-exports/`
- promotion-readiness reviews: `data/review-session-readiness/`
- handoffs: `data/review-session-handoffs/`
- capsules: `data/review-capsules/`
- capsule imports: `data/review-capsule-imports/`
- delegations: `data/review-delegations/`

### Signed Evidence Export And Verification

`v1.18` adds repo-owned signed evidence bundles above the existing runtime and rollout artifacts. The runtime stays single-node and advisory: these signatures make artifacts portable and locally verifiable, but they do not introduce distributed trust or quorum voting.

Signed evidence uses one local signing secret loaded from env:

```bash
export SWARM_EVIDENCE_SIGNING_KEY=replace-me-with-a-local-secret
```

Current defaults:

- signed bundles: `data/evidence-bundles/`
- verification results: `data/evidence-verifications/`
- promotion evidence packets: `data/promotion-evidence-packets/`
- signer label: `local-evidence-signer`
- signer env: `SWARM_EVIDENCE_SIGNING_KEY`

Current supported signed subject kinds:

- `replay_bundle`
- `investigation_bundle`
- `correlated_incident`
- `canary_run`
- `production_promotion`
- `operator_maintenance_action`
- `detector_verification`
- `strategy_shadow`
- `promotion_review`

Examples:

```bash
export SWARM_EVIDENCE_SIGNING_KEY=replace-me-with-a-local-secret

cargo run -p swarm-runtime-http --bin swarmctl -- evidence-export \
  --kind production-promotion \
  --id YOUR_PROMOTION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evidence-result \
  --bundle-id evidence:production_promotion:YOUR_PROMOTION_ID:local-evidence-signer

cargo run -p swarm-runtime-http --bin swarmctl -- evidence-list \
  --kind production-promotion

cargo run -p swarm-runtime-http --bin swarmctl -- evidence-verify \
  --bundle-id evidence:production_promotion:YOUR_PROMOTION_ID:local-evidence-signer

cargo run -p swarm-runtime-http --bin swarmctl -- evidence-verification-result \
  --verification-id evidence_verification:evidence:production_promotion:YOUR_PROMOTION_ID:local-evidence-signer
```

Verification stays fail-closed:

- canonical payload bytes are normalized and rechecked
- payload SHA-256 is recalculated from the stored canonical payload
- detached signature verification must pass against the signed statement
- `--expected-key-id` can pin verification to a known signer fingerprint

Promotion evidence packets reuse existing rollout state and signed evidence instead of regenerating artifacts:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- promotion-evidence-create \
  --promotion-id YOUR_PROMOTION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- promotion-evidence-result \
  --packet-id promotion_evidence:YOUR_PROMOTION_ID
```

Promotion evidence packets are advisory only. They package the finalized promotion outcome, fallback lineage, and supporting signed evidence references for later trust-boundary work, but they do not approve or execute rollout on their own.

### Offline Replay Harness

The repo now ships a deterministic offline replay harness. It uses the same Rust detector, policy, and receipt types as the production runtime, but forces `detect_only` execution so no live response action is executed.

Repo-owned scenarios live under `scenarios/`:

- `scenarios/office-dropper-correlation.yaml`
- `scenarios/benign-baseline.yaml`
- `scenarios/pdf-lolbin-execution.yaml`
- `scenarios/python-maintenance-benign.yaml`

Scenario manifests carry explicit offline corpus metadata. The `metadata:` block
is **required** -- a manifest without one fails to parse, because a scenario with no
declared class was previously exempt from every safety invariant and passed
verification without any of them running.

- `metadata.class`: `adversarial` or `benign`. **`mixed` is REFUSED AT LOAD**, in
  the same place and the same shape as an absent `class:` -- `load_scenario_manifest`
  fails with a validation error naming the manifest, the value, and the two
  invariants that would have owned it. A `mixed` scenario matches neither
  `known_bad_coverage` (which requires `adversarial`) nor `false_positive_bound`
  (which requires `benign`), and it is not only the verification lane that reads
  this field: the experiment metrics, evasion-coverage, red-swarm,
  mutation-fitness and assurance-harvest lanes all branch on it and would skip
  such a scenario in silence -- counted in `total_scenarios`, present in neither
  the `detection_rate` nor the `false_positive_rate` denominator, its detections
  scored by nothing. The refusal sits at the single scenario-load entry point so
  that every one of those lanes inherits it. Classify each scenario as one or the
  other.

  Declaring a class is necessary but not sufficient: each of those two
  invariants reads exactly one half of a verification corpus, so a class is
  enforced only where it is also read. A scenario must appear in the half that
  reads its class -- `adversarial` in `known_bad.suite`, `benign` in
  `benign_controls.scenarios` -- or it satisfies both invariants vacuously and
  FAILS the `scenario_class_enforced` invariant. Appearing in BOTH halves is
  fine and is what the tracked corpus does: `hellcat-office-v1` carries
  `benign-baseline` and `python-maintenance-benign` for its own false-positive
  denominator, and `office-detector-safety-v1` lists those same two files as its
  benign controls.
- `metadata.campaign`: campaign or operator workflow label
- `metadata.techniques`: MITRE ATT&CK technique IDs or internal technique labels
- `metadata.tags`: free-form suite or debugging tags

Named suite manifests live under `scenario-suites/` and point at repo-owned scenario manifests:

- `scenario-suites/hellcat-office-v1.yaml`

Replay results are written under `data/replay-runs/` by default.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- replay-run --scenario scenarios/office-dropper-correlation.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- replay-result --scenario scenarios/office-dropper-correlation.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- --json replay-result --run-id replay_run:office_dropper_correlation:1700000100000
```

Scenario manifests currently support two input modes:

- `kind: events`: inline fixture telemetry plus the response action to request for each step
- `kind: replay_bundles`: one or more persisted replay bundle JSON files that should be re-run offline

The durable replay run bundle captures:

- replay bundles produced by the offline run
- deterministic inline investigation artifacts
- deterministic correlated incidents
- a stable summary for repeatability checks
- measured stage latency snapshots for later regression gates

### Replay Evaluation And Gates

Replay evaluation compares replay-run bundles against the expectations embedded in each scenario manifest, including hunt-level policy or response outcomes and incident grouping. Hot-path stage latencies are measured and recorded beside the manifest budget, but they are **advisory only and do not gate** -- see below.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- replay-evaluate --scenario scenarios/office-dropper-correlation.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- replay-evaluate --run-id replay_run:office_dropper_correlation:1700000100000
cargo run -p swarm-runtime-http --bin swarmctl -- replay-evaluate --scenarios-dir scenarios
cargo run -p swarm-runtime-http --bin swarmctl -- replay-evaluate --suite scenario-suites/hellcat-office-v1.yaml
```

Failure behavior:

- `replay-evaluate` exits nonzero when any expectation over replay output fails: replay bundle, investigation, and incident counts, per-hunt action/policy/response outcomes, and incident hunt grouping. Every one of these is a pure function of the scenario fixture, so the exit code is the same on any machine
- `replay-evaluate` **does not** exit nonzero for an exceeded latency budget. `max_detect_latency_us`, `max_policy_latency_us`, and `max_response_latency_us` in a scenario `expectations:` block are advisory reference points, not thresholds
- `--scenarios-dir` evaluates the full tracked corpus and is intended for local or CI gating
- `--suite` evaluates one named replay suite and aggregates pass/fail status by scenario and technique group

#### Scenario latency budgets are advisory

`expectations.max_detect_latency_us` and its policy and response siblings used to
gate. `ReplayEvaluationReport.passed` reduced over them, `ReplaySuiteReport.passed`
reduced over that, and `replay-evaluate` turned the result into
`std::process::exit(1)`.

The value being compared was a wall-clock `Instant` delta captured in the runtime
service, so it measured the machine, the build profile, and whatever else the
scheduler was running -- not the scenario. Eight consecutive runs over the shipped
corpus on an idle machine spread 658-888us, a 35% swing, and a single stall flipped
`scenarios/office-dropper-correlation.yaml` from pass to fail on unchanged code.
`CONTRIBUTING.md` and `README.md` both tell contributors to run this command, so
the spurious failure landed on people whose only mistake was owning a slow laptop.
It is the same defect, and the same fix, as the canary and promotion
`max_detect_latency_us` gates documented under "Rollout" later in this document.

**Nothing is silently ignored.** The thirteen tracked scenario manifests that
declare `max_detect_latency_us` (eight of which also declare the policy and
response budgets) keep their keys, and the keys are still read:

- the measurement is recorded on `ReplayEvaluationReport.observations` next to the
  budget the manifest declared, together with `within_advisory_budget`
- `replay-evaluate --scenario` prints it under `Observations (non-gating, not part
  of Status):`
- `replay-evaluate --suite` and `--scenarios-dir` print an
  `observation over advisory budget:` line under the scenario, at the exact place
  the failing check used to appear

**If you set a scenario `max_*_latency_us` expecting a hard bound, it no longer
stops anything.** You get a recorded breach in the report and a line in the render;
you do not get a nonzero exit. A performance regression gate has to count work
rather than read a clock -- that is a cost model, and this repo does not have one
yet. Until it does, latency is evidence, not a verdict.

End-to-end flow:

1. Run one tracked scenario with `replay-run`.
2. Inspect the persisted result bundle with `replay-result`.
3. Validate one scenario with `replay-evaluate --scenario ...`.
4. Validate one named suite with `replay-evaluate --suite scenario-suites/hellcat-office-v1.yaml`.
5. Gate the whole tracked corpus with `replay-evaluate --scenarios-dir scenarios`.

The runtime test suite also includes a tracked-scenario regression test in `swarm-runtime` so the repo corpus acts as an executable baseline.

### Detector Experiments

Offline baseline-vs-candidate detector experiments are defined under `experiments/`. Each manifest references one suite manifest, one candidate detector profile, lineage metadata, and offline gate thresholds.

Tracked manifests:

- `experiments/office-baseline-control.yaml` — control candidate matching production behavior
- `experiments/office-python-parent-broadening.yaml` — intentionally broader candidate that should fail the false-positive gate

Experiment results are written under `data/experiments/` by default.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- experiment-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- experiment-evaluate --experiment experiments/office-python-parent-broadening.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- experiment-result --experiment-id experiment:office_baseline_control:office_baseline_control
```

What the experiment report captures:

- baseline and candidate suite reports over the same replay corpus
- aggregate detection rate, false positive rate, and detect-latency comparisons
- lineage metadata (`parent_strategy_id`, mutation, rationale)
- scenario regressions and technique regressions
- offline gate verdicts for known-bad coverage and false-positive delta

Current gating set (`gates` in the report; `passed` reduces over it):

- `known_bad_coverage`: candidate must not miss tracked adversarial scenarios the
  baseline caught
- `false_positive_delta`: candidate must stay within the manifest's benign
  false-positive delta

Both are counts over fixture content, so each computes the same value on any
machine, under any load, on any architecture.

Current non-gating observation set (`observations` in the report; nothing
reduces over it):

- `max_detect_latency_delta_us`: the candidate suite's worst detect latency minus
  the baseline suite's, with the manifest's `gates.max_detect_latency_delta_us`
  recorded beside it as an advisory reference point and `within_advisory_budget`
  recorded as a fact rather than a verdict

`max_detect_latency_delta_us` used to gate. It was removed from the gating set
because the number it compares is a difference of two maxima over wall-clock
`Instant` deltas. A uniform slowdown does cancel out, which is why it looked
safe -- but the baseline suite and the candidate suite run one after the other,
so anything that slows down only the second one moves the difference. A single
20ms stall confined to the candidate suite flipped the gate, the experiment
verdict, and the shadow verdict on identical fixtures; on an idle arm64 machine
with nothing injected the nominal spread was already 1327us against the 2000us
budget `experiments/office-python-parent-broadening.yaml` sets. A latency gate
that can be trusted has to count work rather than read a clock.

**If you set `gates.max_detect_latency_delta_us` in an experiment manifest
expecting a hard bound, it no longer stops anything.** The key is deliberately
unchanged and is still read, still compared, and still reported: it appears as
`advisory_budget` in the report's `observations` block, in the shadow report's
`observations` block, and under `Observations (non-gating, not part of Status)`
in the rendered `experiment-result` and `shadow-result` output, with
`within_advisory_budget: false` when the measured delta exceeds it. Alert on
`within_advisory_budget` if you want a latency signal; do not expect an exit
code. The manifests were left at their existing values so the recorded series
stays comparable over time.

What this changes downstream, in the operator's favour: a latency spread can no
longer produce a failed experiment gate, and therefore can no longer produce a
`blocked` promotion review packet, a spurious evolution pressure signal, or a
`CanaryError::ShadowFailed` that refuses canary admission outright.

Failure behavior:

- `experiment-evaluate` exits nonzero when any offline experiment gate fails --
  the latency observation is not a gate and cannot cause a nonzero exit
- the persisted experiment report can still be loaded later with `experiment-result`

### Verification Corpora

Repo-owned detector verification inputs now live under `verifications/`. A verification corpus defines the invariant inputs that later candidate-gating and promotion-review workflows use.

Tracked corpora:

- `verifications/office-detector-safety-v1.yaml`

Each verification corpus currently records:

- `known_bad.suite`: the named replay suite the candidate must continue to cover
- `benign_controls.scenarios`: explicit benign scenarios used for false-positive inspection
- `canonical_templates`: one or more threat-class templates the detector must still match
- `resource_budgets`: repo-owned thresholds such as max false-positive rate, max detect latency, and max total detections

Existing experiment manifests now bind to one verification corpus through:

```yaml
verification:
  corpus: ../verifications/office-detector-safety-v1.yaml
```

This keeps canonical verification inputs in tracked YAML instead of hardcoded tests and gives later phases one stable contract for per-invariant pass or fail reporting.

### Verification Gate

Candidate verification runs the experiment's candidate detector against the repo-owned verification corpus and emits per-invariant pass or fail output.

Verification results are written under `data/verifications/` by default.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- verification-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- verification-evaluate --experiment experiments/office-python-parent-broadening.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- verification-result --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1
```

Current gating invariant set (`invariants` in the report; `passed` is exactly
`invariants.iter().all(|i| i.passed)`):

- `scenario_class_declared`: every corpus scenario must declare a class an
  invariant can enforce. Since `mixed` is refused at load this can no longer
  fail through a manifest, and is retained as the bundle's own attestation of
  the property
- `scenario_class_enforced`: every corpus scenario must sit in the corpus half
  that reads its class, so that some invariant is actually responsible for it
- `known_bad_coverage`: candidate must not miss tracked adversarial verification scenarios
- `threat_class_templates`: candidate must still match canonical threat-class templates
- `false_positive_bound`: candidate must stay under the repo-owned benign false-positive threshold
- `total_detection_budget`: candidate total emitted detections must stay within the corpus volume budget

The first two are preconditions on the corpus rather than on the candidate, and
they come first for that reason: without them a scenario can satisfy the
remaining invariants by being invisible to all of them.

Every one of these is a count or a rate over fixture content, so each computes
the same value on any machine, under any load, on any architecture.

Current non-gating observation set (`observations` in the report; nothing
reduces over it):

- `detect_latency_budget`: worst-case detect-stage latency measured across the
  verification suites, with the corpus `max_detect_latency_us` recorded beside
  it as an advisory reference point and `within_advisory_budget` recorded as a
  fact rather than a verdict

`detect_latency_budget` used to gate. It was removed from the gating set because
the number it compares is a wall-clock `Instant` delta: it measures the machine,
the build profile, and whatever else the scheduler was running, not the
candidate. An identical candidate over identical fixtures reached opposite
verdicts on the same machine minutes apart. The measurement is still taken, still
recorded in full including which scenario was slowest, and still rendered by
`verification-result` under `Observations (non-gating, not part of Status)`. A
latency gate that can be trusted has to count work rather than read a clock.

The same reasoning applies to the `latency_budget` invariant in
`rulesets/safety/office-detector-admission.yaml`. Its `max_detect_latency_us` is
now advisory: the admission check requires the candidate's verification to carry
an attributable detect-latency observation over the pinned corpus, and reports
the measurement in the verdict details, but does not reject a candidate for
being measured on a busy machine.

Failure behavior:

- `verification-evaluate` exits nonzero when any GATING invariant fails; an
  observation never changes the exit code
- failing output preserves scenario or template references for operator inspection

### Offline Shadow

Offline shadow reuses the same baseline-vs-candidate replay comparison as the experiment flow, but persists the result as a dedicated shadow artifact for later promotion review.

Shadow results are written under `data/shadows/` by default.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- shadow-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- shadow-result --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03
```

Shadow reports capture:

- baseline-vs-candidate detection-rate delta
- false-positive-rate delta
- detect-latency delta
- the replay artifacts used as the comparison window
- pass or fail shadow gates derived from the experiment manifest thresholds
- a non-gating `observations` block carrying the detect-latency delta and its
  advisory budget, copied from the experiment report

Shadow gates are copied verbatim from the experiment report and `passed` reduces
over `gates` only, so the `max_detect_latency_delta_us` demotion above applies
identically here: it is recorded on the shadow artifact and gates nothing. This
is the artifact `canary-admit` reads, so a latency spread can no longer refuse
canary admission with `CanaryError::ShadowFailed`.

Failure behavior:

- `shadow-evaluate` exits nonzero when the candidate fails the offline shadow gates
- shadow execution remains fully offline and never emits live pheromones or response actions

### Promotion Review Packets

Promotion review packets assemble one candidate experiment, one persisted verification artifact, and one persisted shadow artifact into a durable manual-review handoff.

Promotion review packets are written under `data/promotion-reviews/` by default.

Examples:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- promotion-review-create --experiment experiments/office-baseline-control.yaml --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03
cargo run -p swarm-runtime-http --bin swarmctl -- promotion-review-result --review-id promotion_review:office_baseline_control:office_baseline_control:2026-04-03
```

Packets capture:

- candidate lineage and description from the experiment manifest
- stable verification and shadow IDs
- shadow deltas for detection rate, false-positive rate, and detect latency
- a `ready_for_manual_review` or `blocked` recommendation
- blocking reasons derived from failed verification invariants or failed shadow gates

This remains an operator review surface only. The packet does not approve, deploy, or promote anything automatically.

### Bounded Canary

Bounded canary extends the runtime from offline shadow into a scoped live detector lane. The candidate detector is admitted only after verification and shadow have already passed, and its findings remain inside a dedicated canary artifact instead of affecting the production substrate.

Repo-owned canary settings now live in `rulesets/default.yaml`:

```yaml
canary:
  enabled: true
  slot_id: canary-primary
  observation_window_events: 2
  max_candidate_only_rate: 0.25
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 8
```

Current canary inputs and semantics:

- `slot_id`: stable identifier for the single bounded canary lane
- `observation_window_events`: how many live events the candidate must survive before the run can complete normally
- `max_candidate_only_rate`: conservative false-positive proxy bound, based on candidate-only detections versus the production baseline
- `max_baseline_miss_rate`: bound on how often the candidate misses a detection that the baseline still produces
- `max_detect_latency_us`: **advisory only, not a gate.** The reference point recorded beside the non-gating `detect_latency_budget` observation on the canary artifact. Nothing rolls a canary back for exceeding it
- `max_total_detections`: resource budget for total candidate detections over the window

Canary artifacts are written under `data/canaries/` by default.

The canary artifact separates the two kinds of entry, and so does
`canary-result`:

- `threshold_results` is **gating**. Every entry is a count or a rate over what
  the candidate did across the observed events, so it computes the same value on
  any machine, under any load, on any architecture. The run rolls back and the
  candidate is blocked on the first entry that fails.
- `observations` is **non-gating**. Nothing reduces over it. It carries
  `detect_latency_budget`: the worst candidate detect latency measured over the
  window, the advisory budget it was compared against, and
  `within_advisory_budget` as a recorded fact rather than a verdict.

`detect_latency_threshold` used to be a gating threshold and is gone from
`threshold_results`. It was the only bound there whose verdict was not a
function of what the candidate did: `max_candidate_detect_latency_us` is a
wall-clock `Instant` delta, so a busy runner could roll a healthy candidate out
of a live lane and record `AutomaticThreshold` against it. **If you tightened
`canary.max_detect_latency_us` expecting a hard bound, it no longer stops
anything.** The measurement is still taken and still recorded: it appears in
every run's `observations` block and under `Observations (advisory,
non-gating)` in the rendered report, with `within_advisory_budget: false` when
your budget is exceeded. Alerting on that field is the supported replacement.
A latency bound that can be enforced has to count work rather than read a
clock; that is a cost model, and it is not this field.

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- verification-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime-http --bin swarmctl -- shadow-evaluate --experiment experiments/office-baseline-control.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- canary-start \
  --experiment experiments/office-baseline-control.yaml \
  --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 \
  --shadow-id shadow:office_baseline_control:office_baseline_control:office_detector_safety_v1

cargo run -p swarm-runtime-http --bin swarmctl -- canary-event \
  --run-id YOUR_CANARY_RUN_ID \
  --event fixtures/canary/word-powershell.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- canary-event \
  --run-id YOUR_CANARY_RUN_ID \
  --event fixtures/canary/outlook-cmd.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- canary-result --run-id YOUR_CANARY_RUN_ID
```

Automatic failure behavior:

- `canary-event` exits nonzero when the canary auto-rolls back on a threshold or budget violation. Detect latency is not one of those thresholds; see above
- rollback history preserves the trigger, reason, slot ID, and reverted baseline strategy
- the final canary artifact carries an `observing`, `ready_for_promotion_review`, or `blocked` recommendation

Manual operator actions:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- canary-halt --run-id YOUR_CANARY_RUN_ID --reason "operator requested stop"
cargo run -p swarm-runtime-http --bin swarmctl -- canary-rollback --run-id YOUR_CANARY_RUN_ID --reason "candidate diverged from baseline"
```

This milestone still stops short of fleet-wide promotion. The canary artifact is the handoff into the next decision step, not the promotion itself.

### Controlled Production Promotion

Controlled production promotion extends the staged rollout from canary into the production detector role. Promotion starts from a completed canary artifact that is already `ready_for_promotion_review`, rotates the promoted detector into the production lane, retains the previous production detector as the rollback target, and observes the promoted detector through a bounded production window.

Repo-owned promotion settings now live in `rulesets/default.yaml`:

```yaml
promotion:
  enabled: true
  window_id: production-primary
  observation_window_events: 2
  max_promoted_only_rate: 0.20
  max_fallback_recovery_rate: 0.20
  max_detect_latency_us: 10000
  max_total_detections: 12
```

Current promotion inputs and semantics:

- `window_id`: stable identifier for the active production observation window
- `observation_window_events`: how many live events the promoted detector must survive before the promotion can complete normally
- `max_promoted_only_rate`: divergence bound for promoted-only detections versus the retained fallback baseline
- `max_fallback_recovery_rate`: bound on how often the retained fallback baseline still detects activity that the promoted detector misses
- `max_detect_latency_us`: **advisory only, not a gate.** The reference point recorded beside the non-gating `detect_latency_budget` observation on the promotion artifact. Nothing rolls a promotion back for exceeding it
- `max_total_detections`: resource budget for total promoted detections over the production window

Production-promotion artifacts are written under `data/promotions/` by default.

The promotion artifact makes the same split as the canary artifact:
`threshold_results` is gating and reverts production to the retained fallback
detector on the first failure; `observations` is non-gating and carries
`detect_latency_budget` with its advisory budget and `within_advisory_budget`.
`detect_latency_threshold` is gone from `threshold_results` for the same reason
-- `max_promoted_detect_latency_us` is a wall-clock delta, and reverting the
detector serving production traffic on it is a false positive waiting for a
busy runner. **If you tightened `promotion.max_detect_latency_us` expecting a
hard bound, it no longer stops anything;** alert on `within_advisory_budget`
instead.

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- canary-result --run-id YOUR_CANARY_RUN_ID

cargo run -p swarm-runtime-http --bin swarmctl -- promotion-start \
  --canary-run-id YOUR_CANARY_RUN_ID

cargo run -p swarm-runtime-http --bin swarmctl -- promotion-event \
  --promotion-id YOUR_PROMOTION_ID \
  --event fixtures/canary/word-powershell.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- promotion-event \
  --promotion-id YOUR_PROMOTION_ID \
  --event fixtures/canary/outlook-cmd.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- promotion-result --promotion-id YOUR_PROMOTION_ID
```

Automatic failure behavior:

- `promotion-event` exits nonzero when the promoted detector auto-rolls back on a threshold or budget violation. Detect latency is not one of those thresholds; see above
- rollback history preserves the trigger, reason, restored baseline strategy, and observed event count
- the final promotion artifact carries an `observing`, `stable_in_production`, or `blocked` recommendation

Manual operator actions:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- promotion-halt --promotion-id YOUR_PROMOTION_ID --reason "operator requested stop"
cargo run -p swarm-runtime-http --bin swarmctl -- promotion-rollback --promotion-id YOUR_PROMOTION_ID --reason "promoted detector diverged from fallback baseline"
```

This milestone still stops short of quorum governance or partial-fleet rollout. The production-promotion artifact is the bounded single-node promotion record, not a distributed approval system.

### Strategy Memory And Advisory Scorecards

The repo now ships a durable strategy-memory and advisory scorecard lane. This is built entirely from existing rollout artifacts: completed canary runs and completed production promotions. It does not rerun telemetry to build memories, and it does not promote or mutate strategies automatically.

The first slice uses deterministic built-in weighting for:

- rollout outcome weight (`ready_for_promotion_review`, `stable_in_production`, `blocked`, `halted`)
- rollout stage weight (`canary` vs `promotion`)
- recency decay
- context matching across suite name, corpus version, parent strategy, and reference strategy

Strategy-memory artifacts are written under `data/strategy-memory/` by default.

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- strategy-memory-canary \
  --run-id YOUR_CANARY_RUN_ID

cargo run -p swarm-runtime-http --bin swarmctl -- strategy-memory-promotion \
  --promotion-id YOUR_PROMOTION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- strategy-memory-result \
  --memory-id strategy_memory:promotion:YOUR_PROMOTION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- strategy-memory-history \
  --strategy-id office_baseline_control
```

Each durable memory preserves:

- the source artifact ID and rollout stage (`canary` or `promotion`)
- the strategy ID, lineage, suite name, and corpus version
- explicit outcome and rollout weights
- observed detection, divergence, latency, and budget summaries
- any blocking or rollback reasons

Advisory scorecards are written under `data/strategy-scorecards/` by default.

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- strategy-scorecard-create \
  --experiment experiments/office-baseline-control.yaml \
  --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1

cargo run -p swarm-runtime-http --bin swarmctl -- strategy-scorecard-result \
  --scorecard-id YOUR_SCORECARD_ID
```

Scorecards compare the current production baseline and the verified candidate using:

- durable live rollout memories when they exist
- replay-fitness fallback when live memory is sparse
- per-memory explanations with outcome weights, recency decay, context matches, and weighted contribution

The replay-fitness fallback is `detection_rate - false_positive_rate`, clamped to
`[-1.0, 1.0]`. It used to subtract a further penalty of up to 0.25 derived from
the experiment's measured `max_detect_latency_us` -- a wall-clock `Instant`
delta. Against a recommendation epsilon of 0.05 that let the machine, not the
candidate, flip `CandidatePreferred` to `RetainBaseline`, and the fallback is the
path every candidate takes until it has two matching live rollout memories, so a
brand new candidate was always scored this way. Both remaining terms are counts
over fixture content, so the fallback is now identical wherever the same bundle
is replayed. The latency measurement is unchanged and still recorded on the
experiment report the scorecard is derived from.

This lane is advisory only. The scorecard does not approve, deploy, or promote a detector by itself.

### Selection Pressure And Proposal Drafts

The repo now ships an explicit off-hot-path drafting lane ahead of the verified queue. This turns replay regressions, verification drift, and strategy-memory gaps into durable pressure reports, then lets operators package one draft and promote it into the reviewed queue without auto-enqueueing rollout or bypassing proof gates.

The current slice stays narrow:

- pressure reports are repo-owned durable artifacts under `data/evolution-pressures/`
- draft artifacts are repo-owned durable artifacts under `data/evolution-drafts/`
- draft-promotion records are durable links under `data/evolution-draft-promotions/`
- draft promotion creates a reviewed queue entry only; it does not create proof, verification, shadow, handoff, or canary artifacts

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- strategy-scorecard-create \
  --experiment experiments/office-baseline-control.yaml \
  --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-pressure-create \
  --scorecard-id YOUR_SCORECARD_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-pressure-result \
  --pressure-id YOUR_PRESSURE_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-draft-create \
  --pressure-id YOUR_PRESSURE_ID \
  --strategy-id office_memory_followup_v1 \
  --strategy-description "tighten process ancestry while keeping office controls" \
  --mutation memory_gap_followup \
  --rationale "scorecard fell back to replay because live evidence is sparse"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-draft-promote \
  --draft-id YOUR_DRAFT_ID \
  --reason "queue this draft for explicit operator review"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-draft-promotion-result \
  --promotion-id YOUR_PROMOTION_ID
```

Pressure sources currently supported:

- `evolution-pressure-create --experiment-id ...` for replay regressions and failed offline experiment gates
- `evolution-pressure-create --verification-id ...` for failing invariants and preserved counterexamples
- `evolution-pressure-create --scorecard-id ...` for sparse or unfavorable live rollout memory

Pressure and draft artifacts preserve:

- stable IDs plus source-artifact references
- candidate and parent-strategy lineage hints
- explicit rationale for why additional detector work is warranted
- explicit operator-supplied mutation and rationale hints on each draft

Failure behavior:

- `evolution-pressure-create` exits nonzero when the selected artifact shows no drafting pressure
- `evolution-draft-promote` exits nonzero when the draft has already been promoted once
- promoted queue entries remain blocked from canary admission until later proof-backed evidence is produced

### Guided Mutation Specs

The repo now ships a durable guided-mutation lane above reviewed drafts and materialized candidates. This keeps mutation design explicit and operator-authored while packaging several candidate variants under one repo-owned artifact.

Current mutation-spec semantics:

- mutation specs are durable repo-owned artifacts under `data/evolution-mutations/`
- mutation specs can start from either one reviewed draft or one materialized candidate
- mutation specs preserve source lineage, pressure references, and any existing reviewed queue proposal reference
- variants are appended explicitly through `swarmctl`; the runtime does not invent or auto-enqueue them

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-create \
  --draft-id YOUR_DRAFT_ID \
  --base-experiment experiments/office-baseline-control.yaml \
  --rationale "compare explicit parent and threshold variants"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-add-variant \
  --mutation-spec-id YOUR_MUTATION_SPEC_ID \
  --variant-id tighter-thresholds \
  --strategy-id office_mutation_threshold_v1 \
  --strategy-description "raise confidence thresholds without changing parent set" \
  --mutation raise_thresholds \
  --rationale "test whether stricter gating reduces replay regressions" \
  --high-confidence-threshold 0.98 \
  --medium-confidence-threshold 0.92

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-result \
  --mutation-spec-id YOUR_MUTATION_SPEC_ID
```

Each mutation spec preserves:

- the source kind (`draft` or `materialization`) and stable source IDs
- the source strategy, lineage, and source experiment reference
- the operator rationale for widening the candidate bench
- one or more explicit variants with mutation labels and structured profile dimensions

This lane remains offline and advisory. Mutation specs do not auto-materialize manifests, refresh validation bundles, or change queue state by themselves.

### Batch Candidate Materialization And Validation

The repo now ships a batch layer on top of guided mutation specs. Operators can materialize every variant in one mutation spec, then refresh validation evidence across that batch without merging candidate state together.

Current batch semantics:

- materialization batches are durable repo-owned artifacts under `data/evolution-mutation-materialization-batches/`
- validation batches are durable repo-owned artifacts under `data/evolution-mutation-validation-batches/`
- each batch entry preserves the per-candidate link back to the source mutation spec and any reviewed queue proposal reference
- blocked candidates remain persisted and visible; validation batches fail closed but do not discard evidence

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-materialize-batch \
  --mutation-spec-id YOUR_MUTATION_SPEC_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-materialization-batch-result \
  --batch-id YOUR_BATCH_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-validate-batch \
  --batch-id YOUR_BATCH_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-mutation-validation-batch-result \
  --validation-batch-id YOUR_VALIDATION_BATCH_ID
```

Batch artifacts preserve:

- one stable batch ID plus per-candidate materialization or validation IDs
- the strategy ID and mutation dimensions for each variant
- any existing reviewed queue proposal reference for later review
- blocked versus ready counts across the candidate set

This lane still stops short of queue mutation or rollout. Batch validation produces evidence only.

### Candidate Ranking And Review Packets

The repo now ships a deterministic ranking pass above mutation validation batches. Operators can score candidate variants from persisted validation evidence, retain the existing reviewed-queue reference when present, and emit durable review packets for later queue work.

Current ranking semantics:

- ranking artifacts are durable repo-owned records under `data/evolution-rankings/`
- ranking uses validation status, proof status, advisory score deltas, blocking reasons, and reviewed queue state when present
- ranking remains advisory; it does not enqueue, reconcile, canary, or promote candidates automatically

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-rank-candidates \
  --validation-batch-id YOUR_VALIDATION_BATCH_ID \
  --shortlist-count 2

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-ranking-result \
  --ranking-id YOUR_RANKING_ID
```

Each ranking report preserves:

- a full ordered candidate list with deterministic scores
- one or more review packets containing materialization, validation, and reviewed-queue references
- advisory recommendation and score-delta context when it exists

This lane is the final offline comparison seam. Human review still decides whether any ranked candidate should re-enter the later queue or rollout path.

### Ranked Candidate Selection And Rollout Bridge

The repo now ships an operator-controlled bridge from ranked review packets back into the existing rollout ladder. Operators can select one shortlisted ranked candidate, record an explicit review decision, and then create one bridge artifact that feeds the existing handoff and canary path without re-materializing experiment evidence.

Current selection and bridge semantics:

- ranked-candidate selections are durable repo-owned artifacts under `data/evolution-selections/`
- ranked-candidate bridge artifacts are durable repo-owned artifacts under `data/evolution-selection-bridges/`
- selection creation preserves ranking, validation, advisory, and parent-queue lineage in one stable record
- selection review decisions remain advisory until an operator creates a bridge artifact
- bridge creation reuses the preserved experiment, verification, proof, shadow, and advisory references; it does not restate or regenerate them

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-selection-create \
  --ranking-id YOUR_RANKING_ID \
  --packet-id YOUR_PACKET_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-selection-result \
  --selection-id YOUR_SELECTION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-selection-list \
  --review-state pending-review

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-selection-decision \
  --selection-id YOUR_SELECTION_ID \
  --decision accept-for-canary \
  --reason "accept the selected ranked candidate for rollout bridging"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-selection-bridge \
  --selection-id YOUR_SELECTION_ID \
  --reason "bridge the accepted selection into the existing queue and handoff lane"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-selection-bridge-result \
  --bridge-id YOUR_BRIDGE_ID
```

Each selection artifact preserves:

- the source ranking ID and review-packet ID
- the selected strategy, materialization ID, validation bundle ID, and experiment path
- verification, proof, advisory, and shadow references copied from the preserved validation bundle
- the current review state plus explicit operator decision history
- fail-closed blocking reasons when the selected packet is inconsistent, blocked, or no longer queue-ready

Each bridge artifact preserves:

- the selection ID plus any resulting queue proposal ID
- the resulting review state and `handoff_ready` verdict
- proof, verification, shadow, and advisory references reused by the later handoff path
- fail-closed blocking reasons when the selection is not accepted, carries blocking reasons, or drifts from the preserved experiment manifest

Failure behavior:

- `evolution-selection-create` exits nonzero when the selected review packet produces a blocked selection; the blocked selection is still persisted
- `evolution-selection-decision --decision accept-for-canary` is allowed only for unblocked, proved, queue-ready selections
- `evolution-selection-bridge` exits nonzero when the selection is not accepted, remains blocked, or no longer matches the preserved manifest and lineage digests
- blocked bridge artifacts are still persisted so operators can inspect why the ranked candidate failed closed

This lane stays operator-triggered and conservative. It only re-enters the existing rollout ladder; the resulting queue proposal still flows through the existing handoff and bounded canary gates.

### Cross-Batch Portfolio Review And Governance-Ready Packets

The repo now ships a portfolio lane above single ranked-candidate selection. Operators can assemble one durable portfolio from multiple ranked selections spanning different mutation batches or campaign cohorts, record explicit curation decisions on each entry, and then export governance-ready review packets for later trust-boundary work without re-encoding the underlying evidence.

Current portfolio semantics:

- cross-batch portfolio artifacts are durable repo-owned records under `data/evolution-portfolios/`
- governance-ready packet artifacts are durable repo-owned records under `data/evolution-governance-review-packets/`
- portfolio assembly preserves ranking, selection, mutation-batch, validation-batch, cohort, validation, proof, advisory, and queue-lineage context in one stable record
- portfolio decisions remain advisory and do not mutate queue, canary, or production state
- governance-ready packet creation reuses preserved portfolio evidence instead of regenerating verification, proof, or shadow artifacts

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-create \
  --name "office cross cohort shortlist" \
  --rationale "compare ready candidates across two cohorts before governance prep" \
  --selection-id SELECTION_ID_ONE \
  --selection-id SELECTION_ID_TWO \
  --cohort hellcat.office_loader \
  --cohort operator.maintenance

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-result \
  --portfolio-id YOUR_PORTFOLIO_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-list \
  --review-state pending-review

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-decision \
  --portfolio-id YOUR_PORTFOLIO_ID \
  --entry-id YOUR_ENTRY_ID \
  --decision include \
  --reason "keep this shortlisted candidate in the curated portfolio"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-governance-packet-create \
  --portfolio-id YOUR_PORTFOLIO_ID \
  --entry-id YOUR_ENTRY_ID \
  --reason "prepare this curated entry for later governance-backed review"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-governance-packet-result \
  --packet-id YOUR_PACKET_ID
```

Each portfolio artifact preserves:

- one stable portfolio ID plus operator rationale and cohort labels
- per-entry ranking ID, selection ID, mutation-spec ID, validation-batch ID, and validation-bundle ID
- experiment manifest path, manifest digest, lineage digest, verification reference, proof summary, advisory summary, and shadow reference
- current selection review state plus an independent portfolio review state and explicit portfolio decision history
- fail-closed blocking reasons copied forward when a ranked selection was already blocked or otherwise inconsistent

Each governance-ready packet preserves:

- the portfolio ID, entry ID, selection ID, and source ranking ID
- experiment, validation, verification, proof, advisory, shadow, and parent-queue references copied from the curated portfolio entry
- current selection and portfolio review states so later governance work can reuse the exact operator-reviewed context
- an explicit `ready_for_governance` verdict plus durable blocking reasons when the packet fails closed

Failure behavior:

- `evolution-portfolio-create` rejects empty portfolios and mismatched `--selection-id` / `--cohort` counts
- blocked or previously rejected selections can still appear in a portfolio, but they carry forward blocking reasons and start in the `blocked` portfolio state
- `evolution-portfolio-decision --decision include` is allowed only for unblocked entries
- `evolution-governance-packet-create` exits nonzero when the entry is not `included`, when preserved blocking reasons remain, or when the current experiment manifest drifts from the stored manifest or lineage digests
- blocked governance-ready packets are still persisted so operators can inspect why the entry failed closed

This lane is prep work for later governance, not governance itself. It widens comparison and curation across ranked batches while keeping rollout mutation pinned to the existing reviewed queue, handoff, canary, and promotion paths.

### Governance Packet Sets And Portfolio History

The repo now ships one layer above individual governance-ready packets. Operators can merge several packet artifacts into one durable packet set, split subsets back out without rewriting source evidence, and snapshot portfolio history from those packet sets using the existing strategy-memory lane.

Current packet-set and history semantics:

- governance packet-set artifacts are durable repo-owned records under `data/evolution-packet-sets/`
- portfolio history snapshots are durable repo-owned records under `data/evolution-portfolio-history/`
- packet sets preserve source packet, portfolio, cohort, ranking, selection, validation, proof, advisory, and rollout-lineage references in one stable record
- splitting a packet set creates a new child set with a `parent_packet_set_id` and preserved source packet-set entry references
- portfolio history derives rollout outcomes from existing strategy-memory artifacts instead of duplicating canary or promotion state

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-packet-set-create \
  --name "office governance cohort set" \
  --rationale "group ready and blocked governance packets for one operator review pass" \
  --packet-id PACKET_ID_ONE \
  --packet-id PACKET_ID_TWO

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-packet-set-result \
  --packet-set-id YOUR_PACKET_SET_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-packet-set-list \
  --cohort hellcat.office_loader

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-packet-set-split \
  --packet-set-id YOUR_PACKET_SET_ID \
  --name "office red subset" \
  --rationale "review the red cohort separately" \
  --packet-id PACKET_ID_ONE

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-history-create \
  --packet-set-id YOUR_PACKET_SET_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-history-result \
  --history-id YOUR_HISTORY_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-portfolio-history-list \
  --cohort hellcat.office_loader
```

Each packet set preserves:

- one stable packet-set ID plus operator rationale and optional parent packet-set reference
- one stable entry per included governance packet with the source `packet_id` and any upstream `source_packet_set_entry_id`
- source portfolio, cohort, ranking, selection, validation-bundle, experiment, verification, proof, advisory, shadow, and queue-lineage references
- the original packet `ready_for_governance` verdict and fail-closed blocking reasons when a packet already failed upstream

Each portfolio history snapshot preserves:

- the source packet-set ID and packet-set name
- one derived outcome per packet-set entry: `no_observed_rollout`, `ready_for_promotion_review`, `stable_in_production`, `blocked`, or `halted`
- cross-cohort summaries for survival, stable outcomes, blocked or halted outcomes, unobserved entries, and review debt
- review debt classifications derived from existing artifacts: `pending_governance_follow_up` and `awaiting_stable_outcome`

Failure behavior:

- `evolution-packet-set-create` rejects empty packet lists or packet IDs that do not resolve to persisted governance-ready packet artifacts
- packet-set creation and splitting remain advisory; they do not mutate queue, canary, or production state
- `evolution-portfolio-history-create` fails closed when a supposedly ready governance packet carries inconsistent proof, validation, shadow, or blocking state
- history snapshots can show blocked or unobserved entries without discarding them, so cross-cohort review debt remains inspectable over time

### Draft Materialization And Validation Bundles

The repo now ships the bridge from reviewed draft artifacts back into the verified rollout ladder. Operators can materialize a repo-owned experiment manifest from one draft, refresh validation artifacts from that manifest, then reconcile the original draft-backed queue entry in place instead of creating a duplicate proposal.

This bridge stays explicit and operator-triggered:

- materialization artifacts are durable repo-owned records under `data/evolution-materializations/`
- validation bundles are durable repo-owned records under `data/evolution-validation-bundles/`
- reconciliation records are durable repo-owned records under `data/evolution-reconciliations/`
- materialization writes one concrete experiment manifest next to the chosen base experiment manifest
- validation refresh reuses the existing experiment, verification, proof, shadow, and scorecard lanes instead of inventing a second evaluation path
- reconciliation updates the reviewed queue entry created by `evolution-draft-promote`; it does not mint a second queue proposal

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-materialize \
  --draft-id YOUR_DRAFT_ID \
  --base-experiment experiments/office-baseline-control.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-materialization-result \
  --materialization-id YOUR_MATERIALIZATION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-validation-refresh \
  --materialization-id YOUR_MATERIALIZATION_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-validation-result \
  --validation-bundle-id YOUR_VALIDATION_BUNDLE_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-queue-reconcile \
  --promotion-id YOUR_PROMOTION_ID \
  --validation-bundle-id YOUR_VALIDATION_BUNDLE_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-queue-reconciliation-result \
  --reconciliation-id YOUR_RECONCILIATION_ID
```

Materialization supports explicit profile overrides for the current suspicious process-tree candidate type:

- `--add-suspicious-parent VALUE`
- `--remove-suspicious-parent VALUE`
- `--add-suspicious-child VALUE`
- `--remove-suspicious-child VALUE`
- `--high-confidence-threshold FLOAT`
- `--medium-confidence-threshold FLOAT`

Each persisted materialization preserves:

- draft ID, pressure ID, and source experiment reference
- materialized experiment name, path, lineage, and digests
- the concrete suspicious process-tree profile used for the candidate
- a normalized list of applied profile changes

Each persisted validation bundle preserves:

- stable links from one materialization to experiment, verification, proof, shadow, and advisory scorecard artifacts
- manifest and lineage digests used to detect materialization drift
- fail-closed blocking reasons when experiment gates, verification, proof, or shadow evidence fail
- one `ready_for_queue` or `blocked` status for later reconciliation

Each persisted reconciliation preserves:

- the original draft-promotion record and queue proposal ID
- the refreshed validation bundle reference
- the resulting queue review state after the placeholder draft block is replaced with refreshed evidence
- a `handoff_ready` verdict showing whether the existing handoff path can be used after operator acceptance

Failure behavior:

- `evolution-materialize` exits nonzero when threshold overrides are invalid or the base experiment cannot be resolved
- `evolution-validation-refresh` exits nonzero when the refreshed bundle is blocked; the blocked bundle is still persisted for review
- `evolution-queue-reconcile` exits nonzero when the refreshed queue entry remains blocked; the reconciliation record is still persisted
- validation fails closed when materialized manifest or lineage digests drift, when refreshed proof digests do not match the current artifacts, or when verification or shadow evidence fails
- reconciled proposals only become handoff-ready when refreshed verification, proof, and shadow evidence all pass

This bridge keeps the lifecycle explicit: pressure -> draft -> reviewed queue -> materialized experiment -> refreshed validation bundle -> reconciled reviewed queue -> accepted handoff -> canary.

### Evolution Proofs And Verified Proposal Queue

The repo now ships a proof-backed evolution queue for detector proposals. This sits above the advisory scorecard lane and below any future governance-backed rollout system.

The current slice remains deliberately narrow:

- proposals are repo-owned durable artifacts
- queue admission is fail-closed when proof, verification, or lineage evidence is missing or inconsistent
- operator decisions are explicit review records only and do not mutate production detector state directly

Evolution proof artifacts are written under `data/evolution-proofs/` by default.

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- verification-evaluate \
  --experiment experiments/office-baseline-control.yaml

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-proof-create \
  --experiment experiments/office-baseline-control.yaml \
  --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-proof-result \
  --proof-id YOUR_PROOF_ID
```

Each persisted proof captures:

- the candidate strategy, experiment, and verification IDs
- lineage metadata from the experiment manifest
- proof-system label and deterministic SHA-256 digests for the manifest, verification report, and lineage payload
- invariant coverage copied from the passed verification artifact

Evolution queue artifacts are written under `data/evolution-queue/` by default.

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-queue-create \
  --experiment experiments/office-baseline-control.yaml \
  --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 \
  --proof-id YOUR_PROOF_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-queue-list --review-state pending-review

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-queue-decision \
  --proposal-id YOUR_PROPOSAL_ID \
  --decision accept-for-canary \
  --reason "control candidate is ready for bounded canary"

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-queue-result \
  --proposal-id YOUR_PROPOSAL_ID
```

Queue artifacts preserve:

- stable proposal IDs plus current review state
- candidate lineage, verification reference, proof summary, and advisory scorecard summary
- explicit blocking reasons when admission fails closed
- explicit operator decision history such as `accept_for_canary`, `defer`, or `reject`

Failure behavior:

- `evolution-queue-create` exits nonzero when the proposal is blocked
- blocked proposals are still persisted for later review with preserved denial reasons
- `accept-for-canary` is allowed only for unblocked proposals with proved safety evidence

This lane still stops short of governance and rollout mutation. Queue decisions prepare the candidate for later workflows; they do not bypass verification, shadow, canary, or production-promotion steps.

### Queue Handoff And Canary Launch

The repo now ships a queue-to-canary handoff lane. This bridges accepted evolution proposals into the existing bounded canary path without making the operator restate experiment, verification, or proof metadata by hand.

The current slice stays deliberately conservative:

- handoff packets are durable repo-owned artifacts under `data/evolution-handoffs/`
- only `accepted_for_canary` proposals with proved evidence can produce an unblocked handoff
- canary launch is still operator-triggered; accepted proposals do not start rollout implicitly

Example operator flow:

```bash
cargo run -p swarm-runtime-http --bin swarmctl -- evolution-handoff-create \
  --proposal-id YOUR_ACCEPTED_PROPOSAL_ID \
  --shadow-id YOUR_SHADOW_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-handoff-result \
  --handoff-id YOUR_HANDOFF_ID

cargo run -p swarm-runtime-http --bin swarmctl -- evolution-handoff-launch-canary \
  --handoff-id YOUR_HANDOFF_ID
```

Each handoff packet preserves:

- source proposal ID and accepted review state
- experiment path, verification reference, proof summary, and advisory summary
- shadow artifact reference plus suite and corpus context
- blocking reasons when handoff creation fails closed
- resulting canary run ID once launch succeeds

Failure behavior:

- `evolution-handoff-create` exits nonzero when the proposal is not accepted, proof status is not `proved`, or the shadow artifact is missing or inconsistent
- blocked handoff packets are still persisted for later review
- `evolution-handoff-launch-canary` fails when the handoff is blocked or has already launched a canary run

This lane does not replace the existing bounded canary gates. It only preserves and reuses the reviewed queue evidence so operators can launch canary from one durable handoff artifact.

### Historical Field Reference Appendix

The appendix below preserves the older broad mission-schema reference. It is
useful background, but it is not the canonical source of truth for the active
runtime contract. When the appendix conflicts with the active sections above,
the active sections and `rulesets/default.yaml` win.

Below is the older full-schema reference, documented field by field.

```yaml
# ─── Mission Identity ───────────────────────────────────────────────

name: default
# Required. String.
# A short identifier for this mission. Used in log prefixes, NATS subject
# namespacing, and audit trail tagging. Must be unique across concurrent missions.

description: Standard threat hunting mission
# Required. String.
# Human-readable description of the mission's purpose and scope.

# ─── Agent Population ───────────────────────────────────────────────

population:
  # Required. Map of agent role -> population config.
  # Defines how many of each archetype to spawn and their autonomy tier.
  # All 8 archetypes may be specified. Omitted archetypes will not be spawned.

  whisker:
    count: 4
    # Required. Integer >= 0.
    # Number of Whisker agents to spawn at mission start.
    # Whiskers are the primary detection layer. More Whiskers = more telemetry
    # coverage, but each consumes a NATS subscription and CPU for embedding
    # similarity computation. 4 is a good baseline for moderate telemetry volume.

    max_count: 16
    # Required. Integer >= count.
    # Maximum Whiskers the swarm can auto-scale to during Alert/Incident modes.
    # The Dispatcher spawns additional Whiskers when pheromone concentration
    # indicates elevated threat activity.

    tier: tier1
    # Required. One of: tier1, tier2, tier3.
    # Autonomy tier governing what this archetype can do without human approval.
    # tier1: Fully autonomous (routine detection, IOC matching).
    # tier2: Autonomous with reporting (novel detections, hypothesis generation).
    # tier3: Human-approved (response actions, policy changes).

  stalker:
    count: 2
    max_count: 8
    tier: tier2
    # Stalkers investigate leads from Whisker pheromones using LLM-powered
    # hypothesis-driven reasoning. 2 is sufficient for low-to-moderate alert
    # volume. Auto-scales up during active incidents.

  weaver:
    count: 1
    max_count: 4
    tier: tier2
    # Weavers correlate signals across investigations using multi-graph memory.
    # 1 is typically sufficient -- Weavers process aggregated data, not raw
    # telemetry. Scale up only for very high investigation concurrency.

  pouncer:
    count: 1
    max_count: 4
    tier: tier3
    # Pouncers execute response actions (block, isolate, revoke). Always tier3
    # because response actions require BFT consensus from the Tom committee.
    # 1 is sufficient; multiple Pouncers allow parallel response execution
    # during multi-front incidents.

  tom:
    count: 3
    max_count: 5
    tier: tier3
    # Toms govern the swarm: enforce policy, manage lifecycle, run BFT consensus.
    # Minimum 3 for BFT with f=1 (need 2f+1=3 votes out of 3f+1=4 eligible,
    # but 3 Toms can tolerate 0 Byzantine faults with 3/3 agreement).
    # For f=1 tolerance, use 4+ Toms. The default of 3 is minimum viable.
    # max_count should be odd for clean majority thresholds.

  kitten:
    count: 1
    max_count: 2
    tier: tier2
    # Kittens evolve detection strategies via mutation + Z3 verification.
    # 1 is sufficient for most missions. 2 allows parallel exploration of
    # different mutation strategies.

  sphinx:
    count: 1
    max_count: 1
    tier: tier1
    # Sphinx maintains long-term threat memory and the knowledge graph.
    # Singleton by design -- multiple Sphinxes would need graph synchronization.
    # max_count: 1 is intentional.

  calico:
    count: 1
    max_count: 2
    tier: tier1
    # Calico manages deception infrastructure (honeypots, canary tokens).
    # tier1 because deploying deception assets is low-risk and autonomous.
    # Scale up for environments with many deception zones.

# ─── Pheromone Substrate ────────────────────────────────────────────

pheromone:
  # Required. Tunes the stigmergic communication layer.

  default_half_life_secs: 3600
  # Required. Float > 0. Default: 3600 (1 hour).
  # Default exponential decay half-life for pheromone deposits.
  # After this many seconds, a deposit's effective strength is halved.
  #
  # Shorter half-life (e.g., 900 = 15 min): signals fade fast, swarm focuses
  # on recent activity. Good for high-velocity environments.
  # Longer half-life (e.g., 86400 = 24 hrs): signals persist, swarm maintains
  # awareness of older threats. Good for slow-burn APT detection.
  #
  # Individual deposits can override this with their own decay_half_life.

  evaporation_threshold: 0.01
  # Required. Float > 0, < 1. Default: 0.01.
  # Effective strength below which a pheromone is garbage-collected.
  # At default settings (half_life=3600, threshold=0.01), a deposit fully
  # evaporates after approximately 6.6 half-lives = 6.6 hours.
  #
  # Lower values keep faint signals longer (more memory, more noise).
  # Higher values aggressively prune (less memory, risk losing slow signals).

  min_sources_for_escalation: 2
  # Required. Integer >= 1. Default: 2.
  # Minimum number of distinct agents that must contribute deposits to a
  # threat class before concentration can trigger mode escalation.
  # Prevents a single agent from flooding a threat class and causing a
  # false escalation. Set to 1 only if you trust individual agent signals.

  alert_threshold: 2.0
  # Required. Float > 0. Default: 2.0.
  # Pheromone concentration (sum of effective strengths from distinct sources)
  # that triggers Normal -> Alert mode transition.
  # Lower values = more sensitive (more alerts, more false positives).
  # Higher values = less sensitive (fewer alerts, risk missing threats).

  incident_threshold: 5.0
  # Required. Float > alert_threshold. Default: 5.0.
  # Concentration that triggers Alert -> Incident mode transition.
  # Incident mode unlocks Pouncers and focuses all agents.
  # This should be significantly above alert_threshold to prevent
  # premature incident declaration.

# ─── Consensus ──────────────────────────────────────────────────────

consensus:
  # Required. BFT consensus settings for the Tom committee.

  max_byzantine_faults: 1
  # Required. Integer >= 0. Default: 1.
  # Maximum Byzantine faults the consensus protocol tolerates.
  # With f=1, the protocol needs 3f+1=4 total voters and 2f+1=3 approvals.
  # Ensure tom.count >= 2f+1. If tom.count < 2f+1, consensus cannot
  # be reached and response actions will be blocked (fail-closed).
  #
  # f=0: No fault tolerance. All Toms must agree. Fast but fragile.
  # f=1: Tolerates 1 compromised/failed Tom. Minimum for production.
  # f=2: Tolerates 2 faults. Requires 7 Toms (3f+1). High resilience.

  round_timeout_ms: 5000
  # Required. Integer > 0. Default: 5000 (5 seconds).
  # Timeout for a single consensus round (propose + prevote + precommit).
  # If consensus is not reached within this window, the round fails and
  # can be retried with a view change.
  #
  # Lower timeout: faster response but more likely to fail under load.
  # Higher timeout: more tolerant of slow Toms but delays response actions.

  committee_rotation_interval_secs: 3600
  # Required. Integer > 0. Default: 3600 (1 hour).
  # How often the Tom committee membership rotates via VRF.
  # Rotation prevents a persistent attacker from targeting specific Toms.
  # Shorter intervals increase security but cause more state transitions.

# ─── Autonomy Tiers ────────────────────────────────────────────────

autonomy:
  # Required. Defines the confidence boundaries between autonomy tiers.

  tier1_confidence: 0.9
  # Required. Float in (0, 1]. Default: 0.9.
  # Minimum confidence for an action to qualify as Tier 1 (fully autonomous).
  # Actions below this confidence are escalated to Tier 2.
  # High values (0.9+) mean only very confident detections are autonomous.

  tier2_confidence: 0.7
  # Required. Float in (0, tier1_confidence). Default: 0.7.
  # Minimum confidence for Tier 2 (autonomous with reporting).
  # Actions below this confidence are escalated to Tier 3 (human approval).
  # The gap between tier2 and tier1 is the "report but proceed" band.

  require_human_above_severity: critical
  # Required. One of: low, medium, high, critical. Default: critical.
  # Regardless of confidence, any finding at or above this severity
  # requires human approval before response actions.
  # Set to "low" to require human approval for everything (conservative).
  # Set to "critical" to only require humans for the worst threats.

# ─── NATS Connection ───────────────────────────────────────────────

nats:
  # Required. NATS server connection and subject configuration.

  servers:
    - "nats://localhost:4222"
  # Required. List of NATS server URLs.
  # For production, provide multiple servers for cluster failover:
  #   - "nats://nats-1.internal:4222"
  #   - "nats://nats-2.internal:4222"
  #   - "nats://nats-3.internal:4222"

  subject_prefix: "swarm"
  # Required. String. Default: "swarm".
  # Prefix for all NATS subjects used by this mission.
  # Change this to run multiple isolated swarm instances on the same
  # NATS cluster: e.g., "swarm-prod", "swarm-staging", "swarm-test".

  pheromone_stream: "swarm-pheromones"
  # Required. String. Default: "swarm-pheromones".
  # JetStream stream name for pheromone persistence.
  # Must be unique per mission if running multiple swarms on the same cluster.
```

---

## Environment Variables

Environment variables override YAML config for deployment flexibility. They are prefixed with `STS_` (Ambush).

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `STS_CONFIG_PATH` | Path | `rulesets/default.yaml` | Path to the hunt mission YAML file |
| `STS_NATS_SERVERS` | Comma-separated URLs | `nats://localhost:4222` | NATS server URLs (overrides `nats.servers`) |
| `STS_NATS_CREDS` | Path | (none) | Path to NATS credentials file for authenticated connections |
| `STS_NATS_TLS_CERT` | Path | (none) | Path to TLS certificate for NATS |
| `STS_NATS_TLS_KEY` | Path | (none) | Path to TLS private key for NATS |
| `STS_SUBJECT_PREFIX` | String | `swarm` | NATS subject prefix (overrides `nats.subject_prefix`) |
| `STS_LOG_LEVEL` | String | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `STS_LOG_FORMAT` | String | `pretty` | Log format: `pretty` (human), `json` (structured) |
| `STS_ANTHROPIC_API_KEY` | String | (required) | Anthropic API key for Stalker/Weaver/Kitten LLM calls |
| `STS_ANTHROPIC_MODEL` | String | `claude-sonnet-4-20250514` | Model ID for LLM-backed agents |
| `STS_SPIDER_SENSE_PATTERNS` | Path | `builtin:s2bench-v1` | Path to Spider Sense pattern DB (or `builtin:` prefix for embedded) |
| `STS_KEYSTORE_PATH` | Path | (in-memory) | Path to persist agent keypairs. If unset, keys are ephemeral. |
| `STS_MEMORY_BACKEND` | String | `memory` | Knowledge graph backend: `memory`, `sqlite`, `neo4j`, `kuzudb` |
| `STS_MEMORY_DSN` | String | (none) | Connection string for graph database (required for `neo4j`/`kuzudb`) |
| `STS_Z3_TIMEOUT_MS` | Integer | `30000` | Z3 solver timeout for strategy verification |
| `STS_EVOLUTION_CADENCE` | String | `adaptive` | Evolution trigger: `continuous`, `hourly`, `daily`, `adaptive` |
| `STS_RED_SWARM_ENABLED` | Boolean | `false` | Enable the Hellcat red swarm for co-evolutionary training |
| `STS_RED_SWARM_SANDBOX` | Path | (none) | Path to sandboxed target environment for red swarm |

---

## Example Configurations

### Aggressive Hunting

For environments with known active threats where speed matters more than false positive avoidance. High Whisker density, sensitive pheromone thresholds, fast consensus.

```yaml
name: aggressive-hunt
description: Active threat hunting — high sensitivity, fast response

population:
  whisker:
    count: 8
    max_count: 16
    tier: tier1
  stalker:
    count: 4
    max_count: 8
    tier: tier2
  weaver:
    count: 2
    max_count: 4
    tier: tier2
  pouncer:
    count: 2
    max_count: 4
    tier: tier3
  tom:
    count: 5
    max_count: 5
    tier: tier3
  kitten:
    count: 1
    max_count: 2
    tier: tier2
  sphinx:
    count: 1
    max_count: 1
    tier: tier1
  calico:
    count: 2
    max_count: 2
    tier: tier1

pheromone:
  default_half_life_secs: 1800     # 30 min — focus on recent activity
  evaporation_threshold: 0.05      # Aggressive pruning
  min_sources_for_escalation: 1    # Single-agent escalation allowed
  alert_threshold: 1.0             # Very sensitive
  incident_threshold: 3.0          # Low bar for incident declaration

consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 2000           # Fast consensus rounds
  committee_rotation_interval_secs: 1800  # Rotate every 30 min

autonomy:
  tier1_confidence: 0.8            # Lower bar for autonomous action
  tier2_confidence: 0.5            # Lower bar for autonomous + report
  require_human_above_severity: critical

nats:
  servers:
    - "nats://localhost:4222"
  subject_prefix: "swarm"
  pheromone_stream: "swarm-pheromones"
```

**Key differences from default:**
- `min_sources_for_escalation: 1` -- a single Whisker detection can trigger escalation. Trades false positive risk for speed.
- `alert_threshold: 1.0` -- the swarm enters Alert mode quickly.
- `tier1_confidence: 0.8` -- more actions qualify as fully autonomous.
- `round_timeout_ms: 2000` -- consensus rounds complete in 2 seconds.
- Double the Whiskers and Stalkers for broader and deeper coverage.

---

### Passive Monitoring

For production environments where stability matters and the swarm should observe without acting. No Pouncers, high confidence requirements, long pheromone persistence.

```yaml
name: passive-monitor
description: Observation only — detect and report, no response actions

population:
  whisker:
    count: 4
    max_count: 8
    tier: tier1
  stalker:
    count: 1
    max_count: 4
    tier: tier2
  weaver:
    count: 1
    max_count: 2
    tier: tier2
  pouncer:
    count: 0              # No Pouncers — observe only
    max_count: 0
    tier: tier3
  tom:
    count: 3
    max_count: 3
    tier: tier3
  kitten:
    count: 0              # No evolution — stable detection
    max_count: 0
    tier: tier2
  sphinx:
    count: 1
    max_count: 1
    tier: tier1
  calico:
    count: 0              # No deception assets
    max_count: 0
    tier: tier1

pheromone:
  default_half_life_secs: 86400    # 24 hours — long memory
  evaporation_threshold: 0.001     # Keep faint signals
  min_sources_for_escalation: 3    # High source diversity required
  alert_threshold: 4.0             # High bar for alert
  incident_threshold: 10.0         # Very high bar for incident

consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 10000          # Generous timeout
  committee_rotation_interval_secs: 7200

autonomy:
  tier1_confidence: 0.95           # Very high bar for autonomous action
  tier2_confidence: 0.85           # High bar for autonomous + report
  require_human_above_severity: medium  # Human required for medium+

nats:
  servers:
    - "nats://localhost:4222"
  subject_prefix: "swarm"
  pheromone_stream: "swarm-pheromones"
```

**Key differences from default:**
- Pouncers, Kittens, and Calicos set to 0 -- no response, no evolution, no deception.
- `default_half_life_secs: 86400` -- pheromones persist for a full day, enabling slow-burn APT pattern detection.
- `min_sources_for_escalation: 3` -- requires 3 independent agents to confirm before escalation.
- `require_human_above_severity: medium` -- almost everything needs human sign-off.
- This configuration is useful for initial deployment where you want to validate detection quality before enabling response.

---

### Red Team Exercise

For running co-evolutionary training with the Hellcat red swarm enabled. The blue swarm detects while the red swarm attacks a sandboxed environment. Kittens actively evolve.

```yaml
name: red-team-exercise
description: Co-evolutionary training — blue vs red swarm arms race

population:
  whisker:
    count: 6
    max_count: 12
    tier: tier1
  stalker:
    count: 3
    max_count: 6
    tier: tier2
  weaver:
    count: 2
    max_count: 4
    tier: tier2
  pouncer:
    count: 1
    max_count: 2
    tier: tier3
  tom:
    count: 4
    max_count: 5
    tier: tier3
  kitten:
    count: 2              # More Kittens for faster evolution
    max_count: 2
    tier: tier2
  sphinx:
    count: 1
    max_count: 1
    tier: tier1
  calico:
    count: 1
    max_count: 2
    tier: tier1

pheromone:
  default_half_life_secs: 7200     # 2 hours
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0

consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 5000
  committee_rotation_interval_secs: 1800  # Faster rotation for exercise

autonomy:
  tier1_confidence: 0.9
  tier2_confidence: 0.7
  require_human_above_severity: critical

nats:
  servers:
    - "nats://localhost:4222"
  subject_prefix: "swarm-redteam"   # Isolated prefix
  pheromone_stream: "swarm-redteam-pheromones"
```

**Environment variables for this scenario:**

```bash
export STS_CONFIG_PATH=rulesets/red-team-exercise.yaml
export STS_RED_SWARM_ENABLED=true
export STS_RED_SWARM_SANDBOX=/path/to/sandboxed-target
export STS_EVOLUTION_CADENCE=adaptive   # Evolve on red swarm evasion events
export STS_Z3_TIMEOUT_MS=60000          # Longer Z3 timeout for complex strategies
export STS_SUBJECT_PREFIX=swarm-redteam
export STS_LOG_LEVEL=debug              # Verbose logging for exercise analysis
export STS_LOG_FORMAT=json              # Structured logs for post-exercise analysis
```

**Key differences from default:**
- `STS_RED_SWARM_ENABLED=true` -- activates the Hellcat red swarm.
- 2 Kittens for parallel strategy exploration.
- 4 Toms for proper BFT with f=1 (need 4 voters for 3 approvals).
- Isolated NATS prefix (`swarm-redteam`) to prevent interference with production.
- `STS_EVOLUTION_CADENCE=adaptive` -- Kittens evolve when red swarm evasion events are detected, not on a fixed schedule.

---

## Parameter Tuning Guide

### Pheromone Tuning

The pheromone parameters control the swarm's collective sensitivity. They interact with each other:

| Want | Adjust |
|------|--------|
| Faster response to new threats | Lower `alert_threshold`, lower `min_sources_for_escalation` |
| Fewer false escalations | Raise `min_sources_for_escalation`, raise `alert_threshold` |
| Detect slow/persistent threats | Raise `default_half_life_secs`, lower `evaporation_threshold` |
| Focus on recent activity only | Lower `default_half_life_secs`, raise `evaporation_threshold` |
| More aggressive garbage collection | Raise `evaporation_threshold` |

**Effective signal lifetime** (time until a deposit is garbage-collected):

```
lifetime = half_life * log2(initial_confidence / evaporation_threshold)
```

With defaults (half_life=3600, confidence=1.0, threshold=0.01):
`3600 * log2(1.0 / 0.01) = 3600 * 6.64 = 23,918 seconds = ~6.6 hours`

### Consensus Tuning

| Voters (Toms) | max_byzantine_faults (f) | Quorum (2f+1) | Fault Tolerance |
|---------------|--------------------------|---------------|-----------------|
| 3 | 0 | 3 (unanimous) | None — any failure blocks consensus |
| 4 | 1 | 3 | 1 Byzantine or crashed Tom |
| 5 | 1 | 3 | 1 Byzantine, survives 2 crashes |
| 7 | 2 | 5 | 2 Byzantine or crashed Toms |

Rule of thumb: set `tom.count >= 3 * max_byzantine_faults + 1`.

### Scaling Guidance

Scale from measured runtime behavior instead of fixed agent-count tables:

- benchmark the target host and substrate with
  `cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`
  before publishing a new ceiling
- treat roughly 70% of the measured `accepted` ingest rate as the scale-warning
  point and roughly 90% as the scale-before-degradation point
- keep `/readyz` green and keep p95
  `swarm_ingest_request_latency_microseconds` below 1.5x the measured baseline
- size investigation and correlation workers from
  `/healthz.components.async_lane` queue age, running jobs, budget remaining,
  and recent failure counters rather than from telemetry-volume folklore
- Sphinx remains singleton until a later milestone adds explicit sharding or
  federation support

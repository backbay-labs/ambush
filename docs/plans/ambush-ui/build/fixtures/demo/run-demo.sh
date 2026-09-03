#!/usr/bin/env bash
# fixtures/demo/run-demo.sh -- bring up the Perch demo, honestly.
#
# This script does exactly two things it is allowed to do: it checks the
# preconditions that silently ruin the demo, and it starts the two processes.
# It does not fake a hold, it does not seed a receipt, and it prints a line for
# every capability that is not wired yet, so the presenter cannot forget one.
#
#   ./run-demo.sh check    preconditions only, no processes started
#   ./run-demo.sh up       check, then start the daemon and replay the scenario
#   ./run-demo.sh mock     check, then run the desktop app in mock mode only
#
# Run it from the AMBUSH repo root with BUZZ_DIR pointing at block/buzz.

set -euo pipefail

AMBUSH_DIR="${AMBUSH_DIR:-$(pwd)}"
BUZZ_DIR="${BUZZ_DIR:-}"
FIXTURES="${AMBUSH_DIR}/docs/plans/ambush-ui/build/fixtures"
SCENARIO="${FIXTURES}/scenario/hellcat-office-demo.yaml"
DAEMON_BASE="${SWARM_RUNTIME_BASE_URL:-http://127.0.0.1:9090}"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
warn() { printf '\033[33mNOT WIRED  \033[0m%s\n' "$*"; }
ok()   { printf '\033[32mok         \033[0m%s\n' "$*"; }
info() { printf '           %s\n' "$*"; }

fail=0
need() { command -v "$1" >/dev/null 2>&1 || { red "missing: $1"; fail=1; }; }

checks() {
  need cargo
  need node
  [ -n "${BUZZ_DIR}" ] || { red "set BUZZ_DIR to the block/buzz checkout"; fail=1; }
  [ -f "${SCENARIO}" ] || { red "scenario not found: ${SCENARIO}"; fail=1; }

  # --- the four things that silently ruin this demo ------------------------

  # 1. RuntimeMode. In DetectOnly a RequireHuman verdict falls through and
  #    dry-runs; in LiveResponse the runtime returns
  #    AuditResponseRecord::Skipped (crates/swarm-runtime/src/lib.rs:1133-1146)
  #    with lease None and response_attempted false -- which is the refusal B1
  #    replaces with a durable hold. Neither mode produces a hold before B1
  #    lands, but only LiveResponse reaches the state B1 hooks.
  if grep -qE '^[[:space:]]*mode:[[:space:]]*live_response' "${AMBUSH_DIR}/rulesets/default.yaml" 2>/dev/null; then
    ok "runtime mode is live_response"
  else
    warn "runtime.mode is not live_response -- the policy gate dry-runs and the hold state is never reached"
  fi

  # 2. The containment lease store. lease_store_path defaults to None
  #    (crates/swarm-core/src/config/runtime.rs:94-95, :103), and with no store
  #    prepare_containment returns RuntimeError::ContainmentRefused
  #    (crates/swarm-runtime/src/lib.rs:836-844) for all four containment
  #    actions -- so a granted isolate_host fails AT THE DECIDE ROUTE.
  if grep -q 'lease_store_path' "${AMBUSH_DIR}/rulesets/default.yaml" 2>/dev/null; then
    ok "a containment lease store path is configured"
  else
    warn "no containment lease store -- a granted isolate_host refuses with ContainmentRefused, and the containments surface must render 'no lease store configured' as a first-class state"
  fi

  # 3. The bearer token. OperatorAuthState::from_config fails construction with
  #    MissingTokenEnv when any effective principal's token_env is unset
  #    (crates/swarm-runtime-http/src/http/auth.rs:57-82), which is why
  #    swarm_detect logs the containment-router build failure loudly rather than
  #    shipping a daemon with no release route (swarm_detect.rs:1127-1132).
  if [ -n "${SWARM_OPERATOR_TOKEN:-}" ]; then
    ok "SWARM_OPERATOR_TOKEN is set"
  else
    red "SWARM_OPERATOR_TOKEN is unset -- the operator router will not build"
    fail=1
  fi

  # 4. Durability. Both the hold store and the incident store default to
  #    in-memory (crates/swarm-core/src/config/storage.rs:63,:69-71); a restart
  #    destroys every open hold and every FalsePositiveMeasurement ever written.
  warn "hold store and incident store are in-memory by default -- restarting the daemon mid-demo loses the queue and every measurement"

  # --- the capabilities the demo must NOT claim ----------------------------
  warn "B1 HeldActionStore -- RequireHuman is a refusal today, not a queue. Until B1 lands the queue is fixture-backed and the presenter says so out loud."
  warn "B2g governance re-check on the decide path -- missing_governance_receipt_reason and AgentDispatcher::authorize_partition_request are private free/inherent items (crates/swarm-runtime/src/dispatcher.rs:1014, :1294), so a decide route entering at audit_authorize_and_execute skips both."
  warn "B6 envelope signatures -- the one non-test build_signed_envelope caller derives its key from sha256(\"approval-ledger-envelope:{ledger_id}\") (crates/swarm-runtime/src/approval.rs:1807-1809), a public string. Cards ship with envelope_hash and no signature, and render tier 0."
  warn "the copy gate is not CI. tools/check-copy-banned-terms.sh and tools/copy-ban-list.tsv exist as delivered skeletons under docs/plans/ambush-ui/build/skeleton/tools/ and are installed in NEITHER repository; the Buzz-side half named by 16-INVARIANT-TESTS.md D2, desktop/scripts/check-copy-banned-terms.mjs, is not written at all, so the cross-repo parity test that decision depends on cannot run yet. fixtures/demo/check-strings.mjs reads the same TSV and covers this document and the cue card only."

  # 5. Two config keys that look like they gate the Perch routes and do not.
  #    operator_surface.enabled (rulesets/default.yaml:325) gates `swarmctl
  #    serve` on :7766 -- a DIFFERENT PROCESS with its own IngestState and its
  #    own in-memory incident store. 12-BACKEND-BILL-API.md C1 mounts every
  #    Perch route on `swarm_detect --serve` instead, so this key neither
  #    enables nor disables them. Saying so here because the plan set confused
  #    the two processes once already.
  if grep -qE '^[[:space:]]*enabled:[[:space:]]*true' <(sed -n '/^operator_surface:/,/^[a-z]/p' "${AMBUSH_DIR}/rulesets/default.yaml" 2>/dev/null) 2>/dev/null; then
    info "operator_surface is enabled -- that is swarmctl serve on :7766, a different process. It does not gate any Perch route."
  else
    info "operator_surface is disabled -- irrelevant to Perch. Its routes live on swarm_detect --serve at ${DAEMON_BASE}."
  fi

  # 6. correlation.enabled (rulesets/default.yaml:182) is false on the shipped
  #    default, so no Weaver is registered and NO CorrelatedIncident is ever
  #    assembled. The demo mints its own single-member IncidentRecord through
  #    B3i instead, which is the honest path and the one Perch actually uses.
  info "correlation.enabled is false on the shipped default -- no incident is auto-assembled; Perch mints its own through B3i on promote-to-case"

  [ "${fail}" -eq 0 ] || { red "preconditions failed"; exit 1; }
}

case "${1:-check}" in
  check)
    checks
    ;;
  mock)
    checks
    info "building the desktop app WITH the mock bridge -- a plain 'pnpm run build' strips it and every spec fails with 'Cannot read properties of undefined (reading invoke)'"
    ( cd "${BUZZ_DIR}/desktop" && pnpm build:e2e )
    info "port 4173 must be free: reuseExistingServer is true, so a stale server serves the previous build"
    ( cd "${BUZZ_DIR}/desktop" && pnpm test:e2e:smoke -- --grep "perch demo" )
    ;;
  up)
    checks
    info "starting swarm_detect --serve on ${DAEMON_BASE}"
    ( cd "${AMBUSH_DIR}" && cargo run --release --bin swarm_detect -- --serve --config rulesets/default.yaml ) &
    DAEMON_PID=$!
    trap 'kill "${DAEMON_PID}" 2>/dev/null || true' EXIT
    sleep 3
    info "replaying ${SCENARIO} through the demo lane"
    ( cd "${AMBUSH_DIR}" && cargo run --release --bin swarmctl -- first-run --scenario "${SCENARIO}" --pace-ms 900 )
    info "daemon up. Start the console from ${BUZZ_DIR} with: just dev"
    wait "${DAEMON_PID}"
    ;;
  *)
    red "usage: $0 [check|mock|up]"
    exit 2
    ;;
esac

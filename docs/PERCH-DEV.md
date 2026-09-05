# PERCH-DEV — the First-card walking skeleton, end to end

A real `RuntimeEvent::Finding` leaves `swarm_detect --serve` in process, crosses the
bridge, is stored by the Ambush relay, and renders as a `swarm:finding:v1` card in the
desktop console. This document runs that path on one laptop.

**DEBUG BUILD ONLY.** `rulesets-dev/perch-dev.yaml` is signed with the in-repo debug key
and a `--release` daemon refuses it. That refusal is correct: production signs its own
rulesets. Everything below assumes `cargo run` / `cargo build` with no `--release`.

**Two well-known dev credentials live in the committed config**, deliberately. The dev
operator secret is `sha256("ambush-perch-dev-operator-v1")` and the platform read key is
`dev-platform-token`. Both are public by construction so the debug-signed ruleset can name
them without a per-machine re-sign. They authenticate nothing outside a loopback stack.

---

## 0. What was verified, and how

Every command in sections 1 through 6 was run on macOS 15 (arm64) against a **natively
run** stack: Homebrew PostgreSQL 14 on port 5433, Homebrew Redis on 6380, and
`ambush-relay` built from `workspace/` and run on `127.0.0.1:3000` with
`RELAY_URL=ws://localhost:3000`. `docker compose up` itself was **not** exercised, because
the Docker daemon on the authoring machine was unusable. Where a step's behaviour could
differ under compose, this document says so.

| Step | Status |
|---|---|
| 1 sign and validate the ruleset | verified |
| 2 the relay stack | verified natively (Postgres 14 not 17, Redis 7-equivalent, host-run relay); `docker compose up -d postgres redis relay` **not run** |
| 3 `scripts/provision-perch.sh` | verified |
| 4 the daemon, its three log lines, the identities endpoint | verified |
| 5 real telemetry through `/v1/ingest/events` | verified |
| 6 the card read back from the relay | verified |
| 7 the desktop console | **not run here** — Task 24 owns the end-to-end console pass |
| 8 the tuning report moves | route and auth verified; the `E`/`D` verdict half needs step 7 |
| 9 relay outage, 10 the gap | **not run here** |

**What in this document rests on a compose path that was never executed**, so no reviewer
mistakes it for verified:

- Every `docker compose` line as literally written — `up -d postgres redis relay`,
  `stop relay` / `start relay`, `down -v`, `up -d swarm-detect`. Each was replaced by its
  native equivalent, and the substrate differed: PostgreSQL 14 rather than the compose
  file's `postgres:17-alpine`, and a `cargo build` relay rather than one built from
  `workspace/Dockerfile`.
- The `env_file: ./.env.perch` wiring on the `swarm-detect` service. The variables were
  exported into the daemon's environment directly, which exercises the daemon's half of that
  path but not Compose's file parsing.
- `docker compose down -v` as a reset. The lane-recovery claim was proved by deleting the
  relay's `channels`, `channel_members` and `events` rows and restarting the daemon; dropping
  the named volume additionally discards the schema and makes the relay re-run its
  migrations, which was not exercised.
- Everything in "The daemon in a container" below, which is a warning about a path that was
  deliberately not taken.

Two things that read like compose assumptions were measured rather than assumed: the
`localhost` versus `127.0.0.1` rule in step 2, and the in-network host trap at the end of
this document.

---

## 1. Sign the dev ruleset

Idempotent. The sidecar is committed, and re-signing an unedited file must leave the tree
clean, because the signature is deterministic (Ed25519 over a fixed `issued_at_ms`).

```bash
cd "$(git rev-parse --show-toplevel)"
cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets-dev/perch-dev.yaml
test -z "$(git status --porcelain rulesets-dev/)"
cargo run -p swarm-runtime-http --bin swarmctl -- validate --config rulesets-dev/perch-dev.yaml
```

`validate` prints `Status: valid` and `Platform API keys: 1`.

The dev profile lives in `rulesets-dev/`, **not** `rulesets/`: the startup attestation
(`rulesets/attestation.json`, signed with a key that is not in the repository) enumerates
every YAML under `rulesets/`, so a file there that the manifest does not cover fails the
attestation for every daemon in the checkout.

## 2. Environment and the relay stack

```bash
cp .env.perch.example .env.perch
printf 'PERCH_BRIDGE_NOSTR_SEED=%s\n' "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env.perch
set -a; . ./.env.perch; set +a

docker compose up -d postgres redis relay
curl -sf -H 'Accept: application/nostr+json' http://localhost:3000 | head -c 200; echo
```

`.env.perch` is git-ignored. Without a seed the daemon exits non-zero naming the variable,
which is the intended failure: a bridge must not publish under a key nobody chose.

`.env.perch.example` carries `SWARM_OPERATOR_CONTEXT_TOKEN` beside `SWARM_OPERATOR_TOKEN`,
and `set -a` exports both. They are different secrets on purpose: B5 made the read-only
Providence context token stop sharing the credential that also grants approve and
maintenance, and `rulesets-dev/perch-dev.yaml` names the new variable explicitly under
`operator_surface.auth.context_token_env`. Nothing in the hold walkthrough below reads a
context-token surface, so a missing value costs only `/v1/demo/widget`,
`/v1/demo/dashboard` and `/v1/events/stream` — each of which now answers `401
context_token is required` to a caller that presents none.

**`localhost`, not `127.0.0.1`, everywhere.** The relay binds row zero to the connection's
`Host` header (`workspace/crates/ambush-relay/src/tenant.rs`) and seeds exactly one
community for its own `RELAY_URL` host at startup. `docker-compose.yml` sets
`RELAY_URL: ws://localhost:3000`, so a bridge pointed at `ws://127.0.0.1:3000` — the same
socket — is an unmapped host and the relay fails closed at the WebSocket upgrade with a
bare `HTTP error: 404 Not Found`. `perch.relay_url` in the ruleset therefore reads
`ws://localhost:3000`, and it is the same host the desktop adds as its community, which is
what puts the console and the bridge in one record.

## 3. Keys

```bash
bash scripts/provision-perch.sh
```

It prints the operator public key, checks it against the one the ruleset names, and writes
`.perch-dev/operator.nsec` (mode 600, bech32, importable straight into the desktop) plus
`.perch-dev/operator.env`. It does **not** create channels: the twelve lanes are the
bridge's job now (`00-DECISIONS.md` D-FC-5), which is why wiping the relay's database
recovers them on the next daemon start with no operator action. Measured by deleting the
`channels`, `channel_members` and `events` rows and restarting: twelve lanes and
twenty-four memberships came back with no operator action. `docker compose down -v` drops
the named volume as well, so the relay also re-runs its migrations; that fuller reset was
not exercised.

Re-run it after step 4 and it also writes `.perch-dev/identities.json` from the running
daemon. On a relay with `AMBUSH_REQUIRE_RELAY_MEMBERSHIP=true` in `workspace/.env` it then
adds the operator and every bridge identity as relay members; the dev default leaves that
variable unset, the relay is open, and the loop is skipped with a printed note.

## 4. The daemon

```bash
mkdir -p .perch-dev
cargo run -p swarm-runtime-http --bin swarm_detect -- \
  --config rulesets-dev/perch-dev.yaml --serve --bind 127.0.0.1:9090 \
  > .perch-dev/daemon.log 2>&1 &
DAEMON=$!; sleep 6

curl -sf http://127.0.0.1:9090/readyz
grep -q 'perch bridge mounted' .perch-dev/daemon.log
grep -q 'perch operator routes mounted' .perch-dev/daemon.log   # only the new router prints this
grep -q 'lane channels ensured' .perch-dev/daemon.log

curl -sf http://127.0.0.1:9090/metrics/perch/identities > .perch-dev/identities.json
INGEST_PUBKEY=$(python3 -c 'import json;print(json.load(open(".perch-dev/identities.json"))["identities"][0]["pubkey"])')
```

`GET /metrics/perch/identities` is unauthenticated and serves public halves only (D-FC-2).
It answers `{"colony_id": "perch-dev", "identities": [{"slot", "pubkey"}, …]}`.

**Expect six identities from this profile, not three.** The table is one slot for the
ingest identity, one for every *other* admitted agent, then `perch-telemetry` and
`perch-alarm` (`IdentityTable::build`). This ruleset admits four agents, so the list is
four `swarm:ed25519:<agent id>` slots plus the two fixed ones. The count moves with the
config gates that decide which agents register; the last two entries are always telemetry
and alarm, and **the first entry is always the ingest identity**, which is the author of
every finding card and the one `INGEST_PUBKEY` above selects.

The `perch-telemetry` and `perch-alarm` public keys are stable for a given
`(PERCH_BRIDGE_NOSTR_SEED, colony_id)` pair; the `swarm:ed25519:` slots are not, because
the daemon mints a fresh `AgentId` whenever its key directory is empty.

The twelve lanes exist as soon as `lane channels ensured` is logged, with the UUIDs
committed in `perch.lane_channels` and names `lane-<slug-with-dashes>`. The alarm identity
owns each one and every operator principal is added as a member. Restarting the daemon
re-sends the same twelve `kind:9007` events; the relay answers `duplicate: channel already
exists` and the bridge's OK classifier treats that as success, so the channel rows, their
ids and their `created_at` do not move.

## 5. Real telemetry through the real pipeline

Not `/v1/demo/replay` — the actual ingest route, so the finding is produced by the real
detector.

```bash
python3 - <<'PY' > .perch-dev/events.json
import json, yaml, pathlib
doc = yaml.safe_load(pathlib.Path("scenarios/office-dropper-correlation.yaml").read_text())
print(json.dumps([step["event"] for step in doc["input"]["events"]]))
PY

curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events \
  -H 'content-type: application/json' --data @.perch-dev/events.json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print([r["status"] for r in d["accepted"]], "rejected:", len(d["rejected"]))'
```

Expect `['accepted', 'accepted'] rejected: 0`. The response is an object
(`{correlation_id, accepted, rejected}`), not a bare list.

## 6. The card crossed the seam

Read it from the **relay**, out of the daemon's process, before any app opens.

```bash
LANE=$(python3 -c 'import yaml;print(yaml.safe_load(open("rulesets-dev/perch-dev.yaml"))["perch"]["lane_channels"]["execution"])')
sleep 2
PERCH_TEST_RELAY_URL=ws://localhost:3000 PERCH_TEST_LANE_CHANNEL="$LANE" PERCH_TEST_EXPECT_AUTHOR="$INGEST_PUBKEY" \
  cargo test -p swarm-perch-bridge --test relay_live -- --ignored lane_carries_a_finding_card_from_the_ingest_identity
```

This is a Rust test rather than a `curl` because `POST /query` needs a NIP-98 header and
the bridge's own key must never be used to read — it never reads. The test opens a socket
with a throwaway key, `REQ`s
`{"kinds":[9], "#h":[LANE], "authors":[INGEST_PUBKEY], "limit": 20}`, and asserts at least
one event whose line 0 is exactly `<!-- swarm:finding:v1 -->`.

`office-dropper-correlation.yaml` is an `execution` scenario, so its cards land on
`lane-execution`. Read a different lane and you will correctly find nothing.

**On timing.** The pacer publishes at exactly 1 Hz, one frame per tick. On an empty spool
the first card is on the relay inside two seconds. Behind a backlog it is one record per
second, and the evidence stream spools *every* runtime event — including the ones no
producer turns into a card yet, which are committed as
`perch_bridge_skipped_unpublished_total`. After a busy run, budget by
`perch_bridge_ingested_total{stream="evidence"}` minus what has drained, not by two
seconds.

## 7. The console

```bash
cd workspace && just desktop-dev     # or the full Tauri app
```

Restore the identity from `.perch-dev/operator.nsec`, add the community
`ws://localhost:3000`, enable Settings → Experiments → "Operator console", and open
`#lane-execution`. The finding renders as a card badged
`secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record`. Press `E` and the
case opens at `/cases/<case_id>` — "opening the case" until the bridge's
`case channel created` line appears in the daemon log. Press `D` and the write-state row
goes `sending → recorded → acknowledged`.

Set `AMBUSH_PERCH_OPERATOR_ID=console` before launching. The debug seeder's default is
`local-operator` (D-FC-4) while this ruleset's principal is `console`; leave them
disagreeing and the verdict card records one operator id while the daemon records the
other. `AMBUSH_PERCH_DAEMON_BEARER` is the `SWARM_OPERATOR_TOKEN` value.

## 8. The verdict moved the report

Run this **before** step 7 as well and diff the two, so a pre-existing measurement cannot
be mistaken for the verdict's.

```bash
curl -sf http://127.0.0.1:9090/v2/api/runtime/status \
  -H "x-api-key: $SWARM_PLATFORM_API_TOKEN" \
  -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" \
  -H 'x-swarm-schema-version: 1' \
  | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"][0];print(json.dumps({"reviewed":d["false_positive_tracking"],"recommendations":d["alert_tuning"]["recommendations"]},indent=1))' \
  > .perch-dev/status-after.json
diff .perch-dev/status-before.json .perch-dev/status-after.json || true
```

The platform read API authenticates in **two** layers: `x-api-key` against
`platform_api.keys` in the ruleset, then `Authorization: Bearer` against an operator
principal. Send only the bearer and it answers `401 {"error":"missing x-api-key header"}`.

Thresholds (`alert_tuning.rs:6-15`): host 2 reviewed / 2 false positives / 0.75; detector
threshold 4 / 2 / 0.50; rule 3 / 2 / 0.34. One Dismiss moves `reviewed_findings` and
`false_positive_findings`; a recommendation needs two Dismisses on the same host.

The same reviewed set is on the operator surface at
`GET /v1/operator/findings/reviewed`, which takes the operator bearer alone:

```bash
curl -sf http://127.0.0.1:9090/v1/operator/findings/reviewed \
  -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN"
```

## 9. The relay dies for a minute; nothing is lost

```bash
docker compose stop relay; sleep 60; docker compose start relay
curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events -H 'content-type: application/json' --data @.perch-dev/events.json > /dev/null
PERCH_TEST_RELAY_URL=ws://localhost:3000 PERCH_TEST_LANE_CHANNEL="$LANE" PERCH_TEST_EXPECT_AUTHOR="$INGEST_PUBKEY" \
  cargo test -p swarm-perch-bridge --test relay_live -- --ignored the_lane_seq_run_is_contiguous
```

The test reads up to 500 cards from the lane, pulls the envelope out of every one written
by `PERCH_TEST_EXPECT_AUTHOR`, sorts by `seq`, and asserts three things over at least four
cards: `seq` strictly increases, the `prev_envelope_hash` chain is unbroken, and no card
carries a loss `gap`.

**It does not assert that `seq` is consecutive, and must not.** `seq` is the *spool's*,
assigned at append to every record on the issuer's stream, and the evidence stream spools
every runtime event — including the many that no producer turns into a card yet, which are
committed as `perch_bridge_skipped_unpublished_total` and consume their `seq` silently. A
healthy run measured here reads `1, 2, 32, 34, 65, 66, 97, 98, 129, 130, 161, 162`. What
does hold over published cards is the envelope hash chain, because
`chain.prev_envelope_hash` advances only on a publish; that is the stronger claim anyway,
since it catches a dropped, reordered or duplicated card, which a `seq` range cannot.

## 10. A gap renders as a gap

```bash
curl -sf -X POST http://127.0.0.1:9090/metrics/perch/test/stall -H 'content-type: application/json' -d '{"ms": 3000}'
for i in $(seq 1 40); do curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events -H 'content-type: application/json' --data @.perch-dev/events.json > /dev/null; done
```

`POST /metrics/perch/test/stall` exists in debug builds only. More than 1,024 runtime
events accumulate during the stall — `DEFAULT_RUNTIME_EVENT_CAPACITY` — so the
`broadcast::Receiver` lags and drops the oldest. The next finding card carries
`gap.cause = "broadcast_lagged"` with a COUNT and no range, and the console renders the gap
notice above that card.

---

## Shutting down, and the tree

```bash
kill $DAEMON
docker compose down            # add -v to drop the relay database
```

Running the daemon from the repository root leaves four ignored paths behind, and
`tools/check-worktree-clean.sh` reports every one of them as residue:

```bash
rm -rf data/incidents rulesets-dev/data rulesets-dev/governance-partition-state.json
rm -rf /tmp/ambush-perch-dev            # the spool, already outside the repo
bash tools/check-worktree-clean.sh "perch dev"
```

`rulesets-dev/data/agent-keys/` holds real Ed25519 seeds the daemon minted. It is ignored
by `**/data/agent-keys/`, and `tools/check-no-committed-keys.sh` scans tracked files only,
so nothing stops you committing a key you first `git add -f`. Delete the directory instead.

## The daemon in a container

`docker compose up -d swarm-detect` runs the **image's** default command,
`--config /app/rulesets/default.yaml`, and `default.yaml` carries no `perch` block: that
service will not mount a bridge no matter what `PERCH_BRIDGE_NOSTR_SEED` holds. Run the
daemon on the host, as step 4 does.

Moving it into the network is not a matter of mounting a different config, for two reasons
beyond the debug-signature one:

- `ws://localhost:3000` inside that container is the container itself. The in-network
  address is `ws://relay:3000`, and the relay seeds exactly one community — for its own
  `RELAY_URL` host. A bridge announcing a host the relay does not serve is refused at the
  WebSocket upgrade. Measured: a relay seeded for `relay:3000`, a bridge arriving as
  `localhost:3000`, `HTTP error: 404 Not Found`, zero lanes created.
- Making both sides agree on `relay:3000` then makes `localhost:3000` unmapped, and that is
  the address the desktop on the host adds as its community. The console and the bridge
  would stop sharing a record, which is the whole point of the walking skeleton.

`docker-compose.yml` records the rest of what such a move would take.

---

# The hold — steps 11 to 16

Everything above produces a FINDING card. This half produces a HELD ACTION: a response the
policy would have run, stopped at the gate, addressed to a named operator, decided by that
operator, and executed or refused by the daemon on their word.

**It runs on a different profile.** `rulesets-dev/perch-hold-dev.yaml`, not `perch-dev.yaml`
(00-DECISIONS D4 and W3-33): First card is accepted on `detect_only`, which cannot execute
anything, and the hold needs `live_response`. Sign it the same way as step 1.

## 11. A debug binary needs its own startup attestation

`swarm_detect --serve` verifies a signed statement beside its own executable and refuses to
start without one. A release build ships that statement; `cargo build` does not:

```
Error: StartupAttestationFailure { summary: "binary=failed to read startup attestation
`target/debug/swarm_detect.attestation.json`: No such file or directory (os error 2),
rulesets=verified 4 repo-owned ruleset files" }
```

Note that the ruleset half already passed — only the binary statement is missing. Write it
with the debug key, once per rebuild of the binary:

```bash
cargo build -p swarm-runtime-http --bin swarm_detect
cargo run -p swarm-runtime --example attest_debug_binary -- ./target/debug/swarm_detect
```

## 12. The daemon on the live-response profile

```bash
export SWARM_OPERATOR_TOKEN=perch-dev-operator-token
export PERCH_BRIDGE_NOSTR_SEED=$(python3 -c 'import hashlib;print(hashlib.sha256(b"ambush-perch-bridge-dev-v1").hexdigest())')
# The spine (B6) root. A different domain string from the Nostr seed on purpose:
# `perch.spine_seed_env` is required, and the daemon refuses to start without it.
export PERCH_BRIDGE_SPINE_SEED=$(python3 -c 'import hashlib;print(hashlib.sha256(b"ambush-perch-spine-dev-v1").hexdigest())')
./target/debug/swarm_detect --config rulesets-dev/perch-hold-dev.yaml --serve --bind 127.0.0.1:9090
```

Expect `perch bridge starting`, `perch bridge socket authenticated` and
`lane channels ensured lanes=12`. `/readyz` answers 200.

## 13. Produce a hold

The same office-dropper telemetry as step 5. On `live_response` its escalation asks for
`isolate_host` at CRITICAL, which `static.human_gate` holds instead of refusing:

```bash
curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events \
  -H 'content-type: application/json' --data @.perch-dev/events.json
sleep 5
curl -sf "http://127.0.0.1:9090/v1/response/holds" \
  -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" -H 'x-swarm-schema-version: 1' \
  | python3 -m json.tool
```

Expect `open_count: 1`, `store_durable: true`, and one hold whose `state` is `notified`,
whose `action_kind` is `isolate_host`, whose `case_channel` is a UUID and whose
`notified_at_ms` is non-null. A null `notified_at_ms` means the bridge could not address
it — read the daemon log for `hold_undeliverable`, usually a principal with no
`nostr_pubkey` (F18).

## 14. The queue record and the alarm reached the relay

```bash
PK=$(python3 -c "import yaml;print(yaml.safe_load(open('rulesets-dev/perch-hold-dev.yaml'))['operator_surface']['auth']['principals'][0]['nostr_pubkey'])")
CASE=$(curl -sf "http://127.0.0.1:9090/v1/response/holds" -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" \
  -H 'x-swarm-schema-version: 1' | python3 -c 'import json,sys;print(json.load(sys.stdin)["holds"][0]["case_channel"])')

# the 46010 notice, addressed to this operator and scoped to the case channel
curl -s -X POST http://localhost:3000/query -H "X-Pubkey: $PK" -H 'content-type: application/json' \
  -d "[{\"kinds\":[46010],\"#p\":[\"$PK\"],\"limit\":20}]"
# exactly one open swarm:hold:v1 card in the case channel
curl -s -X POST http://localhost:3000/query -H "X-Pubkey: $PK" -H 'content-type: application/json' \
  -d "[{\"kinds\":[9],\"#h\":[\"$CASE\"],\"limit\":20}]"
# the global 26006 alarm
curl -s -X POST http://localhost:3000/query -H "X-Pubkey: $PK" -H 'content-type: application/json' \
  -d '[{"kinds":[26006],"limit":10}]'
```

The notice carries `h` (the case channel), `p` (this operator) and `hold` (the hold id).
The card's line 0 is exactly `<!-- swarm:hold:v1 -->` and its line 1 names the hold, the
action, the severity, the host and the expiry.

## 15. Decide it — leg 2 without the console

The console signs leg 1 onto the relay and then calls the decide route. To exercise the
DAEMON half alone, sign a decision with the same shared preimage function the console uses:

```bash
HOLD=<hold_id from step 13>
cargo run -q -p swarm-runtime-http --example perch_decide_dev -- "$HOLD" refuse "not our host" \
  > /tmp/decide.json
curl -sS -X POST "http://127.0.0.1:9090/v1/response/holds/$HOLD/decide" \
  -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" -H 'x-swarm-schema-version: 1' \
  -H 'content-type: application/json' --data @/tmp/decide.json
```

The helper derives the operator's Ed25519 key from the documented seed
(`Ed25519Signer::from_secret_material("ambush-perch-dev-operator-v1")`) and prints the public
half; it must equal the profile's `verdict_public_key_hex`.

- **refuse** → `state: refused`, `decision.outcome: refused_by_operator`, no receipt, no lease.
- **grant** → `state: executed`, `decision.outcome: granted_executed`, a receipt, an
  `audit_trail_id`, and a `capability_lease` expiring 60 s after the daemon's own decision
  instant. The lease has **no** `issued_at_ms` field (W3-34).
- **the same body twice** → `replayed: true`, the state unchanged.
- **a different decision on a decided hold** → HTTP 409 `hold_already_decided`, "the hold was
  decided under another intent; re-read the hold" — the conflict W3-17 has the console
  re-read rather than retry.

## 16. The console half, headless

The desktop's hold and finding surfaces go through Tauri commands that hold the daemon bearer
and the operator's Ed25519 key, so a browser cannot drive them. Tauri's own test runtime can:
`perch_live_tests.rs` builds the app on `tauri::test::mock_builder()` with the real command
handlers and the generated capabilities, and sends each request through `get_ipc_response`
exactly as the renderer's `invokeTauri` sends it. The commands then sign with the keyring key,
publish over `POST /events`, call the daemon and map its answers, all for real.

```bash
set -a; . .perch-dev/operator.env; set +a          # AMBUSH_PRIVATE_KEY = the operator's nsec (step 3)
export AMBUSH_DEV_KEYRING_SERVICE=ambush-desktop-dev.perch-live-driver   # the driver's OWN keychain blob
export PERCH_LIVE_DAEMON_URL=http://127.0.0.1:9090 PERCH_LIVE_DAEMON_BEARER=$SWARM_OPERATOR_TOKEN
export PERCH_LIVE_VERDICT_PUBKEY=$(python3 -c "import yaml;print(yaml.safe_load(open('rulesets-dev/perch-hold-dev.yaml'))['operator_surface']['auth']['principals'][0]['verdict_public_key_hex'])")
export PERCH_LIVE_OPERATOR_ID=console PERCH_LIVE_RELAY_URL=ws://localhost:3000
export PERCH_LIVE_INGEST_EVENTS=$PWD/.perch-dev/events-grant.json,$PWD/.perch-dev/events.json
cd workspace/desktop/src-tauri && cargo test --lib -- ipc_tests live_tests --include-ignored --nocapture --test-threads=1
```

The keyring service is read once per process, so it MUST be set in the shell, and it must take
the `ambush-desktop-dev.<scope>` form; the driver seeds that blob with the daemon settings and
the well-known dev operator seed, and asserts `perch_operator_identity` returns the key the
profile pins. It produces its own holds by ingesting the fixtures with per-run-unique
`event_id`/`host_id` (telemetry the daemon has already escalated on raises no new hold), grants
first after waiting out the daemon's per-scope minute (a grant inside it is a legitimate
`refused_late`, `policy.scope_rate_limit`), refuses second, replays each, and reads both cards
back from the relay. The finding path promotes the newest admitted card, publishes the verdict,
fails leg 2 against a closed port, retries it with the same verdict id, watches the daemon's
review move only then, and has a forged copy of the card refused as an unadmitted signer. Every
id is printed on `PERCH_LIVE_EVIDENCE` and `PERCH_LIVE_EVIDENCE_FINDING` lines; the record of
one run is `docs/plans/ambush-ui/integration/evidence/walking-skeleton.md`.

## 17. What is still NOT demonstrated

- **The rendered React tree on a real window.** Selecting a hold, the dwell-gated two-stroke
  grant and the rendered two-leg states run against the Playwright mock, which now refuses the
  shapes the Rust side refuses. A real window is the one layer above what §16 drives.
- **`refused_late` from a containment refusal.** Removing `runtime.containment` and
  re-signing does not produce it; a granted `isolate_host` still executes. See W3-35. The
  outcome itself does reproduce, by `policy.scope_rate_limit`, when a scope has seen five
  actions in a minute.

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
bridge's job now (`00-DECISIONS.md` D-FC-5), which is why a `docker compose down -v`
recovers them on the next daemon start with no operator action.

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
service will not mount a bridge no matter what `PERCH_BRIDGE_NOSTR_SEED` holds. The dev
profile is debug-signed and the image builds `--release`, which refuses that signature by
design. Run the daemon on the host, as step 4 does. `docker-compose.yml` records the three
lines that would run the dev profile in a debug image if you need one.

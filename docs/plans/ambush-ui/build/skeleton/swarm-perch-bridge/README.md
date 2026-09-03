# `swarm-perch-bridge` — skeleton

This tree is the artifact for
[`../../11-BRIDGE-CRATE.md`](../../11-BRIDGE-CRATE.md). Every type signature, module boundary and
doc comment is real; every body is `todo!("…")` with the fill-in named. It is meant to be copied
to `AMBUSH crates/swarm-perch-bridge/`, added to `Cargo.toml`'s `members` list, and filled in.

## Before the first commit

1. **Add the workspace member.** `AMBUSH Cargo.toml:3-24` currently lists 20 members; this is the
   21st. Nothing else in the manifest changes — the crate is downstream and no TCB manifest names
   it (`11-BRIDGE-CRATE.md` §1.4).
2. **Add the crate to `tools/check-workspace-layering.sh` in THREE places, in that same commit.**
   ADR 0015 puts `swarm-perch-bridge` in `TRUST_SENSITIVE`, which turns RULE 5 on for
   `src/lib.rs`. Editing only the `TRUST_SENSITIVE` tuple (`:184-191`) fails the gate before it
   ever reads the real tree: the self-test builds a throwaway fixture workspace from
   `FIXTURE_CRATES` (`:618-633`), and the vacuity guard at `:289-294` raises
   `Vacuity("policy names crates that are not workspace members…")` for a policy name absent from
   it — a fixture failure, which exits 1 at `:858-863`. So: the tuple, a `FIXTURE_CRATES` row
   (`swarm-perch-bridge|swarm-core swarm-runtime swarm-response`, matching the real edges), and
   `FIXTURE_DOCUMENTED` (`:637`) so the stub gets the two headings (`:659-671`) and the
   clean-fixture control case (`:794`) still passes. Verify with
   `python3 -c "lines=[l.rstrip() for l in open('crates/swarm-perch-bridge/src/lib.rs')]; print(all(h in lines for h in ('//! ## Owns','//! ## Does not own')))"`.
3. **Run the supply-chain measurement.** `Cargo.toml`'s `nostr` line takes
   `default-features = false` on an unverified hypothesis. Three commands settle it, and a clean
   result deletes `02-ARCHITECTURE-INTEGRATION.md` decision 6's standing `[[bans.skip]]` item:
   ```bash
   cargo tree -p swarm-perch-bridge -i chacha20 -e normal   # expect: nothing
   cargo tree -p swarm-perch-bridge -i hyper     -e normal   # expect: nothing
   cargo deny check bans
   ```
4. **Vendor `src/ws/` properly.** The four files there are the shape, not the content:
   `connection.rs` and `message.rs` must be copied from `BUZZ crates/buzz-ws-client/src/` @
   `eed74bde2` with the Apache-2.0 header and a provenance line, then modified as `src/ws/mod.rs`
   documents. Two of the four upstream panic sites (`.unwrap()` at `connection.rs:170` and `:229`)
   are hard `tools/check-runtime-panic-contract.sh` failures; the other two (`unreachable!()` at
   `:172` and `:231`) are review items. Fix all four.
5. **Run the gates first, not last.**
   ```bash
   bash tools/check-workspace-layering.sh     # expect: exit 0 AFTER the three edits in step 2
   bash tools/check-runtime-panic-contract.sh # expect: exit 0
   bash tools/check-supply-chain.sh
   bash tools/check-worktree-clean.sh "the perch bridge tests"
   ```
   The last one is why `perch.spool_dir` is refused when it resolves inside the workspace: that
   gate uses `find` because it "is immune to .gitignore and does see empty directories".

## Files, and what each decides

| File | Decides |
|---|---|
| `src/lib.rs` | the build inputs, the mount contract, the `## Owns` / `## Does not own` headings |
| `src/stream.rs` | which stream each of the 11 (soon 12 with B1, 13 with B1c, 14 with B1d) `RuntimeEvent` variants belongs to — exhaustive, no `_` arm |
| `src/receive.rs` | the 281 ms hot path, and the import discipline that protects it |
| `src/spool/` | the on-disk format, torn-tail recovery, the `seq` namespace, eviction |
| `src/coalesce.rs` | 10 Hz → 1 Hz, escalation edge-triggering, and the coalesce-is-not-a-gap line |
| `src/pacer.rs` | one frame per identity per tick, front-run packing, `created_at` at drain |
| `src/identity.rs` | key derivation, the `p`-tag assert, the NIP-OA quota consequence |
| `src/publish.rs` | the OK reaper, typed relay rejections, and the zero-`REQ` commitment |
| `src/channels.rs` | case-channel provisioning on **both** promotion triggers, `HoldId`'s shape, and where a case TTL comes from |
| `src/leases.rs` | the 1 Hz containment-lease diff, and what the bridge refuses to invent |
| `src/cards.rs` | marker selection and the `gap` / `coalesced` blocks (schemas are `13-WIRE-SCHEMAS.md`'s) |
| `src/metrics.rs` | the `perch` registry, and the `_total` naming trap |
| `src/config.rs` | the `perch` block, defaulted so the digest-signed ruleset keeps loading |
| `src/error.rs` | one typed variant per failure mode in `11-BRIDGE-CRATE.md` §12 |

## The two things a reader should not have to discover

- **`RuntimeEvent::Escalation` and `ConcentrationSnapshot` stamp a fresh `emitted_at_ms` on every
  one of the ten ticks in a second** (`escalation.rs:253`, `:288`). The ground survey's suggested
  `(threat_class, level, timestamp)` dedupe would never fire. Edge-trigger instead —
  `src/coalesce.rs` carries the correction inline.
- **The bridge issues zero `REQ` and zero `COUNT` frames.** That is what leaves 90% of the relay's
  50-per-5-second `WsEvents` budget free for an alarm burst, and it is asserted by test T-9.
- **The case channel needs a creator on the manual-promotion path, and that is a bill item, not a
  detail.** ADR 0018 C4 enables only manual promotion in the first build, and manual promotion
  emits no `RuntimeEvent::ResponseHeld`. `src/channels.rs`'s `CasePromotionTrigger` has two arms
  for that reason; the second one does not exist until **B1d** lands
  (`11-BRIDGE-CRATE.md` §9.1). Until then, `/cases` is reachable only from a held action.
- **`#watch` must be a private channel and `perch-alarm` must be a member of it**, or every
  `26006` is answered `OK false` at `BUZZ crates/buzz-relay/src/handlers/event.rs:851-852`. See
  `src/channels.rs`'s `PublishAlarm` doc for the measured chain.

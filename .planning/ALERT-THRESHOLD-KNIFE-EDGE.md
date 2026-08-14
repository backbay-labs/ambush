# The shipped `alert_threshold: 2.0` knife edge — finding, measurements, options

**Task:** #26. **Status:** investigated, decision NOT taken (needs the ruleset signing key holder).
**Date:** 2026-08-13.

Every number below is asserted by
`crates/swarm-runtime/tests/shipped_alert_threshold_reachability.rs`, which loads
the real `rulesets/default.yaml` rather than a hand-written config literal. If
the shipped numbers change, those tests fail rather than this document going
quietly stale. Reproduce with:

```
cargo test -p swarm-runtime --test shipped_alert_threshold_reachability -- --test-threads=1 --nocapture
```

## The reported concern

`rulesets/default.yaml:58` sets `alert_threshold: 2.0` alongside
`min_sources_for_escalation: 2` (line 57) and `default_half_life_secs: 3600.0`
(line 55). Pheromone strength decays as `confidence * 0.5^(elapsed / half_life)`.
Two maximum-confidence (1.0) deposits therefore sum to exactly `2.0` at the
instant of deposit and to less one second later — so `Alert` would hold for
exactly one second and `Normal` thereafter.

The arithmetic is correct. The operational conclusion drawn from it is not.

## What was measured

### 1. The arithmetic is confirmed — for a *hypothetical* unit-confidence pair

`PheromoneConcentration::exceeds_threshold` (`crates/swarm-core/src/pheromone.rs:334`)
compares with `>=`, so the boundary second does escalate:

| elapsed | total_strength | `>= 2.0`? |
| ------- | -------------- | --------- |
| +0s     | `2.000000000`  | yes       |
| +1s     | `1.999614955`  | no        |
| +2s     | `1.999229985`  | no        |

Test: `unit_confidence_pair_clears_the_threshold_for_one_second_only`.

That this is a true exact-equality boundary is proven by mutation: changing
`exceeds_threshold` from `>=` to `>` makes the boundary second stop escalating
and the test fails with `left: 0, right: 1`.

### 2. But the shipped detector cannot produce a unit-confidence deposit at all

The shipped `detection.strategy` is `suspicious_process_tree`, and the strongest
finding it emits is capped at `high_confidence_threshold`, which the shipped file
sets to `0.90`. Driving the real detection pipeline
(`swarm_runtime::detection::detect_and_deposit`) with a maximally suspicious
event — suspicious parent, suspicious child, base64-encoded command line —
measured:

```
MEASURED two-source shipped concentration at t=0: total_strength=1.800000 distinct_sources=2
```

**1.80 never reaches 2.0, at any elapsed time.** For the shipped configuration
the threshold is not a one-second knife edge — on two detections it is simply
unreachable, and it is the confidence ceiling, not decay, that keeps it there.

Test: `two_saturated_shipped_detections_never_reach_the_alert_threshold`.

### 3. Normal event flow crosses the threshold on the *second* event

Strength accumulates per deposit; `distinct_sources` counts distinct
strategy-scoped agents. A second event observed by the same two agents adds two
more deposits:

```
MEASURED four shipped deposits from two agents: total_strength=3.600000 distinct_sources=2
```

3.60 clears 2.0 with real margin, and holds:

```
MEASURED seconds the four-deposit concentration stays >= 2.0: 3053
```

**51 minutes**, not one second. So in a real deployment the escalation arrives on
the second event and is held by strength for tens of minutes.

Test: `a_second_event_from_the_same_two_agents_crosses_the_threshold`.

### 4. What the operator *sees* is latched, not the raw concentration

`SwarmMode` does not follow concentration down. Once `ConcentrationMonitor`
escalates, it returns to `Normal` only after `deescalation_cooldown_secs` (300)
of continuously observing nothing. Measured on the hypothetical unit-confidence
pair: mode is `Alert` at T, still `Alert` at T+1 (with no further event emitted
and `mode_changed == false`), still `Alert` at T+300, and returns to `Normal` at
T+301 — the cooldown running from the first quiet observation.

**So even in the hypothetical worst case, the concentration flips after one
second but the operator-visible mode holds Alert for five minutes.**

Test: `the_mode_latch_holds_alert_for_the_full_deescalation_cooldown`.

### 5. The monitor's cadence samples the boundary second from 91% of arrivals

`swarm_detect` runs the monitor with `CONCENTRATION_MONITOR_INTERVAL_MS = 100`
(`crates/swarm-runtime-http/src/bin/swarm_detect.rs:40`), and each evaluation
reads `unix_timestamp_secs()` — whole seconds. Deposits carry second-granularity
timestamps too. So the "boundary instant" is a whole second wide and a 100ms loop
takes ten ticks inside it.

Sweeping the deposit arrival across the second in 10ms steps:

```
MEASURED arrival offsets (of 100, 10ms apart) that still observe the
boundary-second Alert: 91; missed at [910, 920, ..., 990]
```

The only miss window is arrival after the second's last tick (900ms), leaving no
further tick inside its own second. **9% miss, not 100%.**

Test: `the_hundred_millisecond_cadence_misses_only_the_last_tenth_of_the_boundary_second`.
Non-vacuity proven by mutation: with `exceeds_threshold` weakened to `>`, the
measured count drops from 91 to 0 and the test fails.

## Answers to the questions asked

**1. Does the escalation the operator sees really flip after one second?**
No. Two things prevent it. The `SwarmMode` latch holds `Alert` for the full
300s de-escalation cooldown (§4), and the monitor's 100ms cadence observes the
boundary second from 91 of 100 arrival offsets (§5). What flips after one second
is the raw concentration, which is not what the operator surface reports.

**2. Is the one-second boundary reachable in a real deployment?**
Not with the shipped configuration. It requires two deposits of confidence
`1.0`, and the shipped detector's ceiling is `high_confidence_threshold = 0.90`,
giving 1.80 (§2). Normal event flow re-deposits and crosses 2.0 on the second
event at 3.60, holding above the line for 3053s (§3). The knife edge is
reachable only by a configuration that raises `high_confidence_threshold` to
1.0, or by a detector or intel source that deposits unit confidence directly.

**3. Is this a defect?**
Not as shipped. It is a latent sharp edge: the *pair* `alert_threshold: 2.0` with
`min_sources_for_escalation: 2` means "two sources at full confidence, exactly",
so any future configuration that does reach 1.0 confidence lands on an exact
float equality. That is a fragile place for a threshold to sit even though
nothing shipped reaches it.

## Options

Listed for the decision-maker; **no change is made here.**

- **A. Leave it.** Defensible: unreachable for the shipped detector, and decay
  plus a latch is the intended pheromone behaviour. Costs nothing.
- **B. Lower `alert_threshold` (e.g. to 1.5).** Two saturated shipped detections
  (1.80) would then escalate on the *first* event rather than the second, and
  would hold above 1.5 for well over an hour. Changes shipped alerting volume;
  needs a false-positive assessment first.
- **C. Leave the threshold and document the pairing.** Record in the ruleset
  comments that 2.0 with `min_sources_for_escalation: 2` is an exact-equality
  boundary for unit-confidence sources, so anyone raising
  `high_confidence_threshold` to 1.0 knows what they are landing on.
- **D. Make the boundary non-exact in code.** Compare with a small epsilon, or
  document `>=` as deliberate. This touches `swarm-core` rather than the ruleset
  and so does not need the signing key — but it changes escalation semantics for
  every threshold, not just this one.

Recommendation: **C**, optionally with **D** considered separately. B should not
be taken without false-positive measurement.

## Constraint: `rulesets/default.yaml` cannot be edited in this repo

This is not a policy preference — it is enforced by the loader, and was measured.

- `rulesets/attestation.json` records `rulesets/default.yaml` with
  `sha256 = bc63f0e53780325317f638b6e22f4d6f638048fc7ba177485c18592f6104c324`,
  signed ed25519 under key id `b0c91174…`.
- `rulesets/default.yaml.sig.json` binds the same digest plus the file name and
  size, signed under key id `854cb2ac…`.
- **Neither private key is present in this repository.**

Measured behaviour of `swarm_runtime::config::load_config`:

| what was loaded                                        | result                                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------------------- |
| byte-identical copy, renamed `copy.yaml`                | refused — `SubjectMismatch { expected: "copy.yaml", actual: "default.yaml" }` |
| byte-identical copy, named `default.yaml`, own sidecar  | loads; all six tests pass                                                  |
| same file with `alert_threshold: 2.0` → `1.5`           | refused — `DigestMismatch { expected_sha256: "bc63f0e5…", observed_sha256: "582cf12b…" }` |

So **any change to the shipped default requires whoever holds the ruleset
signing key** to re-sign both `default.yaml.sig.json` and `attestation.json`. A
change cannot be landed from this repository alone, and this investigation
deliberately did not attempt one.

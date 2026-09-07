//! FALSIFY-02 negative-falsifiability test for
//! `SpineEnvelopeCanonicalizationRequired` (docs/assurance/MAPPING.md) --
//! and this registry's ONE deviation from the "call the real function on an
//! input it denies" pattern every other `negative_*` test follows. See
//! `.superpowers/sdd/285-01-PLAN/task-3-report.md` for the full writeup.
//!
//! `envelope_signing_bytes` (crates/swarm-spine/src/envelope.rs:45-47) denies
//! computing signing/hash bytes for an envelope body containing a JSON value
//! that cannot be canonicalized -- concretely, a non-finite `f64`
//! (`swarm_crypto::canonical::canonicalize_f64`,
//! crates/swarm-crypto/src/canonical.rs:77-82: `if !value.is_finite() {
//! return Err(..) }`).
//!
//! THE DEVIATION: verified empirically below (not just asserted in this
//! comment, so the claim is re-checked on every run, not merely true when it
//! was written) -- a `serde_json::Value` cannot actually CARRY a non-finite
//! number through any construction path this crate's pinned `serde_json`
//! exposes:
//!   * `serde_json::Number::from_f64` returns `None` for NaN/infinite, so
//!     `Value::from(f64::NAN)` (what `serde_json::json!` and `to_value` both
//!     route through) silently becomes `Value::Null`, never a non-finite
//!     `Number`;
//!   * parsing an out-of-range numeric literal (`1e400`, or 400 nines, with
//!     or without a fractional part or sign) fails at `serde_json::from_str`
//!     ITSELF with "number out of range", before any `Value` exists to hand
//!     to `envelope_signing_bytes` at all.
//!
//! So no value reachable through the public `serde_json::Value` API can ever
//! drive `envelope_signing_bytes` (or `swarm_crypto::canonicalize_json`) into
//! this branch: it is genuinely unreachable from outside the crate today, not
//! merely hard to reach. Changing production visibility to force a path in
//! would violate this task's own constraints, and fabricating a call that
//! never actually denies would be a lie dressed as a passing test.
//!
//! The closest honest falsification available without touching production
//! code: assert the two `serde_json` behaviors above hold (so this test
//! fails loudly the day they don't, rather than staying green over a claim
//! that quietly stopped being true), then falsify the guard's LOGIC directly
//! on a bare `f64` -- the tightest level still reachable.

#![allow(clippy::unwrap_used, clippy::expect_used)]

/// A faithful copy of `canonicalize_f64`'s finiteness guard
/// (crates/swarm-crypto/src/canonical.rs:77-82).
fn real_shaped_finite_check(value: f64) -> Result<(), String> {
    if !value.is_finite() {
        return Err("Non-finite numbers are not valid JSON".to_string());
    }
    Ok(())
}

/// The same guard with the finiteness check removed entirely.
fn broken_finite_check(value: f64) -> Result<(), String> {
    let _ = value;
    Ok(())
}

#[test]
fn negative_spine_envelope_canonicalization_required() {
    // --- empirical proof that the real function's input type cannot carry
    // the triggering value (see module doc). Re-checked every run. ---
    assert!(
        serde_json::Number::from_f64(f64::NAN).is_none(),
        "serde_json must keep rejecting NaN in Number::from_f64 for this deviation to hold"
    );
    assert!(
        serde_json::Number::from_f64(f64::INFINITY).is_none(),
        "serde_json must keep rejecting infinity in Number::from_f64 for this deviation to hold"
    );
    assert!(
        matches!(serde_json::to_value(f64::NAN), Ok(serde_json::Value::Null)),
        "serde_json::to_value(NaN) must keep silently becoming Value::Null, never a Number"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>("1e400").is_err(),
        "serde_json must keep rejecting out-of-range literals at parse time"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&"9".repeat(400)).is_err(),
        "serde_json must keep rejecting an out-of-range plain-digit literal at parse time too"
    );

    // --- the closest honest falsification: the guard's logic in isolation ---
    // 1. The real-shaped guard denies non-finite input.
    assert!(
        real_shaped_finite_check(f64::NAN).is_err(),
        "the real guard's logic must reject NaN"
    );
    assert!(
        real_shaped_finite_check(f64::INFINITY).is_err(),
        "the real guard's logic must reject infinity"
    );

    // 2. The broken variant permits the identical input.
    assert!(
        broken_finite_check(f64::NAN).is_ok(),
        "broken variant is expected to (wrongly) accept NaN"
    );
    assert!(
        broken_finite_check(f64::INFINITY).is_ok(),
        "broken variant is expected to (wrongly) accept infinity"
    );
}

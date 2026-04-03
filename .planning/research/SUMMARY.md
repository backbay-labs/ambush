# Research Summary

## Stack

The strongest direction is a narrow Rust stack centered on Tokio, structured tracing, strict Serde contracts, an in-memory-first substrate, and deterministic policy plus response traits. Python and PyO3 should remain reference-only unless a future offline workflow truly needs them.

## Table Stakes

The project needs:

- a real Rust detector
- measurable latency and throughput
- deterministic policy evaluation
- narrow live response execution
- signed or hashed receipts
- strict config loading
- critical-path integration tests

## Watch Out For

- premature distributed governance
- porting the Python architecture literally
- broadening response scope before one safe path is trusted
- letting vendor copies turn into hidden dependencies
- claiming performance without benchmark artifacts

## Build Order

1. lock contracts and config
2. build one real detector and in-memory substrate
3. add deterministic policy and sandbox response
4. add receipts, tracing, and tests
5. harden durability and operations
6. only then evaluate advanced distributed or research-heavy features


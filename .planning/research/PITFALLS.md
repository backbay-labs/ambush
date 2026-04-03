# Pitfalls Research: What To Avoid Early

## 1. Recreating The Python Architecture In Rust

### Warning Signs

- too many agent abstractions before one working detector exists
- porting names and boundaries literally instead of porting the useful ideas

### Prevention

- treat the Python tree as reference, not blueprint
- prioritize one narrow Rust vertical slice over architecture parity

### Phase

- Phase 1

## 2. Premature Distributed Governance

### Warning Signs

- consensus, VRF rotation, and committee semantics appear before one safe response adapter exists
- safety claims depend on multi-node behavior that has not been deployed

### Prevention

- use a deterministic local policy gate and human gate first
- only reintroduce distributed governance if independent trust domains become real

### Phase

- Phase 3+

## 3. Unsafe Live Response Scope

### Warning Signs

- many response adapters added at once
- enforced mode enabled before dry-run and receipt tests are trustworthy

### Prevention

- start with one sandboxed adapter
- require explicit policy decisions and receipts for every action
- gate destructive actions behind human approval first

### Phase

- Phase 2

## 4. Missing Performance Discipline

### Warning Signs

- detector “works” but no p50/p95/p99 or throughput numbers exist
- config and payload shape churn block benchmarking

### Prevention

- add benchmarks alongside the first real detector
- lock event contracts early enough to make measurements meaningful

### Phase

- Phase 1

## 5. Stringly Typed Contracts

### Warning Signs

- threat classes, severities, or action scopes collapse into free-form strings
- config validation lives in docs instead of code

### Prevention

- tighten Rust enums and structs
- reject malformed config at load
- keep policy and response request types explicit

### Phase

- Phase 1

## 6. Letting Vendor References Become Product Code By Accident

### Warning Signs

- copied upstream files start getting imported directly
- STS APIs mirror vendor layout instead of product needs

### Prevention

- treat `vendor/reference/` as read-only inspiration
- port ideas inward into STS-owned crates
- delete reference trees once ambiguity is gone

### Phase

- All phases


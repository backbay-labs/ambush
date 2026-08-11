# Phase 254 Context

## Goal

Add a repo-owned CI regression gate for the hot-path Criterion benchmark with a tracked p99 baseline and refresh guidance.

## Starting Point

- The runtime already shipped a `hot_path` Criterion bench and the docs described the benchmark slice, but CI did not enforce any regression threshold.
- The tracked percentile sample had drifted behind the current runtime, so activating the gate also required baseline refresh workflow clarity.

## Constraints

- The gate had to parse repo-owned benchmark output instead of relying on external services.
- The baseline mechanism needed to be inspectable and easy to refresh when intentional performance tradeoffs land.
- The benchmark helper had to remain portable across CI Linux shells and local macOS Bash 3.

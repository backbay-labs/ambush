//! LOOM-01 — concurrent deposit vs. decay-eviction over the local-journal
//! substrate, plus the non-Loom regression that binds the abstract model to the
//! real production repair.
//!
//! This file has two disjoint halves selected by cfg:
//!
//! * `#[cfg(loom)]` — a `bounded_abstract_model` (labelled exactly that in
//!   `docs/assurance/MAPPING.md`). Loom instruments only `loom::sync` types, not
//!   the substrate's real `std::sync::RwLock`/`std::fs`, so the model reconstructs
//!   the deposit/GC split-persistence seam from reviewed Loom state rather than by
//!   wrapping the production locks. Compiled only under `RUSTFLAGS="--cfg loom"`.
//!
//! * `#[cfg(not(loom))]` — a real, non-Loom concurrent-reopen regression driving
//!   the actual `LocalJournalPheromoneSubstrate` on a real temp journal. It fails
//!   if the persistence-ordering repair in `substrate.rs::deposit` is reverted and
//!   passes with it. This is the source-bound falsification control; the abstract
//!   Loom model alone does not prove production-source sensitivity.

#![allow(clippy::unwrap_used, clippy::expect_used)]

// ---------------------------------------------------------------------------
// LOOM-01: bounded_abstract_model of the deposit/GC split-persistence seam.
// ---------------------------------------------------------------------------
#[cfg(loom)]
mod loom_model {
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    // An evaporated deposit that `gc_evaporated` must evict.
    const STALE: u64 = 1;
    // A fresh, non-evaporated deposit committed concurrently with GC; it must
    // survive on disk so a reopen (which reads the journal) recovers it.
    const FRESH: u64 = 2;

    // Toggle (env, not a second cfg) that models the UNFIXED production ordering
    // so the falsification can be demonstrated without editing the model:
    //   LOOM_FALSIFY=1 RUSTFLAGS="--cfg loom" cargo test -p swarm-pheromone \
    //       --test loom_concurrent_write -- --test-threads=1
    fn model_unfixed_deposit() -> bool {
        std::env::var_os("LOOM_FALSIFY").is_some()
    }

    fn bounded_builder() -> loom::model::Builder {
        let mut builder = loom::model::Builder::new();
        // Documented preemption bound of 2 (287 design of record / codex prep):
        // enough to expose the append/rewrite interleaving while keeping the
        // model finite. The CI wall-clock timeout is the failing bound.
        builder.preemption_bound = Some(2);
        // Leave the permutation/duration caps UNSET: either can halt exploration
        // "successfully" and manufacture a false pass. Set explicitly to None so a
        // stray LOOM_MAX_* in the environment cannot introduce such a cap.
        builder.max_permutations = None;
        builder.max_duration = None;
        builder
    }

    /// The substrate's only lock is the `deposits: Arc<RwLock<Vec<..>>>`. The
    /// JSONL journal file has NO lock of its own; each append/rewrite syscall is
    /// individually atomic (one `disk` acquisition), but cross-operation ordering
    /// is governed solely by the deposits lock. `mem` models that lock, `disk`
    /// models the journal file.
    ///
    /// FIXED (production, post-repair): `deposit` holds the deposits lock across
    /// BOTH the disk append and the memory push; `gc_evaporated` holds it across
    /// retain + rewrite. The two are therefore serialized and a fresh deposit can
    /// never be dropped from disk.
    ///
    /// UNFIXED (`LOOM_FALSIFY`): `deposit` appends to disk OUTSIDE the deposits
    /// lock; Loom finds the schedule where GC takes the lock and rewrites the
    /// journal from a memory snapshot that predates the push, dropping FRESH.
    #[test]
    fn a_fresh_deposit_survives_when_gc_rewrites_the_journal_concurrently() {
        bounded_builder().check(|| {
            let mem = Arc::new(Mutex::new(vec![STALE]));
            let disk = Arc::new(Mutex::new(vec![STALE]));

            // decay-eviction: retain the non-evaporated, rewrite the journal from
            // the retained in-memory vector, all under the deposits lock.
            let gc = {
                let mem = mem.clone();
                let disk = disk.clone();
                thread::spawn(move || {
                    let mut m = mem.lock().unwrap();
                    m.retain(|&id| id != STALE);
                    let snapshot: Vec<u64> = m.clone();
                    let mut d = disk.lock().unwrap();
                    *d = snapshot;
                })
            };

            let deposit = {
                let mem = mem.clone();
                let disk = disk.clone();
                thread::spawn(move || {
                    if model_unfixed_deposit() {
                        // append_jsonl_line OUTSIDE the deposits lock (the bug).
                        {
                            let mut d = disk.lock().unwrap();
                            d.push(FRESH);
                        }
                        let mut m = mem.lock().unwrap();
                        m.push(FRESH);
                    } else {
                        // Hold the deposits lock across append + push (the repair).
                        let mut m = mem.lock().unwrap();
                        {
                            let mut d = disk.lock().unwrap();
                            d.push(FRESH);
                        }
                        m.push(FRESH);
                    }
                })
            };

            gc.join().unwrap();
            deposit.join().unwrap();

            // Reopen reads from disk: the fresh deposit must be present and the
            // evaporated one must be gone.
            let final_disk = disk.lock().unwrap();
            assert!(
                final_disk.contains(&FRESH),
                "fresh deposit was dropped from the journal by a concurrent GC rewrite"
            );
            assert!(
                !final_disk.contains(&STALE),
                "evaporated deposit was not evicted from the journal"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// LOOM-01 falsification control (non-Loom): real substrate, real journal, real
// reopen. Fails iff the substrate.rs deposit persistence-ordering repair is
// reverted.
// ---------------------------------------------------------------------------
#[cfg(not(loom))]
mod concurrent_reopen_regression {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, Severity};
    use swarm_pheromone::{
        DepositQuery, DepositSigningPayload, LocalJournalPheromoneSubstrate, PheromoneSubstrate,
    };

    // Fixed evaluation instant. A prefill deposit timestamped far in the past
    // with a 1s half-life is fully evaporated at GC_NOW; a fresh deposit
    // timestamped at GC_NOW is at full strength and must be retained.
    const GC_NOW: i64 = 2_000_000_000;
    const PREFILL_TS: i64 = 1_000_000_000;

    // Concurrency shape. Once GC holds the deposits lock and rewrites the
    // journal, every concurrent depositor that has appended-to-disk-but-not-yet-
    // pushed (blocked on that same lock, in the buggy ordering) has its appended
    // line clobbered, so a handful of concurrent depositors reproduces the loss
    // reliably; the iteration loop removes any residual scheduling luck.
    const DEPOSITS_PER_ITER: usize = 16;
    const ITERATIONS: usize = 32;

    fn local_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: ResponsePlaybookConfig::default(),
            // Ignored by LocalJournalPheromoneSubstrate::open; present only to
            // satisfy the config shape.
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn signing_key_for_label(label: &str) -> SigningKey {
        let digest = Sha256::digest(label.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        SigningKey::from_bytes(&seed)
    }

    fn agent_id_for_label(label: &str) -> AgentId {
        AgentId::from_verifying_key(&signing_key_for_label(label).verifying_key())
    }

    fn sign_deposit(deposit: &mut PheromoneDeposit, key: &SigningKey) {
        let payload = DepositSigningPayload {
            schema_version: deposit.schema_version,
            indicator: &deposit.indicator,
            threat_class: &deposit.threat_class,
            severity: &deposit.severity,
            confidence: deposit.confidence,
            timestamp: deposit.timestamp,
            decay_half_life: deposit.decay_half_life,
            agent_id: &deposit.agent_id,
            agent_identity: &deposit.agent_identity,
            agent_role: deposit.agent_role,
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("deposit signing payload");
        let signature = key.sign(&payload_bytes);
        deposit.signature = signature.to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
    }

    fn signed_deposit(label: &str, timestamp: i64, decay_half_life: f64) -> PheromoneDeposit {
        let key = signing_key_for_label(label);
        let agent_id = agent_id_for_label(label);
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({ "label": label }),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 1.0,
            timestamp,
            decay_half_life,
            agent_id: agent_id.clone(),
            agent_identity: agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        sign_deposit(&mut deposit, &key);
        deposit
    }

    fn fresh_label(iter: usize, k: usize) -> String {
        format!("fresh-{iter}-{k}")
    }

    #[test]
    fn fresh_deposits_survive_a_concurrent_gc_and_reopen() {
        // A dedicated multi-threaded runtime; the substrate methods are async
        // wrappers over blocking fs + std locks, so external OS threads drive
        // them via `Handle::block_on` for genuine parallelism.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();

        for iter in 0..ITERATIONS {
            let dir = std::env::temp_dir()
                .join(format!("ambush-loom-reopen-{}-{iter}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let journal = dir.join("pheromones.jsonl");

            let substrate = LocalJournalPheromoneSubstrate::open(local_config(), &journal).unwrap();

            // Prefill with evaporated deposits so GC has a real journal to rewrite.
            for k in 0..DEPOSITS_PER_ITER {
                let stale = signed_deposit(&format!("stale-{iter}-{k}"), PREFILL_TS, 1.0);
                handle.block_on(substrate.deposit(stale)).unwrap();
            }

            // Release GC and every fresh depositor together.
            let barrier = Arc::new(Barrier::new(DEPOSITS_PER_ITER + 1));
            let mut threads = Vec::with_capacity(DEPOSITS_PER_ITER + 1);

            {
                let handle = handle.clone();
                let barrier = barrier.clone();
                let substrate = substrate.clone();
                threads.push(thread::spawn(move || {
                    barrier.wait();
                    handle.block_on(substrate.gc_evaporated(GC_NOW)).unwrap();
                }));
            }

            for k in 0..DEPOSITS_PER_ITER {
                let handle = handle.clone();
                let barrier = barrier.clone();
                let substrate = substrate.clone();
                let deposit = signed_deposit(&fresh_label(iter, k), GC_NOW, 3600.0);
                threads.push(thread::spawn(move || {
                    barrier.wait();
                    handle.block_on(substrate.deposit(deposit)).unwrap();
                }));
            }

            for thread in threads {
                thread.join().unwrap();
            }

            // Reopen from disk (fresh in-memory state, journal is the source of
            // truth) and assert every committed fresh deposit was recovered.
            let reopened = LocalJournalPheromoneSubstrate::open(local_config(), &journal).unwrap();
            let recovered = handle
                .block_on(reopened.query_deposits(DepositQuery::recent(100_000)))
                .unwrap();

            for k in 0..DEPOSITS_PER_ITER {
                let expected = agent_id_for_label(&fresh_label(iter, k));
                assert!(
                    recovered.iter().any(|deposit| deposit.agent_id == expected),
                    "fresh deposit {expected:?} (iter {iter}, k {k}) was lost from the \
                     journal after a concurrent gc_evaporated + reopen",
                );
            }

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

use clap::Parser;
use notify::{EventKind, RecursiveMode, Watcher};
use serde_json::json;
use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use swarm_core::agent::SwarmModeState;
use swarm_core::types::AgentId;
use swarm_policy::ApprovalContext;
use swarm_runtime::bridge_runtime::BridgeRuntimeRegistry;
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::dispatcher::{AgentDispatcher, AgentDispatcherConfig};
use swarm_runtime::escalation::ConcentrationMonitor;
use swarm_runtime::ingest::{IngestState, detect_http_router};
use swarm_runtime::investigation::SummaryInvestigator;
use swarm_runtime::pounce_agent::PounceAgent;
use swarm_runtime::replay::{ReplayScenarioInput, load_scenario_manifest, scenario_paths_in_dir};
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};
use swarm_runtime::stalker_agent::StalkerAgent;
use swarm_runtime::tom_agent::{GovernancePolicy, TomAgent};
use swarm_runtime::weaver_agent::WeaverAgent;
use swarm_runtime::whisker_agent::WhiskerAgent;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

const RELOAD_DEBOUNCE_MS: u64 = 500;
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 30;
const CONCENTRATION_MONITOR_INTERVAL_MS: u64 = 100;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, default_value = "rulesets/default.yaml")]
    config: PathBuf,
    #[arg(long)]
    scenarios_dir: Option<PathBuf>,
    #[arg(long)]
    scenario: Vec<PathBuf>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    serve: bool,
    #[arg(long, default_value = "127.0.0.1:9090")]
    bind: String,
}

fn response_kind(value: &swarm_spine::AuditResponseRecord) -> &'static str {
    match value {
        swarm_spine::AuditResponseRecord::Success(_) => "success",
        swarm_spine::AuditResponseRecord::Failure(_) => "failure",
        swarm_spine::AuditResponseRecord::Skipped { .. } => "skipped",
        swarm_spine::AuditResponseRecord::GuardRejected { .. } => "guard_rejected",
    }
}

#[derive(Debug, Clone, Copy)]
enum ReloadTrigger {
    FileChange,
    SecretChange,
    Signal(&'static str),
}

struct RetargetableWatcher {
    path: PathBuf,
    stop_tx: tokio::sync::watch::Sender<bool>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl RetargetableWatcher {
    fn stop(self) {
        let _ = self.stop_tx.send(true);
        self.join_handle.abort();
    }
}

fn watch_paths_differ(current: Option<&PathBuf>, next: Option<&PathBuf>) -> bool {
    current != next
}

fn spawn_secret_reload_watcher(
    secret_dir: PathBuf,
    reload_tx: tokio::sync::mpsc::UnboundedSender<ReloadTrigger>,
    mut global_shutdown: tokio::sync::watch::Receiver<bool>,
) -> RetargetableWatcher {
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let watched_path = secret_dir.clone();
    let join_handle = tokio::spawn(async move {
        let callback_tx = reload_tx.clone();
        let mut watcher = match notify::recommended_watcher(
            move |result: Result<notify::Event, notify::Error>| match result {
                Ok(event)
                    if matches!(
                        event.kind,
                        EventKind::Create(_)
                            | EventKind::Modify(_)
                            | EventKind::Remove(_)
                            | EventKind::Any
                    ) =>
                {
                    let _ = callback_tx.send(ReloadTrigger::SecretChange);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "secret watcher error"
                    );
                }
            },
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    secret_dir = %watched_path.display(),
                    reason = %error,
                    "failed to create secret watcher"
                );
                return;
            }
        };

        if let Err(error) = watcher.watch(&watched_path, RecursiveMode::Recursive) {
            tracing::error!(
                module = module_path!(),
                secret_dir = %watched_path.display(),
                reason = %error,
                "failed to watch secret directory"
            );
            return;
        }

        loop {
            tokio::select! {
                changed = global_shutdown.changed() => {
                    if changed.is_err() || *global_shutdown.borrow() {
                        break;
                    }
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    RetargetableWatcher {
        path: secret_dir,
        stop_tx,
        join_handle,
    }
}

fn spawn_reload_tasks(
    state: IngestState,
    shutdown: tokio::sync::watch::Sender<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let config_path = state.config_path().to_path_buf();
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<ReloadTrigger>();
    let mut handles = Vec::new();

    let file_tx = reload_tx.clone();
    let watch_path = config_path.clone();
    let mut watcher_shutdown = shutdown.subscribe();
    handles.push(tokio::spawn(async move {
        let callback_tx = file_tx.clone();
        let mut watcher = match notify::recommended_watcher(
            move |result: Result<notify::Event, notify::Error>| match result {
                Ok(event)
                    if matches!(
                        event.kind,
                        EventKind::Create(_)
                            | EventKind::Modify(_)
                            | EventKind::Remove(_)
                            | EventKind::Any
                    ) =>
                {
                    let _ = callback_tx.send(ReloadTrigger::FileChange);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "config watcher error"
                    );
                }
            },
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    reason = %error,
                    "failed to create config watcher"
                );
                return;
            }
        };

        if let Err(error) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
            tracing::error!(
                module = module_path!(),
                config_path = %watch_path.display(),
                reason = %error,
                "failed to watch config file"
            );
            return;
        }

        let _ = watcher_shutdown.changed().await;
    }));

    #[cfg(unix)]
    {
        let sighup_tx = reload_tx.clone();
        let mut sighup_shutdown = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(mut sighup) => loop {
                    tokio::select! {
                        _ = sighup_shutdown.changed() => break,
                        signal = sighup.recv() => {
                            if signal.is_none() {
                                break;
                            }
                            let _ = sighup_tx.send(ReloadTrigger::Signal("SIGHUP"));
                        }
                    }
                },
                Err(error) => {
                    tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "failed to register SIGHUP handler"
                    );
                }
            }
        }));
    }

    let mut reload_shutdown = shutdown.subscribe();
    handles.push(tokio::spawn(async move {
        let mut secret_watcher = state
            .secret_dir_path()
            .map(|secret_dir| {
                spawn_secret_reload_watcher(secret_dir, reload_tx.clone(), shutdown.subscribe())
            });

        loop {
            tokio::select! {
                _ = reload_shutdown.changed() => break,
                trigger = reload_rx.recv() => {
                    let Some(trigger) = trigger else {
                        break;
                    };

                    // SecretChange triggers only secret re-resolution (no
                    // YAML re-parse). FileChange and Signal do a full reload.
                    match trigger {
                        ReloadTrigger::SecretChange => {
                            let reason = "secret file change";
                            match state.reload_secrets_only() {
                                Ok(()) => {
                                    tracing::info!(
                                        module = module_path!(),
                                        trigger = %reason,
                                        "reloaded secrets without full config reload"
                                    );
                                }
                                Err(error) => {
                                    tracing::error!(
                                        module = module_path!(),
                                        trigger = %reason,
                                        reason = %error,
                                        "secret reload failed"
                                    );
                                }
                            }
                            continue;
                        }
                        ReloadTrigger::FileChange | ReloadTrigger::Signal(_) => {}
                    }

                    let reason = match trigger {
                        ReloadTrigger::FileChange => {
                            let mut seen_file_events = 1usize;
                            let debounce_deadline =
                                tokio::time::Instant::now() + Duration::from_millis(RELOAD_DEBOUNCE_MS);
                            let sleep = tokio::time::sleep_until(debounce_deadline);
                            tokio::pin!(sleep);
                            loop {
                                tokio::select! {
                                    _ = &mut sleep => break format!(
                                        "config file change (coalesced {seen_file_events} events)"
                                    ),
                                    _ = reload_shutdown.changed() => return,
                                    next = reload_rx.recv() => match next {
                                        Some(ReloadTrigger::FileChange) => {
                                            seen_file_events = seen_file_events.saturating_add(1);
                                        }
                                        Some(ReloadTrigger::SecretChange) => {
                                            // Secret changed during config debounce — do a
                                            // full reload which also re-resolves secrets.
                                            break "config + secret file change".to_string();
                                        }
                                        Some(ReloadTrigger::Signal(reason)) => break reason.to_string(),
                                        None => return,
                                    }
                                }
                            }
                        }
                        ReloadTrigger::Signal(reason) => reason.to_string(),
                        ReloadTrigger::SecretChange => unreachable!("handled above"),
                    };

                    match state.reload_from_disk() {
                        Ok(()) => {
                            let next_secret_dir = state.secret_dir_path();
                            let current_secret_dir =
                                secret_watcher.as_ref().map(|watcher| &watcher.path);
                            if watch_paths_differ(current_secret_dir, next_secret_dir.as_ref()) {
                                if let Some(watcher) = secret_watcher.take() {
                                    watcher.stop();
                                }
                                secret_watcher = next_secret_dir.map(|secret_dir| {
                                    spawn_secret_reload_watcher(
                                        secret_dir,
                                        reload_tx.clone(),
                                        shutdown.subscribe(),
                                    )
                                });
                            }
                            tracing::info!(
                                module = module_path!(),
                                trigger = %reason,
                                "reloaded runtime config"
                            );
                        }
                        Err(error) => {
                            tracing::error!(
                                module = module_path!(),
                                trigger = %reason,
                                reason = %error,
                                "config reload failed"
                            );
                        }
                    }
                }
            }
        }

        if let Some(watcher) = secret_watcher {
            watcher.stop();
        }
    }));

    handles
}

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            tracing::error!(
                                module = module_path!(),
                                reason = %error,
                                "ctrl-c handler failed"
                            );
                        }
                        "SIGINT"
                    }
                    _ = sigterm.recv() => {
                        "SIGTERM"
                    }
                }
            }
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    reason = %error,
                    "failed to register SIGTERM handler"
                );
                if let Err(ctrl_c_error) = tokio::signal::ctrl_c().await {
                    tracing::error!(
                        module = module_path!(),
                        reason = %ctrl_c_error,
                        "ctrl-c handler failed"
                    );
                }
                "shutdown signal"
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(
                module = module_path!(),
                reason = %error,
                "ctrl-c handler failed"
            );
        }
        "shutdown signal"
    }
}

async fn wait_for_shutdown_request(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn await_reload_tasks(handles: Vec<tokio::task::JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.await;
    }
}

async fn await_background_task(name: &str, handle: tokio::task::JoinHandle<()>) {
    match tokio::time::timeout(Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT_SECS), handle).await {
        Ok(joined) => {
            let _ = joined;
        }
        Err(_) => {
            tracing::error!(
                module = module_path!(),
                task = name,
                timeout_secs = GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
                "background task shutdown timed out"
            );
        }
    }
}

async fn await_background_tasks(name: &str, handles: Vec<tokio::task::JoinHandle<()>>) {
    for (index, handle) in handles.into_iter().enumerate() {
        let task_name = format!("{name}[{index}]");
        await_background_task(task_name.as_str(), handle).await;
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "config": cli.config,
                "mode": config.runtime.mode,
                "strategy": config.detection.strategy,
                "serve": cli.serve,
                "bind": cli.bind,
            }))?
        );
    } else if cli.serve {
        println!(
            "swarm-detect serving config={} mode={:?} strategy={} bind={}",
            cli.config.display(),
            config.runtime.mode,
            config.detection.strategy,
            cli.bind
        );
    } else {
        let mut paths = if let Some(dir) = &cli.scenarios_dir {
            scenario_paths_in_dir(dir)?
        } else {
            Vec::new()
        };
        paths.extend(cli.scenario.iter().cloned());
        println!(
            "swarm-detect config={} mode={:?} strategy={} scenario_count={}",
            cli.config.display(),
            config.runtime.mode,
            config.detection.strategy,
            paths.len()
        );
    }

    if cli.serve {
        let state = IngestState::from_config(cli.config.clone(), config.clone())?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (telemetry_tx, telemetry_rx) = tokio::sync::mpsc::channel(10_000);
        let agent_health = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let mode_state = Arc::new(arc_swap::ArcSwap::from_pointee(SwarmModeState::new()));
        let bridge_registry = BridgeRuntimeRegistry::from_config(&config)?;
        let bridge_health = bridge_registry.shared_health();
        let governance_policy = Arc::new(GovernancePolicy::default());
        let state = state
            .with_telemetry_channel(telemetry_tx.clone())
            .with_agent_health(Arc::clone(&agent_health))
            .with_bridge_health(bridge_health)
            .with_shutdown_channel(shutdown_tx.clone());
        let dispatcher_shutdown = shutdown_rx.clone();
        let monitor_shutdown = shutdown_rx.clone();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            dispatcher_shutdown,
            state.current_substrate(),
            Arc::clone(&agent_health),
        )
        .with_mode_state(Arc::clone(&mode_state))
        .with_request_response_router(state.current_request_response_router());
        if let Some(metrics) = state.current_prometheus_metrics() {
            dispatcher = dispatcher.with_metrics(metrics);
        }
        dispatcher
            .register(Box::new(WhiskerAgent::new(
                AgentId::new("whisker", "primary"),
                telemetry_rx,
                state.current_detector(),
                state.current_substrate(),
                state.current_pheromone_config(),
            )))
            .map_err(std::io::Error::other)?;
        dispatcher
            .register(Box::new(TomAgent::new(
                AgentId::new("tom", "primary"),
                config.runtime.governance_degraded_tick_threshold,
                Arc::clone(&governance_policy),
            )))
            .map_err(std::io::Error::other)?;
        dispatcher
            .register(Box::new(
                PounceAgent::new(
                    AgentId::new("pounce", "primary"),
                    state.current_pheromone_config().response_playbook.clone(),
                )
                .with_governance_policy(Arc::clone(&governance_policy)),
            ))
            .map_err(std::io::Error::other)?;
        if config.investigation.enabled {
            dispatcher
                .register(Box::new(StalkerAgent::new(
                    AgentId::new("stalker", "primary"),
                    state.current_replay_store(),
                    state.current_investigation(),
                    state.current_substrate(),
                    state.current_pheromone_config(),
                )))
                .map_err(std::io::Error::other)?;
        }
        if config.correlation.enabled {
            dispatcher
                .register(Box::new(WeaverAgent::new(
                    AgentId::new("weaver", "primary"),
                    state.current_correlation_engine(),
                    state.current_investigation_store(),
                    state.current_incident_store(),
                )))
                .map_err(std::io::Error::other)?;
        }
        let mut dispatcher_handle = Some(tokio::spawn(async move {
            dispatcher.run().await;
        }));
        let mut concentration_monitor = ConcentrationMonitor::new(
            state.current_pheromone_config(),
            Arc::new(state.current_substrate()),
        )
        .with_shared_mode_state(Arc::clone(&mode_state));
        let mut monitor_handle = Some(tokio::spawn(async move {
            concentration_monitor
                .run_until_shutdown(CONCENTRATION_MONITOR_INTERVAL_MS, monitor_shutdown)
                .await;
        }));
        let bridge_metrics = state.current_prometheus_metrics();
        let mut bridge_handles =
            Some(bridge_registry.spawn(telemetry_tx, shutdown_rx.clone(), bridge_metrics));
        let mut reload_handles = Some(spawn_reload_tasks(state.clone(), shutdown_tx.clone()));
        let listener = tokio::net::TcpListener::bind(&cli.bind).await?;
        let serve_state = state.clone();
        let server = axum::serve(listener, detect_http_router(serve_state))
            .with_graceful_shutdown(wait_for_shutdown_request(shutdown_rx))
            .into_future();
        tokio::pin!(server);

        tokio::select! {
            result = &mut server => {
                let _ = shutdown_tx.send(true);
                if let Some(handle) = dispatcher_handle.take() {
                    await_background_task("dispatcher", handle).await;
                }
                if let Some(handle) = monitor_handle.take() {
                    await_background_task("concentration_monitor", handle).await;
                }
                if let Some(handles) = bridge_handles.take() {
                    await_background_tasks("bridge", handles).await;
                }
                if let Some(handles) = reload_handles.take() {
                    await_reload_tasks(handles).await;
                }
                result?;
            }
            signal = wait_for_shutdown_signal() => {
                tracing::info!(
                    module = module_path!(),
                    signal,
                    "shutdown requested"
                );
                state.begin_drain();
                let drained = state.wait_for_drain().await;
                tracing::info!(
                    module = module_path!(),
                    signal,
                    drained,
                    active_requests = state.active_requests(),
                    drain_timeout_ms = state.drain_timeout().as_millis() as u64,
                    "serve-mode drain completed before shutdown"
                );
                let _ = shutdown_tx.send(true);
                match tokio::time::timeout(
                    Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT_SECS),
                    &mut server,
                )
                .await
                {
                    Ok(result) => result?,
                    Err(_) => {
                        tracing::error!(
                            module = module_path!(),
                            timeout_secs = GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
                            "graceful shutdown timed out; forcing exit"
                        );
                    }
                }
                if let Some(handle) = dispatcher_handle.take() {
                    await_background_task("dispatcher", handle).await;
                }
                if let Some(handle) = monitor_handle.take() {
                    await_background_task("concentration_monitor", handle).await;
                }
                if let Some(handles) = bridge_handles.take() {
                    await_background_tasks("bridge", handles).await;
                }
                if let Some(handles) = reload_handles.take() {
                    await_reload_tasks(handles).await;
                }
            }
        }
        tracing::info!(module = module_path!(), "shutdown complete");
        return Ok(());
    }

    let detector = build_composite_detector(&config.detection)?;
    let stack = ConfiguredRuntimeStack::from_config(config.clone(), SummaryInvestigator)?;
    let mut paths = if let Some(dir) = &cli.scenarios_dir {
        scenario_paths_in_dir(dir)?
    } else {
        Vec::new()
    };
    paths.extend(cli.scenario.iter().cloned());

    if paths.is_empty() {
        return Ok(());
    }

    let agent_id = AgentId("swarm-detect".to_string());
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let mut scenarios = 0usize;
    let mut events = 0usize;
    let mut findings = 0usize;
    let mut deposits = 0usize;

    for path in paths {
        let loaded = load_scenario_manifest(&path)?;
        let scenario_name = loaded.manifest.name.clone();
        let ReplayScenarioInput::Events {
            events: scenario_events,
        } = loaded.manifest.input.clone()
        else {
            return Err(format!(
                "scenario `{}` does not use event input",
                loaded.path.display()
            )
            .into());
        };
        let scenario_event_count = scenario_events.len();
        let mut scenario_findings = 0usize;
        let mut scenario_deposits = 0usize;
        for step in scenario_events {
            let approval = ApprovalContext {
                live_mode: matches!(
                    config.runtime.mode,
                    swarm_core::config::RuntimeMode::LiveResponse
                ),
                receipt_chain: Vec::new(),
                correlation_id: None,
                now_ms: step.event.timestamp,
            };
            let outcome = stack
                .process_event(
                    &detector,
                    &step.event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &approval,
                        signing_key: &signing_key,
                    },
                    |_| Some(step.action.clone()),
                )
                .await?;
            events += 1;
            match outcome {
                Some(bundle) => {
                    findings += bundle.replay.bundle.findings.len();
                    deposits += bundle.replay.bundle.deposits.len();
                    scenario_findings += bundle.replay.bundle.findings.len();
                    scenario_deposits += bundle.replay.bundle.deposits.len();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({
                                "scenario": scenario_name,
                                "event_id": bundle.replay.bundle.event.event_id,
                                "finding_count": bundle.replay.bundle.findings.len(),
                                "deposit_count": bundle.replay.bundle.deposits.len(),
                                "policy_verdict": bundle.replay.bundle.audit.policy.verdict,
                                "response_kind": response_kind(&bundle.replay.bundle.audit.response),
                            }))?
                        );
                    } else {
                        println!(
                            "{} {} findings={} deposits={} policy={:?} response={}",
                            scenario_name,
                            bundle.replay.bundle.event.event_id,
                            bundle.replay.bundle.findings.len(),
                            bundle.replay.bundle.deposits.len(),
                            bundle.replay.bundle.audit.policy.verdict,
                            response_kind(&bundle.replay.bundle.audit.response)
                        );
                    }
                }
                None if !cli.json => {
                    println!(
                        "{} {} findings=0 deposits=0",
                        scenario_name, step.event.event_id
                    )
                }
                None => println!(
                    "{}",
                    serde_json::to_string(
                        &json!({"scenario": scenario_name, "event_id": step.event.event_id, "finding_count": 0, "deposit_count": 0, "policy_verdict": null, "response_kind": null})
                    )?
                ),
            }
        }
        scenarios += 1;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"scenario": scenario_name, "total_events": scenario_event_count, "total_findings": scenario_findings, "total_deposits": scenario_deposits})
                )?
            );
        } else {
            println!(
                "scenario={} total_events={} total_findings={} total_deposits={}",
                scenario_name, scenario_event_count, scenario_findings, scenario_deposits
            );
        }
    }

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"scenarios_processed": scenarios, "total_events": events, "total_findings": findings, "total_deposits": deposits})
            )?
        );
    } else {
        println!(
            "summary scenarios_processed={} total_events={} total_findings={} total_deposits={}",
            scenarios, events, findings, deposits
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::watch_paths_differ;
    use std::path::PathBuf;

    #[test]
    fn watch_paths_differ_detects_secret_dir_retargets() {
        let left = Some(PathBuf::from("/tmp/a"));
        let right = Some(PathBuf::from("/tmp/b"));

        assert!(watch_paths_differ(left.as_ref(), right.as_ref()));
        assert!(watch_paths_differ(left.as_ref(), None));
        assert!(!watch_paths_differ(left.as_ref(), left.as_ref()));
        assert!(!watch_paths_differ(None, None));
    }
}

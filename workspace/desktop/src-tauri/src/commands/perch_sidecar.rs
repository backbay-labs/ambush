//! Local process control for the laptop demo's `swarm_detect`.
//!
//! These three commands are NOT on the INV-01 write table and do not belong
//! there. INV-01 is a claim about the set of non-GET requests this process can
//! issue to a daemon HOST; starting a daemon on this machine issues none.
//!
//! What they do carry is a different risk, and it is handled here: the config
//! path comes from the renderer, and a path the renderer chose freely would
//! let a compromised webview start the daemon under a ruleset of its own. Every
//! path is resolved and required to live under the app data directory or the
//! bundled rulesets before anything is spawned.

use std::path::{Path, PathBuf};

use tauri::Manager as _;

use crate::app_state::AppState;
use crate::perch_sidecar::{SeedsPresent, SidecarProfile, SidecarStatus};

/// Where a sidecar config may live.
///
/// Two roots, both owned by this app. A path outside them is refused rather
/// than sanitised: there is no legitimate reason to start the daemon under a
/// ruleset the app did not ship or write, and a "cleaned" path that still
/// resolves somewhere unexpected is the shape of every path-traversal bug.
fn resolve_profile_path(app: &tauri::AppHandle, requested: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(requested);
    if candidate.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err("the config path must be relative and must not climb".to_string());
    }
    let roots = [
        app.path()
            .app_data_dir()
            .map_err(|e| e.to_string())?
            .join("perch"),
        app.path()
            .resource_dir()
            .map_err(|e| e.to_string())?
            .join("rulesets"),
    ];
    for root in roots {
        let joined = root.join(candidate);
        if joined.exists() {
            return Ok(joined);
        }
    }
    Err(format!(
        "no config named {requested} under the app data directory or the bundled rulesets"
    ))
}

/// Keyring entry names. Distinct from the console's own daemon credentials:
/// the sidecar's seeds are what a LOCAL daemon signs with, and reusing the
/// console's bearer for them would tie a read credential to a signing one.
const NOSTR_SEED_KEY: &str = "perch.sidecar_nostr_seed";
const SPINE_SEED_KEY: &str = "perch.sidecar_spine_seed";
const OPERATOR_TOKEN_KEY: &str = "perch.sidecar_operator_token";

fn keyring_value(key: &str) -> Option<String> {
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    match store.load(key) {
        Ok(Some(value)) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// Read the two seeds and the bearer from the keyring into the child's
/// environment.
///
/// The VALUES never leave this process. They go straight from the keyring into
/// the spawned child's environment, and the only thing that crosses IPC is
/// whether each is present (INV-22).
fn sidecar_env() -> (Vec<(String, String)>, SeedsPresent) {
    let mut env = Vec::new();
    let nostr = keyring_value(NOSTR_SEED_KEY);
    let spine = keyring_value(SPINE_SEED_KEY);
    if let Some(value) = &nostr {
        env.push(("PERCH_BRIDGE_NOSTR_SEED".to_string(), value.clone()));
    }
    if let Some(value) = &spine {
        env.push(("PERCH_BRIDGE_SPINE_SEED".to_string(), value.clone()));
    }
    if let Some(value) = keyring_value(OPERATOR_TOKEN_KEY) {
        env.push(("SWARM_OPERATOR_TOKEN".to_string(), value));
    }
    (
        env,
        SeedsPresent {
            nostr: nostr.is_some(),
            spine: spine.is_some(),
        },
    )
}

#[tauri::command]
pub async fn perch_sidecar_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    config_path: String,
) -> Result<SidecarStatus, String> {
    let resolved = resolve_profile_path(&app, &config_path)?;
    let binary = app
        .path()
        .resolve(
            "binaries/swarm_detect",
            tauri::path::BaseDirectory::Resource,
        )
        .map_err(|_| "the swarm_detect sidecar is not bundled in this build".to_string())?;
    if !binary.exists() {
        return Err("the swarm_detect sidecar is not bundled in this build".to_string());
    }
    let (env, seeds_present) = sidecar_env();
    let profile = SidecarProfile {
        config_path: resolved,
        env,
        ..SidecarProfile::default()
    };
    let status = state
        .perch_sidecar
        .start_at(&binary, &profile, seeds_present)?;
    // Readiness is asked of the daemon, not inferred from the process being
    // alive: a `swarm_detect` that started and then failed its startup
    // attestation is a live process that will never serve.
    std::sync::Arc::clone(&state.perch_sidecar)
        .spawn_health_poll(profile.bind.clone(), state.http_client.clone());
    Ok(status)
}

#[tauri::command]
pub async fn perch_sidecar_stop(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.perch_sidecar.stop()
}

#[tauri::command]
pub async fn perch_sidecar_status(
    state: tauri::State<'_, AppState>,
) -> Result<Option<SidecarStatus>, String> {
    // `None` rather than a synthesised `Stopped`: never started and
    // started-then-stopped are different, and the panel renders them
    // differently.
    Ok(state.perch_sidecar.status())
}

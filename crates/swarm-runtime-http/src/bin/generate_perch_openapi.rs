//! Emit the gated Perch operator OpenAPI artifact from its authoring source.
//!
//! `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml` is the
//! human-authored contract; `docs/openapi/perch-operator-v1.json` is what
//! `tools/check-perch-openapi.sh` gates, byte for byte, against this binary
//! (12-BACKEND-BILL-API.md §14). Rendering is the serializer the platform
//! generator uses — `serde_json::to_string_pretty` plus a trailing newline —
//! so the two gates fail the same way.
//!
//! The document is also checked against the code before it is written: the
//! paths it documents must be exactly the paths `PERCH_ROUTER_PATHS` mounts.
//! A route added without its contract, or a contract for a route that is not
//! mounted, fails here rather than shipping.

use anyhow::{Context, bail};
use clap::Parser;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use swarm_runtime_http::http::perch::PERCH_ROUTER_PATHS;

#[derive(Debug, Parser)]
#[command(
    name = "generate_perch_openapi",
    about = "Render docs/openapi/perch-operator-v1.json from its authoring YAML, checked against the mounted routes"
)]
struct Args {
    /// The authoring YAML.
    #[arg(
        long,
        default_value = "docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml",
        value_name = "PATH"
    )]
    source: PathBuf,
    /// Output path for the generated spec.
    #[arg(
        long,
        default_value = "docs/openapi/perch-operator-v1.json",
        value_name = "PATH"
    )]
    output: PathBuf,
    /// Print the generated spec to stdout instead of writing it to disk.
    #[arg(long)]
    stdout: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let source = fs::read_to_string(&args.source)
        .with_context(|| format!("read authoring source {}", args.source.display()))?;
    let spec: Value = serde_yaml::from_str(&source)
        .with_context(|| format!("parse {} as YAML", args.source.display()))?;
    check_against_router(&spec)?;
    let rendered = serde_json::to_string_pretty(&spec).context("serialize perch OpenAPI")?;
    if args.stdout {
        println!("{rendered}");
        return Ok(());
    }
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    fs::write(&args.output, format!("{rendered}\n"))
        .with_context(|| format!("write {}", args.output.display()))?;
    Ok(())
}

/// The document's paths and the router's paths must be the same set.
fn check_against_router(spec: &Value) -> anyhow::Result<()> {
    let version = spec["openapi"].as_str().unwrap_or_default();
    if !version.starts_with("3.1") {
        bail!("authoring source declares openapi {version:?}; the gate validates 3.1");
    }
    let documented: BTreeSet<&str> = spec["paths"]
        .as_object()
        .context("authoring source has no `paths` object")?
        .keys()
        .map(String::as_str)
        .collect();
    let mounted: BTreeSet<&str> = PERCH_ROUTER_PATHS.iter().copied().collect();
    let undocumented: Vec<&str> = mounted.difference(&documented).copied().collect();
    let unmounted: Vec<&str> = documented.difference(&mounted).copied().collect();
    if !undocumented.is_empty() || !unmounted.is_empty() {
        bail!(
            "the contract and PERCH_ROUTER_PATHS disagree — mounted but undocumented: {undocumented:?}; documented but not mounted: {unmounted:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn spec_with_paths(paths: &[&str]) -> Value {
        let mut map = serde_json::Map::new();
        for path in paths {
            map.insert((*path).to_string(), serde_json::json!({}));
        }
        serde_json::json!({"openapi": "3.1.0", "paths": map})
    }

    #[test]
    fn the_router_paths_pass_and_a_drift_in_either_direction_fails() {
        assert!(check_against_router(&spec_with_paths(&PERCH_ROUTER_PATHS)).is_ok());
        let mut fewer: Vec<&str> = PERCH_ROUTER_PATHS.to_vec();
        fewer.pop();
        let err = check_against_router(&spec_with_paths(&fewer)).expect_err("a missing path fails");
        assert!(
            err.to_string().contains("mounted but undocumented"),
            "{err}"
        );
        let mut more: Vec<&str> = PERCH_ROUTER_PATHS.to_vec();
        more.push("/v1/operator/not-a-route");
        let err = check_against_router(&spec_with_paths(&more)).expect_err("an extra path fails");
        assert!(
            err.to_string().contains("documented but not mounted"),
            "{err}"
        );
    }

    #[test]
    fn a_non_3_1_document_is_refused() {
        let spec = serde_json::json!({"openapi": "3.0.3", "paths": {}});
        assert!(check_against_router(&spec).is_err());
    }
}

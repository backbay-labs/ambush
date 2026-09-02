#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use anyhow::Context;
use clap::Parser;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use swarm_ingest_runtime::control::{
    CURRENT_OPERATOR_API_SCHEMA_VERSION, OPERATOR_API_SCHEMA_VERSION_HEADER,
};

#[derive(Debug, Parser)]
#[command(
    name = "generate_platform_openapi",
    about = "Generate the OpenAPI 3.1 spec for the /v2/api platform surface"
)]
struct Args {
    /// Output path for the generated spec.
    #[arg(
        long,
        default_value = "docs/openapi/v2-platform-openapi.json",
        value_name = "PATH"
    )]
    output: PathBuf,

    /// Print the generated spec to stdout instead of writing it to disk.
    #[arg(long)]
    stdout: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let spec = build_platform_openapi_spec();
    let rendered = serde_json::to_string_pretty(&spec).context("serialize platform OpenAPI")?;

    if args.stdout {
        println!("{rendered}");
        return Ok(());
    }

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create parent directory for generated platform OpenAPI `{}`",
                args.output.display()
            )
        })?;
    }
    fs::write(&args.output, rendered + "\n").with_context(|| {
        format!(
            "write generated platform OpenAPI to `{}`",
            args.output.display()
        )
    })?;
    eprintln!("wrote {}", args.output.display());
    Ok(())
}

fn build_platform_openapi_spec() -> Value {
    json!({
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base",
        "info": {
            "title": "Swarm Team Six Platform API",
            "version": format!("v2-schema-{CURRENT_OPERATOR_API_SCHEMA_VERSION}"),
            "summary": "Authenticated read surface for findings, incidents, collective hypotheses, runtime status, posture, and evasion coverage.",
            "description": "Machine-readable contract for the shipped `/v2/api/*` read surface on the detect server. Requests require both an operator bearer token and a platform API key unless a scoped Providence context token is used on the supported read routes."
        },
        "servers": [
            {
                "url": "http://127.0.0.1:9090",
                "description": "Local detect-server default"
            }
        ],
        "security": [
            {
                "bearerAuth": [],
                "platformApiKey": []
            }
        ],
        "paths": {
            "/v2/api/findings": {
                "get": {
                    "tags": ["platform"],
                    "summary": "List findings",
                    "operationId": "list_findings",
                    "description": "Returns cursor-paginated finding summaries from the replay-backed platform surface.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/Cursor" },
                        { "$ref": "#/components/parameters/PageSize" },
                        { "$ref": "#/components/parameters/HuntId" },
                        { "$ref": "#/components/parameters/FindingId" },
                        { "$ref": "#/components/parameters/StrategyId" },
                        { "$ref": "#/components/parameters/ThreatClass" },
                        { "$ref": "#/components/parameters/Severity" },
                        { "$ref": "#/components/parameters/HostId" },
                        { "$ref": "#/components/parameters/ContextToken" }
                    ],
                    "responses": standard_platform_responses("#/components/schemas/PlatformFindingsPage")
                }
            },
            "/v2/api/incidents": {
                "get": {
                    "tags": ["platform"],
                    "summary": "List incidents",
                    "operationId": "list_incidents",
                    "description": "Returns cursor-paginated correlated incident summaries from the incident store.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/Cursor" },
                        { "$ref": "#/components/parameters/PageSize" },
                        { "$ref": "#/components/parameters/IncidentId" },
                        { "$ref": "#/components/parameters/HuntId" },
                        { "$ref": "#/components/parameters/ReceiptId" },
                        { "$ref": "#/components/parameters/CorrelationKey" },
                        { "$ref": "#/components/parameters/ContextToken" }
                    ],
                    "responses": standard_platform_responses("#/components/schemas/PlatformIncidentsPage")
                }
            },
            "/v2/api/evasion/coverage": {
                "get": {
                    "tags": ["platform"],
                    "summary": "Read evasion coverage",
                    "operationId": "get_evasion_coverage",
                    "description": "Returns the repo-owned evasion coverage snapshot, optionally filtered to one detector family.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        {
                            "name": "detector",
                            "in": "query",
                            "required": false,
                            "description": "Optional detector family to filter from the coverage snapshot.",
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": standard_platform_responses("#/components/schemas/EvasionCoverageSnapshot")
                }
            },
            "/v2/api/assets/{host_id}/posture": {
                "get": {
                    "tags": ["platform"],
                    "summary": "Read asset posture",
                    "operationId": "get_asset_posture",
                    "description": "Returns threat concentration, active investigations, and recent findings for one host.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/HostIdPath" }
                    ],
                    "responses": standard_platform_responses("#/components/schemas/PlatformAssetPosturePage")
                }
            },
            "/v2/api/runtime/status": {
                "get": {
                    "tags": ["platform"],
                    "summary": "Read runtime status",
                    "operationId": "get_runtime_status",
                    "description": "Returns the current runtime mode, degradation, detector health, async-lane status, feedback rollups, and rate-limit state. Requires the bearer token plus x-api-key — Providence-scoped context tokens cannot read runtime status because the response includes bearer-token metadata.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" }
                    ],
                    "responses": standard_platform_responses("#/components/schemas/PlatformRuntimeStatusPage")
                }
            },
            "/v2/api/hypothesis-graphs": {
                "get": {
                    "tags": ["platform", "collective-reasoning"],
                    "summary": "List collective hypothesis graphs",
                    "operationId": "list_hypothesis_graphs",
                    "description": "Returns the enabled runtime graph summary. The collection is empty when collective reasoning is disabled.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/Cursor" },
                        { "$ref": "#/components/parameters/PageSize" }
                    ],
                    "responses": standard_platform_responses("#/components/schemas/HypothesisGraphSummariesPage")
                }
            },
            "/v2/api/hypothesis-graphs/{graph_id}": {
                "get": {
                    "tags": ["platform", "collective-reasoning"],
                    "summary": "Read a collective hypothesis graph",
                    "operationId": "get_hypothesis_graph",
                    "description": "Returns durable evidence, causal edges, competing hypotheses, task state, projected strategy memory, and graph metrics.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/GraphIdPath" }
                    ],
                    "responses": hypothesis_graph_responses("#/components/schemas/HypothesisGraphProjectionPage")
                }
            },
            "/v2/api/hypothesis-graphs/{graph_id}/tasks": {
                "get": {
                    "tags": ["platform", "collective-reasoning"],
                    "summary": "List durable graph tasks",
                    "operationId": "list_hypothesis_graph_tasks",
                    "description": "Returns the graph's bounded durable claim, lease, and terminal task records.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/GraphIdPath" },
                        { "$ref": "#/components/parameters/Cursor" },
                        { "$ref": "#/components/parameters/PageSize" }
                    ],
                    "responses": hypothesis_graph_responses("#/components/schemas/HypothesisGraphTasksPage")
                }
            },
            "/v2/api/hypothesis-graphs/{graph_id}/memory": {
                "get": {
                    "tags": ["platform", "collective-reasoning"],
                    "summary": "List projected strategy memory",
                    "operationId": "list_hypothesis_graph_memory",
                    "description": "Returns authenticated strategy-memory records projected only after their terminal graph publication committed.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/GraphIdPath" },
                        { "$ref": "#/components/parameters/Cursor" },
                        { "$ref": "#/components/parameters/PageSize" }
                    ],
                    "responses": hypothesis_graph_responses("#/components/schemas/HypothesisGraphMemoryPage")
                }
            },
            "/v2/api/stream/findings": {
                "get": {
                    "tags": ["platform"],
                    "summary": "Stream live findings",
                    "operationId": "stream_findings",
                    "description": "Streams live finding events as server-sent events. Generated clients should treat this as a raw text/event-stream response.",
                    "parameters": [
                        { "$ref": "#/components/parameters/SchemaVersionHeader" },
                        { "$ref": "#/components/parameters/HostId" },
                        { "$ref": "#/components/parameters/StrategyId" },
                        { "$ref": "#/components/parameters/ThreatClass" },
                        { "$ref": "#/components/parameters/Severity" }
                    ],
                    "responses": {
                        "200": {
                            "description": "SSE stream of Swarm finding envelopes.",
                            "content": {
                                "text/event-stream": {
                                    "schema": { "type": "string" }
                                }
                            }
                        },
                        "400": error_response("Bad request"),
                        "401": error_response("Missing or invalid authentication"),
                        "403": error_response("Authenticated principal lacks required scope"),
                        "429": rate_limit_response(),
                        "503": error_response("Runtime event streaming is unavailable")
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "opaque"
                },
                "platformApiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "x-api-key"
                }
            },
            "parameters": {
                "SchemaVersionHeader": {
                    "name": OPERATOR_API_SCHEMA_VERSION_HEADER,
                    "in": "header",
                    "required": false,
                    "description": format!("Optional schema-version negotiation header. The current supported value is {CURRENT_OPERATOR_API_SCHEMA_VERSION}."),
                    "schema": {
                        "type": "integer",
                        "minimum": 1
                    }
                },
                "Cursor": query_parameter("cursor", "Opaque cursor returned by a previous list response.", json!({"type": "string"})),
                "PageSize": query_parameter("page_size", "Requested page size. Values above 200 are capped.", json!({"type": "integer", "minimum": 1, "maximum": 200})),
                "HuntId": query_parameter("hunt_id", "Optional hunt identifier filter.", json!({"type": "string"})),
                "FindingId": query_parameter("finding_id", "Optional finding identifier filter.", json!({"type": "string"})),
                "StrategyId": query_parameter("strategy_id", "Optional detector strategy filter.", json!({"type": "string"})),
                "ThreatClass": query_parameter("threat_class", "Optional threat-class filter.", json!({"type": "string"})),
                "Severity": query_parameter("severity", "Optional severity filter.", json!({"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]})),
                "HostId": query_parameter("host_id", "Optional host identifier filter.", json!({"type": "string"})),
                "IncidentId": query_parameter("incident_id", "Optional incident identifier filter.", json!({"type": "string"})),
                "ReceiptId": query_parameter("receipt_id", "Optional receipt identifier filter.", json!({"type": "string"})),
                "CorrelationKey": query_parameter("correlation_key", "Optional incident correlation-key filter.", json!({"type": "string"})),
                "ContextToken": query_parameter("context_token", "Optional Providence-scoped read token accepted on supported GET routes.", json!({"type": "string"})),
                "HostIdPath": {
                    "name": "host_id",
                    "in": "path",
                    "required": true,
                    "description": "Host identifier for the posture lookup.",
                    "schema": { "type": "string" }
                },
                "GraphIdPath": {
                    "name": "graph_id",
                    "in": "path",
                    "required": true,
                    "description": "Stable key-derived collective hypothesis graph identifier.",
                    "schema": { "type": "string", "minLength": 1 }
                }
            },
            "schemas": {
                "ErrorResponse": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "SwarmFindingEnvelope": {
                    "type": "object",
                    "required": ["schema", "finding_id", "event_id", "strategy_id", "threat_class", "severity", "confidence", "evidence"],
                    "properties": {
                        "schema": { "type": "string" },
                        "finding_id": { "type": "string" },
                        "event_id": { "type": "string" },
                        "strategy_id": { "type": "string" },
                        "threat_class": { "type": "string" },
                        "severity": { "type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
                        "confidence": { "type": "number" },
                        "evidence": {
                            "type": "object",
                            "description": "Strategy-specific evidence payload.",
                            "additionalProperties": true
                        }
                    },
                    "additionalProperties": false
                },
                "PlatformFindingSummary": {
                    "type": "object",
                    "required": ["bundle_id", "hunt_id", "trail_id", "created_at_ms", "response_kind", "related_receipt_ids", "finding"],
                    "properties": {
                        "bundle_id": { "type": "string" },
                        "hunt_id": { "type": "string" },
                        "trail_id": { "type": "string" },
                        "created_at_ms": { "type": "integer" },
                        "host_id": { "type": ["string", "null"] },
                        "response_kind": { "type": "string" },
                        "response_receipt_id": { "type": ["string", "null"] },
                        "related_receipt_ids": { "type": "array", "items": { "type": "string" } },
                        "latest_rehearsal_bundle_id": { "type": ["string", "null"] },
                        "latest_rehearsal": generic_object("Latest rehearsal preview for the hunt."),
                        "related_incident_id": { "type": ["string", "null"] },
                        "related_incident_summary": { "type": ["string", "null"] },
                        "related_incident_providence_reconciliation": generic_object("Latest Providence reconciliation state for the related incident."),
                        "finding": { "$ref": "#/components/schemas/SwarmFindingEnvelope" }
                    },
                    "additionalProperties": false
                },
                "PlatformFindingsPage": platform_page_schema("PlatformFindingSummary"),
                "PlatformIncidentSummary": {
                    "type": "object",
                    "required": ["incident_id", "summary", "created_at_ms", "included_hunt_ids", "included_investigation_ids", "related_receipt_ids", "correlation_keys"],
                    "properties": {
                        "incident_id": { "type": "string" },
                        "summary": { "type": "string" },
                        "created_at_ms": { "type": "integer" },
                        "included_hunt_ids": { "type": "array", "items": { "type": "string" } },
                        "included_investigation_ids": { "type": "array", "items": { "type": "string" } },
                        "related_receipt_ids": { "type": "array", "items": { "type": "string" } },
                        "correlation_keys": { "type": "array", "items": { "type": "string" } },
                        "providence_reconciliation": generic_object("Providence reconciliation state for the incident."),
                        "latest_rehearsal_hunt_id": { "type": "string" },
                        "latest_rehearsal_bundle_id": { "type": "string" },
                        "latest_rehearsal": generic_object("Latest rehearsal preview linked to the incident.")
                    },
                    "additionalProperties": false
                },
                "PlatformIncidentsPage": platform_page_schema("PlatformIncidentSummary"),
                "PlatformDetectorStatus": {
                    "type": "object",
                    "required": ["ready", "strategy", "details"],
                    "properties": {
                        "ready": { "type": "boolean" },
                        "strategy": { "type": "string" },
                        "details": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "PlatformLifecycleStatus": {
                    "type": "object",
                    "required": ["draining", "active_requests"],
                    "properties": {
                        "draining": { "type": "boolean" },
                        "active_requests": { "type": "integer", "minimum": 0 }
                    },
                    "additionalProperties": false
                },
                "PlatformThreatConcentrationSummary": {
                    "type": "object",
                    "required": ["threat_class", "total_strength", "distinct_sources", "peak_confidence"],
                    "properties": {
                        "threat_class": { "type": "string" },
                        "total_strength": { "type": "number" },
                        "distinct_sources": { "type": "integer", "minimum": 0 },
                        "peak_confidence": { "type": "number" }
                    },
                    "additionalProperties": false
                },
                "PlatformInvestigationSummary": {
                    "type": "object",
                    "required": ["investigation_id", "hunt_id", "finding_id", "status", "queued_at_ms", "last_updated_ms", "response_kind", "correlation_keys"],
                    "properties": {
                        "investigation_id": { "type": "string" },
                        "hunt_id": { "type": "string" },
                        "finding_id": { "type": "string" },
                        "status": { "type": "string" },
                        "queued_at_ms": { "type": "integer" },
                        "last_updated_ms": { "type": "integer" },
                        "response_kind": { "type": "string" },
                        "correlation_keys": { "type": "array", "items": { "type": "string" } },
                        "summary_preview": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "PlatformAssetPosture": {
                    "type": "object",
                    "required": ["host_id", "captured_at_ms", "escalation_level", "threat_concentrations", "active_investigations", "recent_findings"],
                    "properties": {
                        "host_id": { "type": "string" },
                        "captured_at_ms": { "type": "integer" },
                        "escalation_level": { "type": "string", "enum": ["normal", "alert", "incident"] },
                        "threat_concentrations": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/PlatformThreatConcentrationSummary" }
                        },
                        "active_investigations": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/PlatformInvestigationSummary" }
                        },
                        "recent_findings": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/PlatformFindingSummary" }
                        }
                    },
                    "additionalProperties": false
                },
                "PlatformAssetPosturePage": platform_page_schema("PlatformAssetPosture"),
                "PlatformRuntimeStatus": {
                    "type": "object",
                    "required": ["captured_at_ms", "mode_state", "degradation", "agent_health", "detector", "lifecycle", "anti_tamper", "async_lane", "false_positive_tracking", "alert_tuning", "bearer_tokens", "rate_limit"],
                    "properties": {
                        "captured_at_ms": { "type": "integer" },
                        "mode_state": generic_object("Current swarm mode and last transition metadata."),
                        "degradation": generic_object("Current runtime degradation state and capabilities."),
                        "agent_health": {
                            "type": "array",
                            "items": generic_object_schema("Registered agent health summary.")
                        },
                        "detector": { "$ref": "#/components/schemas/PlatformDetectorStatus" },
                        "lifecycle": { "$ref": "#/components/schemas/PlatformLifecycleStatus" },
                        "anti_tamper": generic_object("Current anti-tamper status report."),
                        "async_lane": generic_object("Async investigation and correlation lane status."),
                        "false_positive_tracking": generic_object("Aggregate analyst false-positive tracking report."),
                        "alert_tuning": generic_object("Aggregate alert-tuning recommendation report."),
                        "bearer_tokens": {
                            "type": "array",
                            "items": generic_object_schema("Configured operator bearer-token status.")
                        },
                        "rate_limit": generic_object("Per-source platform API rate-limit status."),
                        "bridge_health": { "$ref": "#/components/schemas/BridgeStatusReport" }
                    },
                    "additionalProperties": false
                },
                "PlatformRuntimeStatusPage": platform_page_schema("PlatformRuntimeStatus"),
                "GraphServiceMetrics": {
                    "type": "object",
                    "required": ["submissions", "submission_failures", "completed_acquisitions", "completed_challenges", "completed_falsifications", "falsification_no_findings", "memory_records_projected", "memory_projection_failures", "campaign_rotations"],
                    "properties": {
                        "submissions": { "type": "integer", "minimum": 0 },
                        "submission_failures": { "type": "integer", "minimum": 0 },
                        "completed_acquisitions": { "type": "integer", "minimum": 0 },
                        "completed_challenges": { "type": "integer", "minimum": 0 },
                        "completed_falsifications": { "type": "integer", "minimum": 0 },
                        "falsification_no_findings": { "type": "integer", "minimum": 0 },
                        "memory_records_projected": { "type": "integer", "minimum": 0 },
                        "memory_projection_failures": { "type": "integer", "minimum": 0 },
                        "campaign_rotations": { "type": "integer", "minimum": 0 }
                    },
                    "additionalProperties": false
                },
                "HypothesisGraphSummary": {
                    "type": "object",
                    "required": ["graph_id", "generation", "graph_version", "evidence_count", "node_count", "edge_count", "contradiction_count", "hypothesis_count", "pending_task_count", "completed_task_count", "memory_count", "logical_time_high_water", "metrics"],
                    "properties": {
                        "graph_id": { "type": "string" },
                        "generation": { "type": "integer", "minimum": 0 },
                        "graph_version": { "type": "integer", "minimum": 0 },
                        "evidence_count": { "type": "integer", "minimum": 0 },
                        "node_count": { "type": "integer", "minimum": 0 },
                        "edge_count": { "type": "integer", "minimum": 0 },
                        "contradiction_count": { "type": "integer", "minimum": 0 },
                        "hypothesis_count": { "type": "integer", "minimum": 0 },
                        "pending_task_count": { "type": "integer", "minimum": 0 },
                        "completed_task_count": { "type": "integer", "minimum": 0 },
                        "memory_count": { "type": "integer", "minimum": 0 },
                        "logical_time_high_water": { "type": "integer", "minimum": 0 },
                        "metrics": { "$ref": "#/components/schemas/GraphServiceMetrics" }
                    },
                    "additionalProperties": false
                },
                "HypothesisGraphProjection": {
                    "type": "object",
                    "required": ["graph_id", "generation", "digest", "graph", "hypotheses", "tasks", "terminal_publications", "memory", "logical_time_high_water", "metrics"],
                    "properties": {
                        "graph_id": { "type": "string" },
                        "generation": { "type": "integer", "minimum": 0 },
                        "digest": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "graph": generic_object("Typed durable causal graph including evidence and signed edges."),
                        "hypotheses": {
                            "type": "object",
                            "description": "Competing hypothesis records keyed by hypothesis ID.",
                            "additionalProperties": generic_object_schema("Typed hypothesis record.")
                        },
                        "tasks": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/HypothesisTaskRecord" }
                        },
                        "terminal_publications": { "type": "integer", "minimum": 0 },
                        "memory": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/StrategyMemoryRecord" }
                        },
                        "logical_time_high_water": { "type": "integer", "minimum": 0 },
                        "metrics": { "$ref": "#/components/schemas/GraphServiceMetrics" }
                    },
                    "additionalProperties": false
                },
                "HypothesisTaskRecord": generic_object_schema("Typed durable graph task with claim, lease, completion, and terminal history."),
                "StrategyMemoryRecord": generic_object_schema("Authenticated strategy-memory record projected from the committed terminal outbox."),
                "HypothesisGraphSummariesPage": platform_page_schema("HypothesisGraphSummary"),
                "HypothesisGraphProjectionPage": platform_page_schema("HypothesisGraphProjection"),
                "HypothesisGraphTasksPage": platform_page_schema("HypothesisTaskRecord"),
                "HypothesisGraphMemoryPage": platform_page_schema("StrategyMemoryRecord"),
                "EvasionThreatClassCoverage": {
                    "type": "object",
                    "required": ["threat_class", "total_payloads", "detected_payloads", "catch_rate", "scenario_count", "techniques"],
                    "properties": {
                        "threat_class": { "type": "string" },
                        "total_payloads": { "type": "integer", "minimum": 0 },
                        "detected_payloads": { "type": "integer", "minimum": 0 },
                        "catch_rate": { "type": "number" },
                        "scenario_count": { "type": "integer", "minimum": 0 },
                        "techniques": { "type": "array", "items": { "type": "string" } }
                    },
                    "additionalProperties": false
                },
                "DetectorEvasionCoverageReport": {
                    "type": "object",
                    "required": ["detector", "total_payloads", "detected_payloads", "catch_rate", "threat_classes", "intentionally_uncovered"],
                    "properties": {
                        "detector": { "type": "string" },
                        "total_payloads": { "type": "integer", "minimum": 0 },
                        "detected_payloads": { "type": "integer", "minimum": 0 },
                        "catch_rate": { "type": "number" },
                        "threat_classes": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/EvasionThreatClassCoverage" }
                        },
                        "intentionally_uncovered": {
                            "type": "array",
                            "items": generic_object_schema("Repo-declared intentional evasion gap.")
                        }
                    },
                    "additionalProperties": false
                },
                "EvasionCoverageSnapshot": {
                    "type": "object",
                    "required": ["generated_at_ms", "suite_name", "suite_path", "corpus_version", "detectors"],
                    "properties": {
                        "generated_at_ms": { "type": "integer" },
                        "suite_name": { "type": "string" },
                        "suite_path": { "type": "string" },
                        "corpus_version": { "type": "string" },
                        "detectors": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/DetectorEvasionCoverageReport" }
                        }
                    },
                    "additionalProperties": false
                },
                "BridgeStatusSnapshot": {
                    "type": "object",
                    "required": ["name", "source_id", "ready", "events_processed", "error_count"],
                    "properties": {
                        "name": { "type": "string" },
                        "source_id": { "type": "string" },
                        "ready": { "type": "boolean" },
                        "events_processed": { "type": "integer", "minimum": 0 },
                        "error_count": { "type": "integer", "minimum": 0 },
                        "lag_seconds": { "type": ["number", "null"] },
                        "last_error": { "type": ["string", "null"] }
                    },
                    "additionalProperties": false
                },
                "BridgeStatusReport": {
                    "type": "object",
                    "required": ["configured", "ok", "degraded", "idle", "entries"],
                    "properties": {
                        "configured": { "type": "integer", "minimum": 0 },
                        "ok": { "type": "integer", "minimum": 0 },
                        "degraded": { "type": "integer", "minimum": 0 },
                        "idle": { "type": "integer", "minimum": 0 },
                        "entries": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/BridgeStatusSnapshot" }
                        }
                    },
                    "additionalProperties": false
                }
            }
        }
    })
}

fn query_parameter(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": schema
    })
}

fn standard_platform_responses(schema_ref: &str) -> Value {
    json!({
        "200": {
            "description": "Successful response.",
            "content": {
                "application/json": {
                    "schema": { "$ref": schema_ref }
                }
            }
        },
        "400": error_response("Bad request"),
        "401": error_response("Missing or invalid authentication"),
        "403": error_response("Authenticated principal lacks required scope"),
        "429": rate_limit_response(),
        "503": error_response("Requested platform API surface is unavailable")
    })
}

fn hypothesis_graph_responses(schema_ref: &str) -> Value {
    let mut responses = standard_platform_responses(schema_ref);
    responses["404"] = error_response(
        "Collective hypothesis graph is disabled or the requested graph ID does not exist",
    );
    responses
}

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" }
            }
        }
    })
}

fn rate_limit_response() -> Value {
    let mut response = error_response("Rate limit exceeded");
    response["headers"] = json!({
        "Retry-After": {
            "description": "Seconds to wait before retrying the request.",
            "schema": { "type": "integer", "minimum": 1 }
        }
    });
    response
}

fn platform_page_schema(item_schema: &str) -> Value {
    json!({
        "type": "object",
        "required": ["schema_version", "data"],
        "properties": {
            "schema_version": {
                "type": "integer",
                "minimum": 1,
                "default": CURRENT_OPERATOR_API_SCHEMA_VERSION
            },
            "data": {
                "type": "array",
                "items": {
                    "$ref": format!("#/components/schemas/{item_schema}")
                }
            },
            "cursor": {
                "type": ["string", "null"],
                "description": "Opaque cursor for the next page; null on the final page."
            }
        },
        "additionalProperties": false
    })
}

fn generic_object(description: &str) -> Value {
    let mut schema = generic_object_schema(description);
    schema["description"] = json!(description);
    schema
}

fn generic_object_schema(description: &str) -> Value {
    json!({
        "type": "object",
        "description": description,
        "additionalProperties": true
    })
}

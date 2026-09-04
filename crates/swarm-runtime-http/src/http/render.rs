use super::helpers::ReviewEvidenceVerificationFilter;
use swarm_core::types::{
    ProvidenceIncidentStatus, ProvidenceReconciliationOutcome, ResponseRehearsalPreview,
};
use swarm_evolution::evidence::{EvidenceSubjectKind, PromotionEvidenceRecommendation};
use swarm_evolution::operator_maintenance::OperatorMaintenanceStatus;

pub(super) fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn review_link(path: &str, label: &str) -> String {
    format!(
        "<a class=\"review-link\" href=\"{}\">{}</a>",
        escape_html(path),
        escape_html(label)
    )
}

pub(super) fn render_review_layout(title: &str, subtitle: &str, body: &str) -> String {
    let subtitle_html = if subtitle.is_empty() {
        String::new()
    } else {
        format!("<p class=\"subtitle\">{}</p>", escape_html(subtitle))
    };
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title}</title><style>{style}</style></head><body><main class=\"page\"><header class=\"hero\"><div><p class=\"eyebrow\">Ambush</p><h1>{heading}</h1>{subtitle}</div><nav class=\"nav\"><a href=\"/v1/operator/review\">Home</a><a href=\"/v1/operator/review/sessions\">Sessions</a><a href=\"/v1/operator/review/evidence\">Evidence</a><a href=\"/v1/operator/review/promotion-packets\">Promotion Packets</a></nav></header>{body}</main></body></html>",
        title = escape_html(title),
        heading = escape_html(title),
        subtitle = subtitle_html,
        body = body,
        style = concat!(
            ":root{color-scheme:light;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;}",
            "body{margin:0;background:#f4efe5;color:#1d2433;}",
            ".page{max-width:1120px;margin:0 auto;padding:24px 20px 56px;}",
            ".hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:24px;padding:20px 24px;border-radius:20px;background:linear-gradient(135deg,#fef7e5,#e7f1ff);border:1px solid #d7deeb;}",
            ".eyebrow{margin:0 0 6px;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#805b10;}",
            "h1{margin:0;font-size:32px;line-height:1.1;}",
            ".subtitle{margin:10px 0 0;max-width:70ch;color:#465066;}",
            ".nav{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;}",
            ".nav a,.review-link{color:#0f4f8a;text-decoration:none;font-weight:600;}",
            ".nav a{padding:10px 12px;border-radius:999px;background:#ffffffbf;border:1px solid #d3dceb;}",
            ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;}",
            ".card{background:#fff;border:1px solid #d7deeb;border-radius:18px;padding:18px;box-shadow:0 10px 25px rgba(29,36,51,.06);}",
            ".card h2,.card h3{margin-top:0;}",
            ".dashboard-shell{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr);gap:18px;margin-bottom:18px;}",
            ".dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:16px;}",
            ".metric-card{padding:16px;border-radius:16px;background:linear-gradient(160deg,#fff9ef,#eef5ff);border:1px solid #d7deeb;}",
            ".metric-card h3{margin:0 0 8px;font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#6a7282;}",
            ".kpi{font-size:28px;line-height:1.05;font-weight:800;letter-spacing:-.02em;}",
            ".status-row{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;}",
            ".status-banner{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;font-weight:700;font-size:12px;letter-spacing:.04em;text-transform:uppercase;}",
            ".status-banner.ok{background:#ddf8e8;color:#15643a;}",
            ".status-banner.warn{background:#fff1dc;color:#9a580a;}",
            ".status-banner.err{background:#fde1e1;color:#9c2331;}",
            ".status-dot{width:10px;height:10px;border-radius:999px;background:currentColor;}",
            ".health-list,.timeline-list{list-style:none;padding:0;margin:0;}",
            ".health-list{display:flex;flex-direction:column;gap:10px;}",
            ".health-item{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px 14px;border-radius:14px;border:1px solid #e0e6f0;background:#f8fafc;}",
            ".timeline-list{display:flex;flex-direction:column;gap:10px;max-height:420px;overflow:auto;padding-right:4px;}",
            ".timeline-item{padding:12px 14px;border-radius:14px;border:1px solid #dfe7f2;background:#f8fafc;border-left:4px solid #9fb2c8;}",
            ".timeline-item.escalation{background:#fff1ea;border-left-color:#c2410c;}",
            ".timeline-item.mode_transition{background:#edf4ff;border-left-color:#0f4f8a;}",
            ".timeline-item.agent_health{background:#eef4ff;border-left-color:#2563eb;}",
            ".timeline-item.response_execution{background:#f4f0ff;border-left-color:#7c3aed;}",
            ".timeline-item.ingest{background:#eefbf5;border-left-color:#15803d;}",
            ".timeline-title{display:flex;justify-content:space-between;gap:10px;align-items:baseline;margin-bottom:6px;}",
            ".timeline-title strong{font-size:14px;}",
            ".timeline-time{font-size:12px;color:#667085;white-space:nowrap;}",
            ".dashboard-empty{padding:14px;border:1px dashed #cbd5e1;border-radius:14px;background:#fbfdff;color:#667085;}",
            ".compact-table td,.compact-table th{padding:8px 6px;}",
            ".meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:16px 0;}",
            ".meta div{padding:12px 14px;border-radius:14px;background:#f7f9fc;border:1px solid #e0e6f0;}",
            ".meta dt{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#6a7282;font-weight:700;}",
            ".meta dd{margin:6px 0 0;font-weight:600;word-break:break-word;}",
            ".pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;}",
            ".pill.passed,.pill.ready{background:#ddf8e8;color:#15643a;}",
            ".pill.failed,.pill.blocked{background:#fde1e1;color:#9c2331;}",
            ".pill.unverified{background:#eceff5;color:#495164;}",
            "table{width:100%;border-collapse:collapse;margin-top:10px;}",
            "th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #e7ebf3;vertical-align:top;}",
            "th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#6a7282;}",
            ".toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:18px 0;}",
            ".toolbar label{display:flex;flex-direction:column;gap:6px;font-size:14px;font-weight:600;color:#344054;}",
            ".toolbar input,.toolbar select,.toolbar textarea{min-width:180px;padding:10px 12px;border-radius:12px;border:1px solid #ccd5e3;background:#fff;}",
            ".toolbar button{padding:10px 16px;border-radius:12px;border:0;background:#0f4f8a;color:#fff;font-weight:700;cursor:pointer;}",
            "code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}",
            "pre{margin:0;white-space:pre-wrap;word-break:break-word;background:#141923;color:#eef3ff;padding:14px;border-radius:14px;}",
            "details{margin-top:14px;}",
            "ul{padding-left:20px;}",
            ".muted{color:#667085;}",
            "@media (max-width:980px){.dashboard-shell{grid-template-columns:1fr;}}",
            "@media (max-width:760px){.hero{flex-direction:column;}.nav{justify-content:flex-start;}}"
        )
    )
}

/// The operator home's live demo panel.
///
/// It reads the daemon's `/v1/demo/dashboard` and `/v1/events/stream` from the
/// operator's browser, cross-origin and with no credentials. B5
/// (13-PLAN-THE-HOLD.md Task 14) closed both: the daemon demands a
/// `context_token` on each and no longer answers the stream with a wildcard
/// `Access-Control-Allow-Origin`, so this panel renders its own disconnected
/// state against a post-B5 daemon. It was already `runtime.demo_mode`-only --
/// both handlers answer `403 demo mode is disabled` otherwise -- and a context
/// token always carries a scope, so the `agent_health` frames this panel asks
/// for could not be served under one in any case. Restoring it means giving the
/// operator surface a minted-token seam and a scope to mint against; that is
/// not part of the hold.
pub(super) fn render_demo_dashboard_panel(runtime_base_url: &str) -> String {
    let runtime_base_url_json =
        serde_json::to_string(runtime_base_url).unwrap_or_else(|_| "\"\"".to_string());
    let script = r#"<script>
(function () {
  const runtimeBaseUrl = __RUNTIME_BASE_URL__;
  const snapshotUrl = runtimeBaseUrl.replace(/\/$/, "") + "/v1/demo/dashboard";
  const streamUrl = runtimeBaseUrl.replace(/\/$/, "") + "/v1/events/stream?types=" + encodeURIComponent([
    "agent_health",
    "concentration_snapshot",
    "escalation",
    "mode_transition",
    "agent_action",
    "response_execution",
    "replay",
    "ingest"
  ].join(","));

  const connection = document.getElementById("dashboard-connection");
  const modeValue = document.getElementById("dashboard-mode");
  const modeDetail = document.getElementById("dashboard-mode-detail");
  const runtimeSource = document.getElementById("dashboard-runtime-source");
  const escalationsValue = document.getElementById("dashboard-escalation-count");
  const healthValue = document.getElementById("dashboard-health-count");
  const healthList = document.getElementById("dashboard-agent-health");
  const concentrationBody = document.getElementById("dashboard-concentrations");
  const timeline = document.getElementById("dashboard-timeline");

  let eventSource = null;
  let latestHealth = new Map();

  function setConnection(kind, label) {
    connection.className = "status-banner " + kind;
    connection.innerHTML = '<span class="status-dot"></span>' + label;
  }

  function titleCase(value) {
    return String(value || "")
      .split("_")
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");
  }

  function formatTime(epochMs) {
    if (!epochMs) {
      return "pending";
    }
    return new Date(epochMs).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  }

  function renderMode(modeState) {
    const mode = modeState && modeState.current ? modeState.current : "normal";
    modeValue.textContent = titleCase(mode);
    if (modeState && modeState.last_transition_at) {
      const transitionMs = modeState.last_transition_at * 1000;
      const threatClass = modeState.triggering_threat_class
        ? titleCase(modeState.triggering_threat_class)
        : "cooldown reset";
      modeDetail.textContent = "Last transition " + formatTime(transitionMs) + " via " + threatClass;
    } else {
      modeDetail.textContent = "No escalation recorded in this runtime session.";
    }
  }

  function renderHealth(entries) {
    latestHealth = new Map((entries || []).map((entry) => [entry.id, entry]));
    healthValue.textContent = String(entries.length);
    if (!entries.length) {
      healthList.innerHTML = '<li class="dashboard-empty">No registered agent health has been published yet.</li>';
      return;
    }
    healthList.innerHTML = entries.map((entry) => {
      const pillClass = entry.health === "healthy" ? "ready" : entry.health;
      return '<li class="health-item"><div><strong>' + entry.id + '</strong><div class="muted">' +
        titleCase(entry.role) + '</div></div><span class="pill ' + pillClass + '">' +
        titleCase(entry.health) + '</span></li>';
    }).join("");
  }

  function renderConcentrations(entries) {
    const rows = (entries || []).map((entry) => {
      return '<tr><td><strong>' + titleCase(entry.threat_class) + '</strong></td><td>' +
        Number(entry.total_strength || 0).toFixed(2) + '</td><td>' +
        String(entry.distinct_sources || 0) + '</td><td>' +
        Number(entry.peak_confidence || 0).toFixed(2) + '</td></tr>';
    }).join("");
    concentrationBody.innerHTML = rows || '<tr><td colspan="4" class="dashboard-empty">No concentration data available yet.</td></tr>';
  }

  function timelineItem(kind, title, detail, epochMs) {
    return '<li class="timeline-item ' + kind + '"><div class="timeline-title"><strong>' +
      title + '</strong><span class="timeline-time">' + formatTime(epochMs) +
      '</span></div><div class="muted">' + detail + '</div></li>';
  }

  function pushTimeline(kind, title, detail, epochMs) {
    const markup = timelineItem(kind, title, detail, epochMs);
    if (timeline.querySelector(".dashboard-empty")) {
      timeline.innerHTML = markup;
    } else {
      timeline.insertAdjacentHTML("afterbegin", markup);
    }
    while (timeline.children.length > 30) {
      timeline.removeChild(timeline.lastElementChild);
    }
  }

  function renderEscalationSeed(records) {
    if (!(records || []).length) {
      timeline.innerHTML = '<li class="dashboard-empty">Waiting for live runtime events.</li>';
      escalationsValue.textContent = "0";
      return;
    }
    escalationsValue.textContent = String(records.length);
    timeline.innerHTML = records.map((record) => {
      const detail = titleCase(record.threat_class) + " strength " +
        Number(record.total_strength || 0).toFixed(2) + " from " +
        String(record.distinct_sources || 0) + " sources";
      return timelineItem(
        "escalation",
        titleCase(record.mode) + " escalation",
        detail,
        (record.timestamp || 0) * 1000
      );
    }).join("");
  }

  function handleRuntimeEvent(event) {
    switch (event.event_type) {
      case "concentration_snapshot":
        renderConcentrations(event.concentrations || []);
        renderMode({ current: event.current_mode });
        break;
      case "agent_health": {
        const next = Array.from(latestHealth.values());
        const index = next.findIndex((entry) => entry.id === event.agent_id);
        const entry = { id: event.agent_id, role: event.role, health: event.to };
        if (index >= 0) {
          next[index] = entry;
        } else {
          next.push(entry);
        }
        renderHealth(next.sort((left, right) => left.id.localeCompare(right.id)));
        pushTimeline(
          "agent_health",
          event.agent_id + " health changed",
          titleCase(event.role) + " is now " + titleCase(event.to),
          event.emitted_at_ms
        );
        break;
      }
      case "escalation":
        pushTimeline(
          "escalation",
          titleCase(event.level) + " escalation",
          titleCase(event.threat_class) + " strength " + Number(event.total_strength || 0).toFixed(2) +
            " from " + String(event.distinct_sources || 0) + " sources",
          event.emitted_at_ms
        );
        break;
      case "mode_transition":
        renderMode({
          current: event.to
        });
        pushTimeline(
          "mode_transition",
          titleCase(event.from) + " → " + titleCase(event.to),
          event.reason || "mode transition",
          event.emitted_at_ms
        );
        break;
      case "response_execution":
        pushTimeline(
          "response_execution",
          titleCase(event.response_kind) + " response",
          event.agent_id + " · " + event.action_kind + " · " + titleCase(event.policy_verdict),
          event.emitted_at_ms
        );
        break;
      case "agent_action":
        pushTimeline(
          "agent_action",
          event.agent_id + " action",
          titleCase(event.action_kind),
          event.emitted_at_ms
        );
        break;
      case "ingest":
        pushTimeline(
          "ingest",
          event.accepted ? "Telemetry accepted" : "Telemetry rejected",
          event.event_id + " · " + event.source,
          event.emitted_at_ms
        );
        break;
      case "replay":
        if (event.phase === "step") {
          return;
        }
        pushTimeline(
          "replay",
          "Replay " + titleCase(event.phase),
          event.scenario_name + " · " + String(event.total_steps || 0) + " steps",
          event.emitted_at_ms
        );
        break;
      default:
        break;
    }
  }

  async function bootstrap() {
    runtimeSource.textContent = runtimeBaseUrl;
    setConnection("warn", "Connecting");
    try {
      const response = await fetch(snapshotUrl, { credentials: "omit" });
      if (!response.ok) {
        throw new Error("snapshot returned " + response.status);
      }
      const snapshot = await response.json();
      renderMode(snapshot.mode_state || { current: "normal" });
      renderHealth(snapshot.agent_health || []);
      renderConcentrations(snapshot.concentrations || []);
      renderEscalationSeed(snapshot.recent_escalations || []);
      setConnection("ok", "Live");
    } catch (error) {
      setConnection("err", "Snapshot Error");
      timeline.innerHTML = '<li class="dashboard-empty">Unable to load runtime snapshot: ' +
        String(error.message || error) + '</li>';
    }

    eventSource = new EventSource(streamUrl, { withCredentials: false });
    eventSource.onopen = function () {
      setConnection("ok", "Streaming");
    };
    eventSource.onerror = function () {
      setConnection("warn", "Reconnecting");
    };
    [
      "agent_health",
      "concentration_snapshot",
      "escalation",
      "mode_transition",
      "agent_action",
      "response_execution",
      "replay",
      "ingest"
    ].forEach((type) => {
      eventSource.addEventListener(type, function (message) {
        try {
          handleRuntimeEvent(JSON.parse(message.data));
        } catch (error) {
          setConnection("warn", "Stream Decode Error");
        }
      });
    });
  }

  bootstrap();
})();
</script>"#
        .replace("__RUNTIME_BASE_URL__", &runtime_base_url_json);

    format!(
        "<section class=\"dashboard-shell\">\
            <article class=\"card\">\
                <div class=\"status-row\">\
                    <div><h2>Live Demo Dashboard</h2><p class=\"muted\">Bootstrapped from the runtime snapshot endpoint and kept live from the typed runtime event stream.</p></div>\
                    <div id=\"dashboard-connection\" class=\"status-banner warn\"><span class=\"status-dot\"></span>Connecting</div>\
                </div>\
                <div class=\"dashboard-grid\">\
                    <div class=\"metric-card\"><h3>Swarm Mode</h3><div id=\"dashboard-mode\" class=\"kpi\">Loading</div><div id=\"dashboard-mode-detail\" class=\"muted\">Waiting for runtime snapshot.</div></div>\
                    <div class=\"metric-card\"><h3>Agents Visible</h3><div id=\"dashboard-health-count\" class=\"kpi\">0</div><div class=\"muted\">Per-agent health over the live runtime stream.</div></div>\
                    <div class=\"metric-card\"><h3>Escalations Seeded</h3><div id=\"dashboard-escalation-count\" class=\"kpi\">0</div><div class=\"muted\">Recent escalation records used to seed the timeline.</div></div>\
                    <div class=\"metric-card\"><h3>Runtime Source</h3><div id=\"dashboard-runtime-source\" class=\"kpi\" style=\"font-size:18px;word-break:break-word;\">{runtime_base_url}</div><div class=\"muted\">Repo-owned base URL for snapshot and SSE reads.</div></div>\
                </div>\
            </article>\
            <article class=\"card\">\
                <h2>Runtime Timeline</h2>\
                <p class=\"muted\">Escalations, mode shifts, and agent actions arrive here from the shared event backbone.</p>\
                <ol id=\"dashboard-timeline\" class=\"timeline-list\"><li class=\"dashboard-empty\">Waiting for live runtime events.</li></ol>\
            </article>\
        </section>\
        <section class=\"grid\" style=\"margin-bottom:18px;\">\
            <article class=\"card\"><h2>Agent Health</h2><ul id=\"dashboard-agent-health\" class=\"health-list\"><li class=\"dashboard-empty\">Waiting for agent health.</li></ul></article>\
            <article class=\"card\"><h2>Threat Concentrations</h2><table class=\"compact-table\"><thead><tr><th>Threat Class</th><th>Strength</th><th>Sources</th><th>Peak Confidence</th></tr></thead><tbody id=\"dashboard-concentrations\"><tr><td colspan=\"4\" class=\"dashboard-empty\">Waiting for concentration snapshots.</td></tr></tbody></table></article>\
        </section>{script}",
        runtime_base_url = escape_html(runtime_base_url),
        script = script
    )
}

pub(super) fn render_status_pill(label: &str, class_name: &str) -> String {
    format!(
        "<span class=\"pill {class_name}\">{label}</span>",
        class_name = escape_html(class_name),
        label = escape_html(label)
    )
}

pub(super) fn render_subject_kind_options(selected: Option<EvidenceSubjectKind>) -> String {
    let mut options = vec!["<option value=\"\">All subject kinds</option>".to_string()];
    for kind in [
        EvidenceSubjectKind::ReplayBundle,
        EvidenceSubjectKind::InvestigationBundle,
        EvidenceSubjectKind::CorrelatedIncident,
        EvidenceSubjectKind::CanaryRun,
        EvidenceSubjectKind::ProductionPromotion,
        EvidenceSubjectKind::OperatorMaintenanceAction,
        EvidenceSubjectKind::DetectorVerification,
        EvidenceSubjectKind::StrategyShadow,
        EvidenceSubjectKind::PromotionReview,
    ] {
        let selected_attr = if selected == Some(kind) {
            " selected"
        } else {
            ""
        };
        options.push(format!(
            "<option value=\"{value}\"{selected}>{value}</option>",
            value = kind.as_str(),
            selected = selected_attr
        ));
    }
    options.join("")
}

pub(super) fn render_verification_filter_options(
    selected: Option<ReviewEvidenceVerificationFilter>,
) -> String {
    let mut options = vec!["<option value=\"\">Any verification state</option>".to_string()];
    for filter in [
        ReviewEvidenceVerificationFilter::Passed,
        ReviewEvidenceVerificationFilter::Failed,
        ReviewEvidenceVerificationFilter::Unverified,
    ] {
        let selected_attr = if selected == Some(filter) {
            " selected"
        } else {
            ""
        };
        options.push(format!(
            "<option value=\"{value}\"{selected}>{label}</option>",
            value = filter.as_str(),
            selected = selected_attr,
            label = filter.label()
        ));
    }
    options.join("")
}

pub(super) fn render_promotion_recommendation_options(
    selected: Option<PromotionEvidenceRecommendation>,
) -> String {
    let mut options = vec!["<option value=\"\">Any recommendation</option>".to_string()];
    for recommendation in [
        PromotionEvidenceRecommendation::ReadyForExternalReview,
        PromotionEvidenceRecommendation::Blocked,
    ] {
        let selected_attr = if selected == Some(recommendation) {
            " selected"
        } else {
            ""
        };
        options.push(format!(
            "<option value=\"{value}\"{selected}>{value}</option>",
            value = recommendation.as_str(),
            selected = selected_attr
        ));
    }
    options.join("")
}

pub(super) fn render_maintenance_status_pill(status: OperatorMaintenanceStatus) -> String {
    let (label, class_name) = match status {
        OperatorMaintenanceStatus::Applied => ("applied", "passed"),
        OperatorMaintenanceStatus::Blocked => ("blocked", "blocked"),
        OperatorMaintenanceStatus::Failed => ("failed", "failed"),
    };
    render_status_pill(label, class_name)
}

pub(super) fn render_providence_incident_status(status: ProvidenceIncidentStatus) -> &'static str {
    match status {
        ProvidenceIncidentStatus::Open => "open",
        ProvidenceIncidentStatus::Investigating => "investigating",
        ProvidenceIncidentStatus::Resolved => "resolved",
    }
}

pub(super) fn render_providence_reconciliation_outcome(
    outcome: ProvidenceReconciliationOutcome,
) -> (&'static str, &'static str) {
    match outcome {
        ProvidenceReconciliationOutcome::InSync => ("in_sync", "passed"),
        ProvidenceReconciliationOutcome::SwarmAhead => ("swarm_ahead", "ready"),
        ProvidenceReconciliationOutcome::ProvidenceAhead => ("providence_ahead", "blocked"),
        ProvidenceReconciliationOutcome::Mismatch => ("mismatch", "failed"),
    }
}

pub(super) fn render_rehearsal_preview_details(preview: &ResponseRehearsalPreview) -> String {
    let affected_capabilities = if preview.blast_radius.affected_capabilities.is_empty() {
        "<li class=\"muted\">No affected capabilities recorded.</li>".to_string()
    } else {
        preview
            .blast_radius
            .affected_capabilities
            .iter()
            .map(|value| format!("<li><code>{}</code></li>", escape_html(value)))
            .collect::<Vec<_>>()
            .join("")
    };
    let rollback_steps = if preview.rollback.steps.is_empty() {
        "<li class=\"muted\">No explicit rollback steps recorded.</li>".to_string()
    } else {
        preview
            .rollback
            .steps
            .iter()
            .map(|step| format!("<li>{}</li>", escape_html(&step.summary)))
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        "<div class=\"meta\">\
            <div><dt>Rehearsal ID</dt><dd><code>{rehearsal_id}</code></dd></div>\
            <div><dt>Source Bundle</dt><dd><code>{source_bundle_id}</code></dd></div>\
            <div><dt>Dry Run Only</dt><dd>{dry_run}</dd></div>\
            <div><dt>Blast Radius</dt><dd>{blast_summary}</dd></div>\
            <div><dt>Rollback</dt><dd>{rollback_summary}</dd></div>\
        </div>\
        <p class=\"muted\">{impact_summary}</p>\
        <h3>Affected Capabilities</h3><ul>{affected_capabilities}</ul>\
        <h3>Rollback Steps</h3><ul>{rollback_steps}</ul>",
        rehearsal_id = escape_html(&preview.rehearsal_id),
        source_bundle_id = escape_html(&preview.source_bundle_id),
        dry_run = if preview.simulated_only { "yes" } else { "no" },
        blast_summary = escape_html(&preview.blast_radius.summary),
        rollback_summary = escape_html(&preview.rollback.summary),
        impact_summary = escape_html(&format!(
            "{} scope `{}` with up to {} affected scope(s)",
            format!("{:?}", preview.blast_radius.impact).to_lowercase(),
            preview.blast_radius.scope_value,
            preview.blast_radius.max_affected_scopes,
        )),
        affected_capabilities = affected_capabilities,
        rollback_steps = rollback_steps,
    )
}

pub(super) fn subject_api_path(kind: EvidenceSubjectKind, id: &str) -> Option<String> {
    match kind {
        EvidenceSubjectKind::ReplayBundle => Some(format!("/v1/operator/replay?bundle_id={id}")),
        EvidenceSubjectKind::InvestigationBundle => {
            Some(format!("/v1/operator/investigation?investigation_id={id}"))
        }
        EvidenceSubjectKind::CorrelatedIncident => {
            Some(format!("/v1/operator/incident?incident_id={id}"))
        }
        EvidenceSubjectKind::OperatorMaintenanceAction => {
            Some(format!("/v1/operator/maintenance/actions/{id}"))
        }
        EvidenceSubjectKind::ProductionPromotion
        | EvidenceSubjectKind::CanaryRun
        | EvidenceSubjectKind::DetectorVerification
        | EvidenceSubjectKind::StrategyShadow
        | EvidenceSubjectKind::PromotionReview => None,
    }
}

pub(super) fn render_related_ref_link(kind: &str, id: &str) -> String {
    if let Some(href) = related_ref_path(kind, id) {
        review_link(&href, id)
    } else {
        format!("<code>{}</code>", escape_html(id))
    }
}

fn related_ref_path(kind: &str, id: &str) -> Option<String> {
    match kind {
        "replay_bundle" => Some(format!("/v1/operator/replay?bundle_id={id}")),
        "investigation_bundle" => Some(format!("/v1/operator/investigation?investigation_id={id}")),
        "correlated_incident" => Some(format!("/v1/operator/incident?incident_id={id}")),
        "operator_maintenance_action" => Some(format!("/v1/operator/maintenance/actions/{id}")),
        "evidence_bundle" => Some(format!("/v1/operator/review/evidence/{id}")),
        "evidence_verification" => Some(format!("/v1/operator/review/verifications/{id}")),
        "promotion_evidence_packet" => Some(format!("/v1/operator/review/promotion-packets/{id}")),
        _ => None,
    }
}

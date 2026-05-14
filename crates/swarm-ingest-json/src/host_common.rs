use crate::record_error;
use chrono::DateTime;
use serde_json::Value;
use swarm_core::{BridgeHealth, TelemetryBridgeResult};

pub(crate) fn event_root(record: &Value) -> &Value {
    record.pointer("/Event").unwrap_or(record)
}

pub(crate) fn first_value<'a>(record: &'a Value, pointers: &[&str]) -> Option<&'a Value> {
    pointers.iter().find_map(|pointer| record.pointer(pointer))
}

pub(crate) fn first_string(record: &Value, pointers: &[&str]) -> Option<String> {
    first_value(record, pointers).and_then(value_to_string)
}

pub(crate) fn first_bool(record: &Value, pointers: &[&str]) -> Option<bool> {
    first_value(record, pointers).and_then(value_to_bool)
}

pub(crate) fn first_u16(record: &Value, pointers: &[&str]) -> Option<u16> {
    first_value(record, pointers).and_then(value_to_u16)
}

pub(crate) fn required_string(
    record: &Value,
    pointers: &[&str],
    field: &str,
    health: &mut BridgeHealth,
    source_id: &str,
) -> TelemetryBridgeResult<String> {
    first_string(record, pointers).ok_or_else(|| {
        record_error(
            health,
            format!("{source_id} field `{field}` is required and must be non-empty"),
        )
    })
}

pub(crate) fn required_timestamp(
    record: &Value,
    pointers: &[&str],
    field: &str,
    health: &mut BridgeHealth,
    source_id: &str,
) -> TelemetryBridgeResult<i64> {
    first_value(record, pointers)
        .and_then(parse_timestamp_value)
        .ok_or_else(|| {
            record_error(
                health,
                format!("{source_id} field `{field}` must be a valid timestamp"),
            )
        })
}

pub(crate) fn required_u16(
    record: &Value,
    pointers: &[&str],
    field: &str,
    health: &mut BridgeHealth,
    source_id: &str,
) -> TelemetryBridgeResult<u16> {
    first_u16(record, pointers).ok_or_else(|| {
        record_error(
            health,
            format!("{source_id} field `{field}` must be a valid u16"),
        )
    })
}

pub(crate) fn telemetry_event_id(
    source_id: &str,
    record_id: Option<String>,
    event_kind: impl AsRef<str>,
    timestamp: i64,
) -> String {
    if let Some(record_id) = record_id.filter(|value| !value.trim().is_empty()) {
        format!("{source_id}-{record_id}")
    } else {
        format!("{source_id}-{}-{timestamp}", event_kind.as_ref())
    }
}

pub(crate) fn process_name_from_path(value: &str) -> String {
    let basename = value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_string();
    if basename.to_ascii_lowercase().ends_with(".exe") && basename.len() > 4 {
        basename[..basename.len() - 4].to_string()
    } else {
        basename
    }
}

pub(crate) fn sanitize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed == "-"
            || trimmed.eq_ignore_ascii_case("n/a")
            || trimmed.eq_ignore_ascii_case("(null)")
        {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => sanitize_optional_string(Some(value.clone())),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Object(map) => map
            .get("#text")
            .and_then(value_to_string)
            .or_else(|| map.get("@SystemTime").and_then(value_to_string))
            .or_else(|| map.get("SystemTime").and_then(value_to_string)),
        _ => None,
    }
}

fn value_to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => {
            let trimmed = value.trim();
            if trimmed.eq_ignore_ascii_case("true")
                || trimmed.eq_ignore_ascii_case("yes")
                || trimmed.eq_ignore_ascii_case("valid")
                || trimmed == "1"
            {
                Some(true)
            } else if trimmed.eq_ignore_ascii_case("false")
                || trimmed.eq_ignore_ascii_case("no")
                || trimmed.eq_ignore_ascii_case("invalid")
                || trimmed == "0"
            {
                Some(false)
            } else {
                None
            }
        }
        Value::Number(value) => value.as_u64().map(|value| value > 0),
        _ => None,
    }
}

fn value_to_u16(value: &Value) -> Option<u16> {
    match value {
        Value::Number(value) => value.as_u64().and_then(|value| u16::try_from(value).ok()),
        Value::String(value) => value.trim().parse::<u16>().ok(),
        _ => None,
    }
}

fn parse_timestamp_value(value: &Value) -> Option<i64> {
    match value {
        Value::String(value) => parse_timestamp_str(value),
        Value::Number(value) => value.as_i64().map(normalize_epoch_seconds).or_else(|| {
            value
                .as_f64()
                .map(|value| normalize_epoch_seconds(value.trunc() as i64))
        }),
        Value::Object(map) => map
            .get("@SystemTime")
            .or_else(|| map.get("SystemTime"))
            .or_else(|| map.get("#text"))
            .and_then(parse_timestamp_value),
        _ => None,
    }
}

fn parse_timestamp_str(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(timestamp) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(timestamp.timestamp());
    }

    if let Ok(value) = trimmed.parse::<i64>() {
        return Some(normalize_epoch_seconds(value));
    }

    if let Ok(value) = trimmed.parse::<f64>() {
        return Some(normalize_epoch_seconds(value.trunc() as i64));
    }

    trimmed
        .strip_prefix("audit(")
        .and_then(|value| value.split(':').next())
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value.trunc() as i64)
}

fn normalize_epoch_seconds(value: i64) -> i64 {
    if value > 1_000_000_000_000 {
        value / 1000
    } else {
        value
    }
}

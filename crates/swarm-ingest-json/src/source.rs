use serde_json::Value;
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use swarm_core::config::JsonFileSourceConfig;

#[derive(Debug, thiserror::Error)]
pub enum JsonRecordSourceError {
    #[error("failed to read JSON records from `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse JSON record source `{path}`: {reason}")]
    Parse { path: String, reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct JsonRecordSource {
    records: VecDeque<Value>,
}

impl JsonRecordSource {
    pub fn new(records: impl IntoIterator<Item = Value>) -> Self {
        Self {
            records: records.into_iter().collect(),
        }
    }

    pub fn from_file_config(config: &JsonFileSourceConfig) -> Result<Self, JsonRecordSourceError> {
        Self::from_path(&config.path)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, JsonRecordSourceError> {
        let path = path.as_ref();
        let path_display = path.display().to_string();
        let raw = fs::read_to_string(path).map_err(|source| JsonRecordSourceError::Read {
            path: path_display.clone(),
            source,
        })?;
        Self::from_str(&path_display, &raw)
    }

    pub fn from_str(path: &str, raw: &str) -> Result<Self, JsonRecordSourceError> {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            return match value {
                Value::Array(records) => Ok(Self::new(records)),
                Value::Object(_) => Ok(Self::new([value])),
                _ => Err(JsonRecordSourceError::Parse {
                    path: path.to_string(),
                    reason: "top-level JSON must be an object, array, or JSON Lines stream"
                        .to_string(),
                }),
            };
        }

        let mut records = Vec::new();
        for (index, line) in raw.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value = serde_json::from_str::<Value>(trimmed).map_err(|source| {
                JsonRecordSourceError::Parse {
                    path: path.to_string(),
                    reason: format!("line {} failed to parse as JSON: {source}", index + 1),
                }
            })?;
            if !value.is_object() {
                return Err(JsonRecordSourceError::Parse {
                    path: path.to_string(),
                    reason: format!("line {} must decode to a JSON object", index + 1),
                });
            }
            records.push(value);
        }

        if records.is_empty() {
            return Err(JsonRecordSourceError::Parse {
                path: path.to_string(),
                reason: "no JSON records found".to_string(),
            });
        }

        Ok(Self::new(records))
    }

    pub fn next_record(&mut self) -> Option<Value> {
        self.records.pop_front()
    }

    pub fn is_exhausted(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::JsonRecordSource;

    #[test]
    fn parses_json_array_sources() {
        let source = JsonRecordSource::from_str("inline", r#"[{"event":"one"},{"event":"two"}]"#)
            .expect("array source should parse");

        assert!(!source.is_exhausted());
    }

    #[test]
    fn parses_json_lines_sources() {
        let source =
            JsonRecordSource::from_str("inline", "{\"event\":\"one\"}\n{\"event\":\"two\"}\n")
                .expect("json lines source should parse");

        assert!(!source.is_exhausted());
    }

    #[test]
    fn rejects_empty_sources() {
        let error = JsonRecordSource::from_str("inline", "\n\n").expect_err("empty source fails");
        assert!(error.to_string().contains("no JSON records found"));
    }
}

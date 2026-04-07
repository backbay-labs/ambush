use crate::ExecutionMode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    pub timestamp_ms: i64,
    pub receipt_id: String,
    pub action: String,
    pub mode: ExecutionMode,
    pub adapter: String,
    pub attempts: u32,
    pub last_error: String,
    pub details: Value,
}

#[derive(Debug)]
pub struct DeadLetterJournal {
    path: PathBuf,
}

impl DeadLetterJournal {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let journal = Self::from_path(path);
        journal.ensure_path()?;
        Ok(journal)
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn write(&self, entry: &DeadLetterEntry) -> io::Result<()> {
        self.ensure_path()?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, entry)?;
        file.write_all(b"\n")?;
        file.flush()
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn read_entries(&self, limit: Option<usize>) -> io::Result<Vec<DeadLetterEntry>> {
        self.ensure_path()?;
        let raw = std::fs::read_to_string(&self.path)?;
        let mut entries = Vec::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let entry = serde_json::from_str(trimmed).map_err(io::Error::other)?;
            entries.push(entry);
        }
        if let Some(limit) = limit
            && entries.len() > limit
        {
            let start = entries.len() - limit;
            return Ok(entries.split_off(start));
        }
        Ok(entries)
    }

    fn ensure_path(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            create_dir_all(parent)?;
        }
        if !self.path.exists() {
            File::create(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{DeadLetterEntry, DeadLetterJournal};
    use crate::ExecutionMode;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swarm-response-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn write_appends_jsonl_line() {
        let path = temp_path("dead-letter");
        let journal = DeadLetterJournal::new(&path).unwrap();
        journal
            .write(&DeadLetterEntry {
                timestamp_ms: 1_700_000_000_000,
                receipt_id: "receipt-1".to_string(),
                action: "block_egress".to_string(),
                mode: ExecutionMode::Enforced,
                adapter: "http_edr".to_string(),
                attempts: 2,
                last_error: "failed".to_string(),
                details: serde_json::json!({"status": "timeout"}),
            })
            .unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 1);
        assert!(raw.contains("\"receipt_id\":\"receipt-1\""));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_creates_missing_parent_directories() {
        let root = temp_path("dead-letter-parent");
        let path = root.join("nested/dead-letter.jsonl");
        let journal = DeadLetterJournal::new(&path).unwrap();
        journal
            .write(&DeadLetterEntry {
                timestamp_ms: 1_700_000_000_001,
                receipt_id: "receipt-2".to_string(),
                action: "escalate".to_string(),
                mode: ExecutionMode::Enforced,
                adapter: "webhook".to_string(),
                attempts: 1,
                last_error: "failed".to_string(),
                details: serde_json::json!({}),
            })
            .unwrap();

        assert!(path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn read_entries_returns_latest_entries_when_limited() {
        let path = temp_path("dead-letter-read");
        let journal = DeadLetterJournal::from_path(&path);
        for idx in 0..3 {
            journal
                .write(&DeadLetterEntry {
                    timestamp_ms: 1_700_000_000_100 + idx,
                    receipt_id: format!("receipt-{idx}"),
                    action: "notify".to_string(),
                    mode: ExecutionMode::Enforced,
                    adapter: "notification".to_string(),
                    attempts: 1,
                    last_error: "suppressed".to_string(),
                    details: serde_json::json!({"index": idx}),
                })
                .unwrap();
        }

        let entries = journal.read_entries(Some(2)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].receipt_id, "receipt-1");
        assert_eq!(entries[1].receipt_id, "receipt-2");

        let _ = fs::remove_file(path);
    }
}

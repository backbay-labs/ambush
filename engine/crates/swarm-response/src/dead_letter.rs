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
    max_bytes: Option<u64>,
}

impl DeadLetterJournal {
    pub fn new(path: impl Into<PathBuf>, max_bytes: Option<u64>) -> io::Result<Self> {
        let journal = Self::from_path(path, max_bytes);
        journal.ensure_path()?;
        Ok(journal)
    }

    pub fn from_path(path: impl Into<PathBuf>, max_bytes: Option<u64>) -> Self {
        Self {
            path: path.into(),
            max_bytes,
        }
    }

    pub fn write(&self, entry: &DeadLetterEntry) -> io::Result<()> {
        self.rotate_if_needed()?;
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

    fn rotate_if_needed(&self) -> io::Result<()> {
        let Some(max_bytes) = self.max_bytes else {
            return Ok(());
        };
        let metadata = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if metadata.len() < max_bytes {
            return Ok(());
        }
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let rotated = PathBuf::from(format!("{}.{}", self.path.display(), timestamp_ms));
        std::fs::rename(&self.path, &rotated)?;
        // Create a fresh empty journal file
        File::create(&self.path)?;
        Ok(())
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
        let journal = DeadLetterJournal::new(&path, None).unwrap();
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
        let journal = DeadLetterJournal::new(&path, None).unwrap();
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
    fn rotation_renames_file_when_exceeding_max_bytes() {
        let path = temp_path("dead-letter-rotate");
        // Each JSON entry is ~189 bytes, so 800 bytes holds about 4 entries
        let journal = DeadLetterJournal::new(&path, Some(800)).unwrap();

        // Write entries until file exceeds 800 bytes (5 entries ~= 945 bytes)
        for idx in 0..5 {
            journal
                .write(&DeadLetterEntry {
                    timestamp_ms: 1_700_000_000_000 + idx,
                    receipt_id: format!("receipt-rot-{idx}"),
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    adapter: "http_edr".to_string(),
                    attempts: 1,
                    last_error: "failed".to_string(),
                    details: serde_json::json!({"status": "timeout"}),
                })
                .unwrap();
        }

        // File should be larger than 800 bytes now
        let size_before = fs::metadata(&path).unwrap().len();
        assert!(size_before > 800, "file should exceed max_bytes threshold");

        // Write one more entry which should trigger rotation
        journal
            .write(&DeadLetterEntry {
                timestamp_ms: 1_700_000_000_099,
                receipt_id: "receipt-rot-final".to_string(),
                action: "block_egress".to_string(),
                mode: ExecutionMode::Enforced,
                adapter: "http_edr".to_string(),
                attempts: 1,
                last_error: "failed".to_string(),
                details: serde_json::json!({"status": "timeout"}),
            })
            .unwrap();

        // After rotation, the active journal should only have the new entry
        let entries = journal.read_entries(None).unwrap();
        assert_eq!(
            entries.len(),
            1,
            "active journal should have 1 entry after rotation"
        );
        assert_eq!(entries[0].receipt_id, "receipt-rot-final");

        // A rotated file should exist with a numeric timestamp suffix
        let parent = path.parent().unwrap();
        let prefix = path.file_name().unwrap().to_str().unwrap();
        let rotated_files: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.starts_with(prefix) && name != prefix
            })
            .collect();
        assert_eq!(
            rotated_files.len(),
            1,
            "should have exactly one rotated file"
        );
        let rotated_name = rotated_files[0].file_name().to_string_lossy().to_string();
        let suffix = rotated_name.strip_prefix(&format!("{prefix}.")).unwrap();
        assert!(
            suffix.parse::<u128>().is_ok(),
            "suffix should be a numeric timestamp"
        );

        // Cleanup
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(rotated_files[0].path());
    }

    #[test]
    fn no_rotation_when_max_bytes_is_none() {
        let path = temp_path("dead-letter-no-rotate");
        let journal = DeadLetterJournal::new(&path, None).unwrap();

        for idx in 0..10 {
            journal
                .write(&DeadLetterEntry {
                    timestamp_ms: 1_700_000_000_000 + idx,
                    receipt_id: format!("receipt-nr-{idx}"),
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    adapter: "http_edr".to_string(),
                    attempts: 1,
                    last_error: "failed".to_string(),
                    details: serde_json::json!({"status": "timeout"}),
                })
                .unwrap();
        }

        // No rotated files should exist
        let parent = path.parent().unwrap();
        let prefix = path.file_name().unwrap().to_str().unwrap();
        let rotated_files: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.starts_with(prefix) && name != prefix
            })
            .collect();
        assert!(rotated_files.is_empty(), "no rotated files should exist");

        let entries = journal.read_entries(None).unwrap();
        assert_eq!(entries.len(), 10);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rotated_file_preserves_original_entries() {
        let path = temp_path("dead-letter-preserve");
        // Each JSON entry is ~189 bytes, so 800 bytes holds about 4 entries
        let journal = DeadLetterJournal::new(&path, Some(800)).unwrap();

        // Write entries until file exceeds 800 bytes (5 entries ~= 945 bytes)
        let mut written_count = 0;
        for idx in 0..5 {
            journal
                .write(&DeadLetterEntry {
                    timestamp_ms: 1_700_000_000_000 + idx,
                    receipt_id: format!("receipt-pres-{idx}"),
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    adapter: "http_edr".to_string(),
                    attempts: 1,
                    last_error: "failed".to_string(),
                    details: serde_json::json!({"status": "timeout"}),
                })
                .unwrap();
            written_count += 1;
        }

        // Trigger rotation
        journal
            .write(&DeadLetterEntry {
                timestamp_ms: 1_700_000_000_099,
                receipt_id: "receipt-pres-trigger".to_string(),
                action: "block_egress".to_string(),
                mode: ExecutionMode::Enforced,
                adapter: "http_edr".to_string(),
                attempts: 1,
                last_error: "failed".to_string(),
                details: serde_json::json!({"status": "timeout"}),
            })
            .unwrap();

        // Find the rotated file
        let parent = path.parent().unwrap();
        let prefix = path.file_name().unwrap().to_str().unwrap();
        let rotated_path = fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .find(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.starts_with(prefix) && name != prefix
            })
            .expect("rotated file should exist")
            .path();

        // Read rotated file and verify it has the original entries
        let rotated_journal = DeadLetterJournal::from_path(&rotated_path, None);
        let rotated_entries = rotated_journal.read_entries(None).unwrap();
        assert_eq!(rotated_entries.len(), written_count);
        assert_eq!(rotated_entries[0].receipt_id, "receipt-pres-0");
        assert_eq!(
            rotated_entries[written_count - 1].receipt_id,
            format!("receipt-pres-{}", written_count - 1)
        );

        // Cleanup
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&rotated_path);
    }

    #[test]
    fn read_entries_returns_latest_entries_when_limited() {
        let path = temp_path("dead-letter-read");
        let journal = DeadLetterJournal::from_path(&path, None);
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

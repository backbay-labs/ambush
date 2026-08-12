use super::helpers::sanitize_id;
use super::types::{
    ReviewCapsule, ReviewCapsuleImport, ReviewCapsuleImportIndex, ReviewCapsuleImportList,
    ReviewCapsuleImportLookup, ReviewCapsuleImportRecord, ReviewCapsuleImportStoreError,
    ReviewCapsuleIndex, ReviewCapsuleList, ReviewCapsuleLookup, ReviewCapsuleRecord,
    ReviewCapsuleStoreError, ReviewDelegationPacket, ReviewDelegationPacketIndex,
    ReviewDelegationPacketList, ReviewDelegationPacketLookup, ReviewDelegationPacketRecord,
    ReviewDelegationPacketStoreError, ReviewSessionExport, ReviewSessionExportIndex,
    ReviewSessionExportList, ReviewSessionExportLookup, ReviewSessionExportRecord,
    ReviewSessionExportStoreError, ReviewSessionIndex, ReviewSessionList, ReviewSessionLookup,
    ReviewSessionMaintenanceHandoff, ReviewSessionMaintenanceHandoffIndex,
    ReviewSessionMaintenanceHandoffList, ReviewSessionMaintenanceHandoffLookup,
    ReviewSessionMaintenanceHandoffRecord, ReviewSessionMaintenanceHandoffStoreError,
    ReviewSessionPromotionReadiness, ReviewSessionPromotionReadinessIndex,
    ReviewSessionPromotionReadinessList, ReviewSessionPromotionReadinessLookup,
    ReviewSessionPromotionReadinessRecord, ReviewSessionPromotionReadinessStoreError,
    ReviewSessionRecord, ReviewSessionReport, ReviewSessionStoreError,
};
use std::fs;
use std::path::{Path, PathBuf};

/// File-backed review-session store.
#[derive(Debug, Clone)]
pub struct FileReviewSessionStore {
    root: PathBuf,
}

impl FileReviewSessionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, session_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(session_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewSessionIndex, ReviewSessionStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ReviewSessionStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ReviewSessionStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ReviewSessionIndex) -> Result<(), ReviewSessionStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewSessionStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &ReviewSessionReport,
    ) -> Result<ReviewSessionLookup, ReviewSessionStoreError> {
        let path = self.report_path(&report.session_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            ReviewSessionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewSessionStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewSessionRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.session_id != record.session_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionLookup {
            record,
            report: report.clone(),
        })
    }

    pub fn load(
        &self,
        session_id: &str,
    ) -> Result<Option<ReviewSessionLookup>, ReviewSessionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.session_id == session_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ReviewSessionStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| ReviewSessionStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ReviewSessionLookup { record, report }))
    }

    pub fn list(&self) -> Result<ReviewSessionList, ReviewSessionStoreError> {
        let sessions = self.read_index()?.entries;
        Ok(ReviewSessionList {
            total_count: sessions.len(),
            sessions,
        })
    }
}

/// File-backed export store for review sessions.
#[derive(Debug, Clone)]
pub struct FileReviewSessionExportStore {
    root: PathBuf,
}

impl FileReviewSessionExportStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionExportStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionExportStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, export_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(export_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewSessionExportIndex, ReviewSessionExportStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionExportIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewSessionExportStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewSessionExportStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewSessionExportIndex,
    ) -> Result<(), ReviewSessionExportStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionExportStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewSessionExportStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        export: &ReviewSessionExport,
    ) -> Result<ReviewSessionExportLookup, ReviewSessionExportStoreError> {
        let path = self.report_path(&export.export_id);
        let raw = serde_json::to_string_pretty(export).map_err(|source| {
            ReviewSessionExportStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewSessionExportStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewSessionExportRecord::from_export(export, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.export_id != record.export_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionExportLookup {
            record,
            export: export.clone(),
        })
    }

    pub fn load(
        &self,
        export_id: &str,
    ) -> Result<Option<ReviewSessionExportLookup>, ReviewSessionExportStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.export_id == export_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewSessionExportStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let export =
            serde_json::from_str(&raw).map_err(|source| ReviewSessionExportStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ReviewSessionExportLookup { record, export }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionExportList, ReviewSessionExportStoreError> {
        let mut exports = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            exports.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewSessionExportList {
            total_count: exports.len(),
            session_id: session_id.map(ToString::to_string),
            exports,
        })
    }
}

/// File-backed promotion-readiness store for review sessions.
#[derive(Debug, Clone)]
pub struct FileReviewSessionPromotionReadinessStore {
    root: PathBuf,
}

impl FileReviewSessionPromotionReadinessStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionPromotionReadinessStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, readiness_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(readiness_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<ReviewSessionPromotionReadinessIndex, ReviewSessionPromotionReadinessStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionPromotionReadinessIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewSessionPromotionReadinessStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewSessionPromotionReadinessIndex,
    ) -> Result<(), ReviewSessionPromotionReadinessStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewSessionPromotionReadinessStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &ReviewSessionPromotionReadiness,
    ) -> Result<ReviewSessionPromotionReadinessLookup, ReviewSessionPromotionReadinessStoreError>
    {
        let path = self.report_path(&report.readiness_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            ReviewSessionPromotionReadinessRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.readiness_id != record.readiness_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionPromotionReadinessLookup {
            record,
            report: report.clone(),
        })
    }

    pub fn load(
        &self,
        readiness_id: &str,
    ) -> Result<
        Option<ReviewSessionPromotionReadinessLookup>,
        ReviewSessionPromotionReadinessStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.readiness_id == readiness_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some(ReviewSessionPromotionReadinessLookup {
            record,
            report,
        }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionPromotionReadinessList, ReviewSessionPromotionReadinessStoreError>
    {
        let mut readiness_reports = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            readiness_reports.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewSessionPromotionReadinessList {
            total_count: readiness_reports.len(),
            session_id: session_id.map(ToString::to_string),
            readiness_reports,
        })
    }
}

/// File-backed maintenance-handoff store for review sessions.
#[derive(Debug, Clone)]
pub struct FileReviewSessionMaintenanceHandoffStore {
    root: PathBuf,
}

impl FileReviewSessionMaintenanceHandoffStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionMaintenanceHandoffStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, handoff_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(handoff_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<ReviewSessionMaintenanceHandoffIndex, ReviewSessionMaintenanceHandoffStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionMaintenanceHandoffIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewSessionMaintenanceHandoffStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewSessionMaintenanceHandoffIndex,
    ) -> Result<(), ReviewSessionMaintenanceHandoffStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewSessionMaintenanceHandoffStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        handoff: &ReviewSessionMaintenanceHandoff,
    ) -> Result<ReviewSessionMaintenanceHandoffLookup, ReviewSessionMaintenanceHandoffStoreError>
    {
        let path = self.report_path(&handoff.handoff_id);
        let raw = serde_json::to_string_pretty(handoff).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record = ReviewSessionMaintenanceHandoffRecord::from_handoff(
            handoff,
            path.display().to_string(),
        );
        index
            .entries
            .retain(|entry| entry.handoff_id != record.handoff_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionMaintenanceHandoffLookup {
            record,
            handoff: handoff.clone(),
        })
    }

    pub fn load(
        &self,
        handoff_id: &str,
    ) -> Result<
        Option<ReviewSessionMaintenanceHandoffLookup>,
        ReviewSessionMaintenanceHandoffStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.handoff_id == handoff_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let handoff = serde_json::from_str(&raw).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some(ReviewSessionMaintenanceHandoffLookup {
            record,
            handoff,
        }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionMaintenanceHandoffList, ReviewSessionMaintenanceHandoffStoreError>
    {
        let mut handoffs = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            handoffs.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewSessionMaintenanceHandoffList {
            total_count: handoffs.len(),
            session_id: session_id.map(ToString::to_string),
            handoffs,
        })
    }
}

/// File-backed store for signed portable review capsules.
#[derive(Debug, Clone)]
pub struct FileReviewCapsuleStore {
    root: PathBuf,
}

impl FileReviewCapsuleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewCapsuleStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewCapsuleStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, capsule_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(capsule_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewCapsuleIndex, ReviewCapsuleStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewCapsuleIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ReviewCapsuleStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ReviewCapsuleStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ReviewCapsuleIndex) -> Result<(), ReviewCapsuleStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewCapsuleStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewCapsuleStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        capsule: &ReviewCapsule,
    ) -> Result<ReviewCapsuleLookup, ReviewCapsuleStoreError> {
        let path = self.report_path(&capsule.capsule_id);
        let raw = serde_json::to_string_pretty(capsule).map_err(|source| {
            ReviewCapsuleStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewCapsuleStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewCapsuleRecord::from_capsule(capsule, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.capsule_id != record.capsule_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewCapsuleLookup {
            record,
            capsule: capsule.clone(),
        })
    }

    pub fn load(
        &self,
        capsule_id: &str,
    ) -> Result<Option<ReviewCapsuleLookup>, ReviewCapsuleStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.capsule_id == capsule_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ReviewCapsuleStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let capsule =
            serde_json::from_str(&raw).map_err(|source| ReviewCapsuleStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ReviewCapsuleLookup { record, capsule }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewCapsuleList, ReviewCapsuleStoreError> {
        let mut capsules = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            capsules.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewCapsuleList {
            total_count: capsules.len(),
            session_id: session_id.map(ToString::to_string),
            capsules,
        })
    }
}

/// File-backed store for imported review capsules.
#[derive(Debug, Clone)]
pub struct FileReviewCapsuleImportStore {
    root: PathBuf,
}

impl FileReviewCapsuleImportStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewCapsuleImportStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewCapsuleImportStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, import_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(import_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewCapsuleImportIndex, ReviewCapsuleImportStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewCapsuleImportIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewCapsuleImportStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewCapsuleImportStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewCapsuleImportIndex,
    ) -> Result<(), ReviewCapsuleImportStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewCapsuleImportStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewCapsuleImportStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        import: &ReviewCapsuleImport,
    ) -> Result<ReviewCapsuleImportLookup, ReviewCapsuleImportStoreError> {
        let path = self.report_path(&import.import_id);
        let raw = serde_json::to_string_pretty(import).map_err(|source| {
            ReviewCapsuleImportStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewCapsuleImportStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewCapsuleImportRecord::from_import(import, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.import_id != record.import_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.imported_at_ms));
        self.write_index(&index)?;
        Ok(ReviewCapsuleImportLookup {
            record,
            import: import.clone(),
        })
    }

    pub fn load(
        &self,
        import_id: &str,
    ) -> Result<Option<ReviewCapsuleImportLookup>, ReviewCapsuleImportStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.import_id == import_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewCapsuleImportStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let import =
            serde_json::from_str(&raw).map_err(|source| ReviewCapsuleImportStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ReviewCapsuleImportLookup { record, import }))
    }

    pub fn list(&self) -> Result<ReviewCapsuleImportList, ReviewCapsuleImportStoreError> {
        let imports = self.read_index()?.entries;
        Ok(ReviewCapsuleImportList {
            total_count: imports.len(),
            imports,
        })
    }
}

/// File-backed store for review delegation packets.
#[derive(Debug, Clone)]
pub struct FileReviewDelegationPacketStore {
    root: PathBuf,
}

impl FileReviewDelegationPacketStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewDelegationPacketStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewDelegationPacketStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, delegation_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(delegation_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewDelegationPacketIndex, ReviewDelegationPacketStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewDelegationPacketIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewDelegationPacketStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewDelegationPacketStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewDelegationPacketIndex,
    ) -> Result<(), ReviewDelegationPacketStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewDelegationPacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewDelegationPacketStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        packet: &ReviewDelegationPacket,
    ) -> Result<ReviewDelegationPacketLookup, ReviewDelegationPacketStoreError> {
        let path = self.report_path(&packet.delegation_id);
        let raw = serde_json::to_string_pretty(packet).map_err(|source| {
            ReviewDelegationPacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewDelegationPacketStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewDelegationPacketRecord::from_packet(packet, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.delegation_id != record.delegation_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewDelegationPacketLookup {
            record,
            packet: packet.clone(),
        })
    }

    pub fn load(
        &self,
        delegation_id: &str,
    ) -> Result<Option<ReviewDelegationPacketLookup>, ReviewDelegationPacketStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.delegation_id == delegation_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewDelegationPacketStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let packet = serde_json::from_str(&raw).map_err(|source| {
            ReviewDelegationPacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some(ReviewDelegationPacketLookup { record, packet }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewDelegationPacketList, ReviewDelegationPacketStoreError> {
        let mut delegations = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            delegations.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewDelegationPacketList {
            total_count: delegations.len(),
            session_id: session_id.map(ToString::to_string),
            delegations,
        })
    }
}

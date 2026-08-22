//! Private, append-only state for content-free routing decisions.
//!
//! The store is intentionally independent from circuit and admission state.  A bad store never
//! produces an efficient decision: callers receive an error and keep the configured capable
//! upstream.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Mutex,
};

#[cfg(test)]
use std::cell::Cell;

use bowline_core::ledger::{RoutingDecisionSourceV3, RoutingUnavailableCauseV3};
use bowline_core::routing::{
    select_stage, task_reference, RoutingReason, RoutingSelection, RoutingSignal, RoutingStep,
    RoutingTarget, StageRoutingProfile,
};
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_MAX_ACTIVE_TASKS: usize = 1_024;
pub const MAX_ACTIVE_TASKS: usize = 16_384;
pub const DEFAULT_MAX_REQUEST_SIGNALS: usize = 32;
pub const MAX_REQUEST_SIGNALS: usize = 32;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const DEFAULT_ROUTING_SEGMENT_BYTES: u64 = 1_048_576;
pub const DEFAULT_ROUTING_MAX_SEGMENTS: u32 = 16;
// Bumped from 2 to 3 with the move to a salted, keyed task reference (bowline.routing.task.v2).
// A store recorded under an older schema used an unkeyed digest for every stored `task_ref`; its
// history is unreadable under a salted derivation, so recovery refuses it outright rather than
// silently minting new, unrelated task references over old history. Bumped again from 3 to 4 with
// the introduction of `salt_digest`: a schema-3 directory has no fingerprint to compare against,
// so without this bump it would reach `SaltFingerprintMismatch` — which reads as tampering —
// instead of an honest "predates this build" refusal.
const ROUTING_STATE_SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingStateLimits {
    pub max_active_tasks: usize,
    pub segment_bytes: u64,
    pub max_segments: u32,
}

impl Default for RoutingStateLimits {
    fn default() -> Self {
        Self {
            max_active_tasks: DEFAULT_MAX_ACTIVE_TASKS,
            segment_bytes: DEFAULT_ROUTING_SEGMENT_BYTES,
            max_segments: DEFAULT_ROUTING_MAX_SEGMENTS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    task_ref: String,
    step_id: u64,
    route_digest: String,
    profile_digest: String,
    signals: Vec<RoutingSignal>,
    target: RoutingTarget,
    reason: RoutingReason,
    source: RoutingDecisionSourceV3,
    state_digest: String,
    decision_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingStoredDecision {
    pub task_ref: String,
    pub step_id: u64,
    pub profile_digest: String,
    pub target: RoutingTarget,
    pub reason: RoutingReason,
    pub source: RoutingDecisionSourceV3,
    pub state_digest: String,
    pub decision_digest: String,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RoutingStateHealth {
    pub ready: bool,
    /// Set when the store refused new history because its task or segment budget is spent. This
    /// release does not reclaim: an operator resets the routing state directory. Distinct from
    /// `failed`, which means the writer itself broke.
    pub capacity_exhausted: bool,
    pub active_tasks: usize,
    pub active_task_capacity: usize,
    pub segments: usize,
    pub segment_capacity: u32,
}

#[derive(Default)]
struct StateData {
    tasks: BTreeMap<String, Vec<StoredRecord>>,
    segments: Vec<SegmentState>,
    failed: bool,
    /// Set by every refusal for capacity and cleared by the next successful commit. Never
    /// persisted: a restart re-derives it from the first refusal after recovery.
    capacity_exhausted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SegmentState {
    index: u32,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateMetadata {
    schema_version: u32,
    segments: Vec<MetadataSegment>,
    active_segment: Option<u32>,
    // Detects a replaced or lost `salt` file: this field binds `metadata.json` to the salt that
    // wrote it, not the segment history itself, which carries a CRC rather than a MAC. Absent
    // (default empty) only for a pre-3a schema-version-3 directory, which the schema_version
    // check above already refuses before this field is ever compared. Derived via
    // `salt_fingerprint`; never the salt itself, so it discloses nothing if it ever leaked.
    #[serde(default)]
    salt_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataSegment {
    index: u32,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataCommitJournal {
    schema_version: u32,
    phase: MetadataCommitPhase,
    committed: StateMetadata,
    pending: StateMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MetadataCommitPhase {
    Rollback,
    Committed,
}

const METADATA_COMMIT_JOURNAL: &str = "metadata.pending.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataFailurePoint {
    BeforeJournalTempWrite,
    DuringJournalTempWrite,
    AfterJournalTempWrite,
    AfterJournalTempSync,
    AfterJournalRename,
    AfterJournalDirectorySync,
    BeforeSegmentMutation,
    AfterFrameSync,
    AfterMetadataPublish,
    AfterCommittedMarker,
    AfterJournalUnlink,
}

#[cfg(test)]
thread_local! {
    static TEST_METADATA_FAILURE: Cell<Option<MetadataFailurePoint>> = const { Cell::new(None) };
}

#[cfg(test)]
fn inject_metadata_failure(point: MetadataFailurePoint) {
    TEST_METADATA_FAILURE.with(|failure| failure.set(Some(point)));
}

fn fail_metadata_at(_point: MetadataFailurePoint) -> Result<(), RoutingStateError> {
    #[cfg(test)]
    if TEST_METADATA_FAILURE.with(|failure| {
        if failure.get() == Some(_point) {
            failure.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(RoutingStateError::Io);
    }
    Ok(())
}

pub struct RoutingStateStore {
    root: PathBuf,
    limits: RoutingStateLimits,
    data: Mutex<StateData>,
    // Generated once at store creation and never sent anywhere. Every caller of `task_reference`
    // must go through this store rather than deriving its own, so a task reference cannot be
    // reproduced off-host.
    salt: [u8; 32],
    // The handle retains the advisory lock for this process lifetime.  A second active gateway
    // must fail closed rather than interleave frames with this writer.
    _writer_lock: File,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingStateError {
    #[error("routing state path is unsafe")]
    UnsafePath,
    #[error("routing state capacity is exhausted")]
    Capacity,
    #[error("routing step conflicts with accepted state")]
    StepConflict,
    #[error("routing state is corrupt or undecodable")]
    Corrupt,
    #[error("routing state predates salted task references and must be reset")]
    LegacyTaskReferenceSchema,
    #[error(
        "routing state was written by a newer Bowline release and must not be deleted; roll forward instead"
    )]
    NewerRoutingStateSchema,
    #[error("routing state salt does not match the fingerprint recorded in its metadata")]
    SaltFingerprintMismatch,
    #[error("routing state salt file is all zero and cannot be used as a key")]
    AllZeroRoutingStateSalt,
    #[error(
        "routing state salt file is missing; restore it from backup before considering a reset"
    )]
    MissingRoutingStateSalt,
    #[error("routing state I/O failed")]
    Io,
    #[error("routing state writer failed")]
    WriterFailure,
    #[error("routing state already has an active writer")]
    Locked,
    #[error("invalid routing input")]
    Invalid,
}

impl RoutingStateError {
    pub fn unavailable_cause(&self) -> Option<RoutingUnavailableCauseV3> {
        match self {
            Self::StepConflict => Some(RoutingUnavailableCauseV3::StepConflict),
            Self::Capacity => Some(RoutingUnavailableCauseV3::CapacityExhausted),
            Self::Corrupt => Some(RoutingUnavailableCauseV3::StateCorrupt),
            Self::WriterFailure => Some(RoutingUnavailableCauseV3::WriterFailure),
            Self::UnsafePath
            | Self::Io
            | Self::Locked
            | Self::Invalid
            | Self::LegacyTaskReferenceSchema
            | Self::NewerRoutingStateSchema
            | Self::SaltFingerprintMismatch
            | Self::AllZeroRoutingStateSalt
            | Self::MissingRoutingStateSalt => None,
        }
    }

    pub fn startup_unavailable_cause(&self) -> RoutingUnavailableCauseV3 {
        match self {
            Self::Corrupt => RoutingUnavailableCauseV3::StateCorrupt,
            _ => RoutingUnavailableCauseV3::StartupUnavailable,
        }
    }
}

impl RoutingStateStore {
    pub fn open(
        ledger_dir: impl AsRef<Path>,
        limits: RoutingStateLimits,
    ) -> Result<Self, RoutingStateError> {
        if limits.max_active_tasks == 0
            || limits.max_active_tasks > MAX_ACTIVE_TASKS
            || limits.segment_bytes == 0
            || limits.segment_bytes > bowline_core::ledger::MAX_SEGMENT_BYTES
            || limits.max_segments == 0
            || limits.max_segments > bowline_core::ledger::MAX_SEGMENTS
        {
            return Err(RoutingStateError::Invalid);
        }
        let root = ledger_dir.as_ref().join("routing-state");
        ensure_private_dir(&root)?;
        let writer_lock = acquire_writer_lock(&root)?;
        let salt = load_or_create_salt(&root)?;
        let data = recover(&root, limits, &salt)?;
        write_metadata(&root, &data.segments, &salt)?;
        Ok(Self {
            root,
            limits,
            data: Mutex::new(data),
            salt,
            _writer_lock: writer_lock,
        })
    }

    /// The per-install salt generated at store creation. Never persisted anywhere but the
    /// store's own private, 0600 `salt` file, and never sent anywhere. Callers use it to derive a
    /// task reference through `bowline_core::routing::task_reference` rather than loading it
    /// themselves.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn decide(
        &self,
        task_id: &str,
        step_id: u64,
        route_digest: &str,
        profile: &StageRoutingProfile,
        signals: Vec<RoutingSignal>,
    ) -> Result<RoutingStoredDecision, RoutingStateError> {
        self.decide_with_source(
            task_id,
            step_id,
            route_digest,
            profile,
            signals,
            RoutingDecisionSourceV3::TrustedImmediatePeer,
        )
    }

    pub fn decide_with_source(
        &self,
        task_id: &str,
        step_id: u64,
        route_digest: &str,
        profile: &StageRoutingProfile,
        signals: Vec<RoutingSignal>,
        source: RoutingDecisionSourceV3,
    ) -> Result<RoutingStoredDecision, RoutingStateError> {
        if step_id == 0 || signals.len() > MAX_REQUEST_SIGNALS || route_digest.is_empty() {
            return Err(RoutingStateError::Invalid);
        }
        let task_ref =
            task_reference(&self.salt, task_id).map_err(|_| RoutingStateError::Invalid)?;
        let current = RoutingStep { signals };
        current.validate().map_err(|_| RoutingStateError::Invalid)?;
        let profile_digest = profile.digest();
        let mut data = self
            .data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if data.failed {
            return Err(RoutingStateError::WriterFailure);
        }
        let history = data.tasks.get(&task_ref);
        if history.is_none() && data.tasks.len() >= self.limits.max_active_tasks {
            data.capacity_exhausted = true;
            return Err(RoutingStateError::Capacity);
        }
        if let Some(history) = history {
            let expected = history.len() as u64 + 1;
            if step_id <= history.len() as u64 {
                let prior = &history[(step_id - 1) as usize];
                if prior.route_digest == route_digest
                    && prior.profile_digest == profile_digest
                    && prior.signals == current.signals
                {
                    return Ok(RoutingStoredDecision {
                        task_ref,
                        step_id,
                        profile_digest: prior.profile_digest.clone(),
                        target: prior.target,
                        reason: prior.reason,
                        source: prior.source,
                        state_digest: prior.state_digest.clone(),
                        decision_digest: prior.decision_digest.clone(),
                        replayed: true,
                    });
                }
                return Err(RoutingStateError::StepConflict);
            }
            if step_id != expected {
                return Err(RoutingStateError::StepConflict);
            }
        } else if step_id != 1 {
            return Err(RoutingStateError::StepConflict);
        }
        let prior_steps = history
            .map(|records| {
                records
                    .iter()
                    .map(|record| RoutingStep {
                        signals: record.signals.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let RoutingSelection { target, reason } = select_stage(profile, &prior_steps, &current)
            .map_err(|_| RoutingStateError::Invalid)?;
        let prior_state = history
            .and_then(|records| records.last())
            .map(|record| record.state_digest.as_str())
            .unwrap_or("empty");
        let state_digest = digest(
            b"bowline.routing.state.v1",
            &(
                prior_state,
                &task_ref,
                step_id,
                route_digest,
                &profile_digest,
                &current.signals,
                target,
                reason,
                source,
            ),
        );
        let decision_digest = digest(
            b"bowline.routing.decision.v1",
            &(
                &task_ref,
                step_id,
                route_digest,
                &profile_digest,
                target,
                reason,
                source,
                &state_digest,
            ),
        );
        let record = StoredRecord {
            task_ref: task_ref.clone(),
            step_id,
            route_digest: route_digest.into(),
            profile_digest: profile_digest.clone(),
            signals: current.signals,
            target,
            reason,
            source,
            state_digest: state_digest.clone(),
            decision_digest: decision_digest.clone(),
        };
        // The rollback journal is the first durable mutation. It names both the old committed
        // prefix and the exact next prefix, so a failed call can never become a later decision.
        let segments = match planned_segments(&record, self.limits, &data.segments) {
            Ok(segments) => segments,
            Err(RoutingStateError::Capacity) => {
                data.capacity_exhausted = true;
                return Err(RoutingStateError::Capacity);
            }
            Err(_) => {
                data.failed = true;
                return Err(RoutingStateError::WriterFailure);
            }
        };
        let mut journal = MetadataCommitJournal {
            schema_version: METADATA_COMMIT_JOURNAL_SCHEMA_VERSION,
            phase: MetadataCommitPhase::Rollback,
            committed: metadata_from_segments(&data.segments, &self.salt),
            pending: metadata_from_segments(&segments, &self.salt),
        };
        if write_metadata_commit_journal(&self.root, &journal)
            .and_then(|_| fail_metadata_at(MetadataFailurePoint::BeforeSegmentMutation))
            .is_err()
        {
            data.failed = true;
            return Err(RoutingStateError::WriterFailure);
        }
        if append_record(&self.root, &record, self.limits, &data.segments)
            .and_then(|actual| {
                if actual == segments {
                    Ok(())
                } else {
                    Err(RoutingStateError::Corrupt)
                }
            })
            .and_then(|_| fail_metadata_at(MetadataFailurePoint::AfterFrameSync))
            .and_then(|_| write_metadata_value(&self.root, &journal.pending, false))
            .and_then(|_| fail_metadata_at(MetadataFailurePoint::AfterMetadataPublish))
            .is_err()
        {
            data.failed = true;
            return Err(RoutingStateError::WriterFailure);
        }
        // From this marker onward the decision is durable and must be returned. Cleanup errors
        // are deliberately non-fatal: recovery accepts the committed marker and repeats cleanup.
        journal.phase = MetadataCommitPhase::Committed;
        if write_metadata_commit_journal_value(&self.root, &journal).is_err() {
            data.failed = true;
            return Err(RoutingStateError::WriterFailure);
        }
        let _ = fail_metadata_at(MetadataFailurePoint::AfterCommittedMarker);
        let _ = fs::remove_file(self.root.join(METADATA_COMMIT_JOURNAL));
        let _ = fail_metadata_at(MetadataFailurePoint::AfterJournalUnlink);
        let _ = sync_directory(&self.root);
        data.segments = segments;
        data.tasks.entry(task_ref.clone()).or_default().push(record);
        data.capacity_exhausted = false;
        Ok(RoutingStoredDecision {
            task_ref,
            step_id,
            profile_digest,
            target,
            reason,
            source,
            state_digest,
            decision_digest,
            replayed: false,
        })
    }

    pub fn active_tasks(&self) -> usize {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .tasks
            .len()
    }

    pub fn health(&self) -> RoutingStateHealth {
        let data = self
            .data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        RoutingStateHealth {
            ready: !data.failed && !data.capacity_exhausted,
            capacity_exhausted: data.capacity_exhausted,
            active_tasks: data.tasks.len(),
            active_task_capacity: self.limits.max_active_tasks,
            segments: data.segments.len(),
            segment_capacity: self.limits.max_segments,
        }
    }
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("routing digest value is serializable");
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(bytes);
    format!("sha256:{:x}", hash.finalize())
}

fn ensure_private_dir(path: &Path) -> Result<(), RoutingStateError> {
    if path.exists() {
        let meta = fs::symlink_metadata(path).map_err(|_| RoutingStateError::Io)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o777 != 0o700
            || meta.uid() != effective_uid()
        {
            return Err(RoutingStateError::UnsafePath);
        }
    } else {
        fs::create_dir_all(path).map_err(|_| RoutingStateError::Io)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| RoutingStateError::Io)?;
    }
    let meta = fs::symlink_metadata(path).map_err(|_| RoutingStateError::Io)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o777 != 0o700
        || meta.uid() != effective_uid()
    {
        return Err(RoutingStateError::UnsafePath);
    }
    Ok(())
}

fn acquire_writer_lock(root: &Path) -> Result<File, RoutingStateError> {
    let path = root.join("writer.lock");
    let file = open_private_file(&path, true, false)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => RoutingStateError::Locked,
        std::fs::TryLockError::Error(_) => RoutingStateError::Io,
    })?;
    Ok(file)
}

fn append_record(
    root: &Path,
    record: &StoredRecord,
    limits: RoutingStateLimits,
    existing: &[SegmentState],
) -> Result<Vec<SegmentState>, RoutingStateError> {
    let payload = serde_json::to_vec(record).map_err(|_| RoutingStateError::Invalid)?;
    let length = u32::try_from(payload.len()).map_err(|_| RoutingStateError::Invalid)?;
    let mut segments = planned_segments(record, limits, existing)?;
    if segments.len() > existing.len() {
        let index = segments.last().expect("planned rotation has segment").index;
        let path = segment_path(root, index);
        let _ = open_private_file(&path, true, true)?;
    }
    let active = segments.last_mut().expect("a segment was allocated");
    let path = segment_path(root, active.index);
    let mut file = open_private_file(&path, true, false)?;
    let mut crc = Hasher::new();
    crc.update(&payload);
    file.seek(SeekFrom::End(0))
        .and_then(|_| file.write_all(&length.to_be_bytes()))
        .and_then(|_| file.write_all(&crc.finalize().to_be_bytes()))
        .and_then(|_| file.write_all(&payload))
        .and_then(|_| file.sync_data())
        .map_err(|_| RoutingStateError::Io)?;
    Ok(segments)
}

fn planned_segments(
    record: &StoredRecord,
    limits: RoutingStateLimits,
    existing: &[SegmentState],
) -> Result<Vec<SegmentState>, RoutingStateError> {
    let payload = serde_json::to_vec(record).map_err(|_| RoutingStateError::Invalid)?;
    let frame_bytes = u64::try_from(payload.len())
        .map_err(|_| RoutingStateError::Invalid)?
        .checked_add(8)
        .ok_or(RoutingStateError::Invalid)?;
    if frame_bytes > limits.segment_bytes {
        return Err(RoutingStateError::Capacity);
    }
    let mut segments = existing.to_vec();
    let needs_rotation = segments
        .last()
        .is_none_or(|segment| segment.bytes.saturating_add(frame_bytes) > limits.segment_bytes);
    if needs_rotation {
        if segments.len() >= limits.max_segments as usize {
            return Err(RoutingStateError::Capacity);
        }
        let index = segments
            .last()
            .map(|segment| {
                segment
                    .index
                    .checked_add(1)
                    .ok_or(RoutingStateError::Capacity)
            })
            .transpose()?
            .unwrap_or(0);
        segments.push(SegmentState { index, bytes: 0 });
    }
    let active = segments.last_mut().expect("a segment was allocated");
    active.bytes = active
        .bytes
        .checked_add(frame_bytes)
        .ok_or(RoutingStateError::Capacity)?;
    Ok(segments)
}

fn recover(
    root: &Path,
    limits: RoutingStateLimits,
    salt: &[u8; 32],
) -> Result<StateData, RoutingStateError> {
    cleanup_orphan_temps(root)?;
    if let Some(journal) = load_metadata_commit_journal(root, limits, salt)? {
        recover_metadata_journal(root, limits, &journal, salt)?;
    }
    let metadata = load_metadata(root, limits, salt)?;
    let mut paths = segment_paths(root)?;
    if paths.len() > limits.max_segments as usize {
        return Err(RoutingStateError::Capacity);
    }
    paths.sort_by_key(|(index, _)| *index);
    if paths
        .iter()
        .enumerate()
        .any(|(position, (index, _))| *index != position as u32)
    {
        return Err(RoutingStateError::Corrupt);
    }
    let mut data = StateData::default();
    let committed = metadata
        .as_ref()
        .map(|metadata| metadata.segments.as_slice())
        .unwrap_or(&[]);
    if metadata.is_some() && paths.len() > committed.len() {
        // A failed rotation may have created a new uncommitted segment. Keeping the gateway
        // unavailable is safer than ever replaying a decision which the caller did not receive.
        return Err(RoutingStateError::Corrupt);
    }
    // Metadata is the sole durable commit point. Frames beyond the recorded byte boundary were
    // never returned to a caller, including the case where the metadata rename failed after a
    // segment sync. They must not become decisions after restart.
    for (position, segment) in committed.iter().enumerate() {
        let Some((index, path)) = paths.get(position) else {
            return Err(RoutingStateError::Corrupt);
        };
        if *index != segment.index {
            return Err(RoutingStateError::Corrupt);
        }
        // Check the descriptor-reported length before allocation or read. A hostile regular file
        // with a huge logical size must fail closed without asking the allocator to materialize it.
        let descriptor_len = fs::metadata(path).map_err(|_| RoutingStateError::Io)?.len();
        if descriptor_len > limits.segment_bytes {
            return Err(RoutingStateError::Corrupt);
        }
        let capacity = usize::try_from(descriptor_len).map_err(|_| RoutingStateError::Corrupt)?;
        let mut bytes = Vec::with_capacity(capacity);
        open_private_file(path, false, false)?
            .read_to_end(&mut bytes)
            .map_err(|_| RoutingStateError::Io)?;
        if segment.bytes > limits.segment_bytes || (bytes.len() as u64) < segment.bytes {
            return Err(RoutingStateError::Corrupt);
        }
        if bytes.len() as u64 > segment.bytes {
            if position + 1 != committed.len() {
                return Err(RoutingStateError::Corrupt);
            }
            repair_torn_tail(path, segment.bytes)?;
        }
        bytes.truncate(segment.bytes as usize);
        let (records, committed_bytes, torn) = decode_segment(&bytes)?;
        if torn {
            return Err(RoutingStateError::Corrupt);
        }
        for record in records {
            let history = data.tasks.entry(record.task_ref.clone()).or_default();
            if record.step_id != history.len() as u64 + 1 {
                return Err(RoutingStateError::Corrupt);
            }
            validate_record(
                &record,
                history.last().map(|prior| prior.state_digest.as_str()),
            )?;
            history.push(record);
        }
        data.segments.push(SegmentState {
            index: *index,
            bytes: committed_bytes as u64,
        });
    }
    // A missing metadata file occurs only before the first initialization. A lone final torn
    // tail in that state is the one allowed repair policy.
    if metadata.is_none() {
        if paths.len() > 1 {
            return Err(RoutingStateError::Corrupt);
        }
        if let Some((index, path)) = paths.first() {
            let descriptor_len = fs::metadata(path).map_err(|_| RoutingStateError::Io)?.len();
            if descriptor_len > limits.segment_bytes {
                return Err(RoutingStateError::Corrupt);
            }
            let capacity =
                usize::try_from(descriptor_len).map_err(|_| RoutingStateError::Corrupt)?;
            let mut bytes = Vec::with_capacity(capacity);
            open_private_file(path, false, false)?
                .read_to_end(&mut bytes)
                .map_err(|_| RoutingStateError::Io)?;
            let (records, committed_bytes, torn) = decode_segment(&bytes)?;
            if !torn {
                return Err(RoutingStateError::Corrupt);
            }
            repair_torn_tail(path, committed_bytes as u64)?;
            data.segments.push(SegmentState {
                index: *index,
                bytes: committed_bytes as u64,
            });
            if !records.is_empty() {
                return Err(RoutingStateError::Corrupt);
            }
        }
    }
    if data.tasks.len() > limits.max_active_tasks {
        return Err(RoutingStateError::Capacity);
    }
    if metadata.is_some_and(|metadata| !validate_metadata(&metadata, &data.segments)) {
        return Err(RoutingStateError::Corrupt);
    }
    Ok(data)
}

fn recover_metadata_journal(
    root: &Path,
    limits: RoutingStateLimits,
    journal: &MetadataCommitJournal,
    salt: &[u8; 32],
) -> Result<(), RoutingStateError> {
    let current = load_metadata(root, limits, salt)?;
    if journal.phase == MetadataCommitPhase::Committed {
        if current.as_ref() != Some(&journal.pending) {
            return Err(RoutingStateError::Corrupt);
        }
        fs::remove_file(root.join(METADATA_COMMIT_JOURNAL)).map_err(|_| RoutingStateError::Io)?;
        return sync_directory(root);
    }
    if current.as_ref() != Some(&journal.committed) && current.as_ref() != Some(&journal.pending) {
        return Err(RoutingStateError::Corrupt);
    }

    let mut paths = segment_paths(root)?;
    if paths.len() > limits.max_segments as usize {
        return Err(RoutingStateError::Capacity);
    }
    paths.sort_by_key(|(index, _)| *index);
    let committed = &journal.committed.segments;
    if paths.len() < committed.len()
        || paths
            .iter()
            .zip(committed)
            .any(|((index, _), metadata)| *index != metadata.index)
    {
        return Err(RoutingStateError::Corrupt);
    }
    match paths.get(committed.len()) {
        None if paths.len() == committed.len() => {}
        Some((index, path)) if paths.len() == committed.len() + 1 => {
            let expected = match committed.last() {
                Some(segment) => segment
                    .index
                    .checked_add(1)
                    .ok_or(RoutingStateError::Corrupt)?,
                None => 0,
            };
            if *index != expected {
                return Err(RoutingStateError::Corrupt);
            }
            validate_private_regular_file(path)?;
            fs::remove_file(path).map_err(|_| RoutingStateError::Io)?;
            sync_directory(root)?;
        }
        _ => return Err(RoutingStateError::Corrupt),
    }

    if current.as_ref() != Some(&journal.committed) {
        write_metadata_value(root, &journal.committed, false)?;
    }
    fs::remove_file(root.join(METADATA_COMMIT_JOURNAL)).map_err(|_| RoutingStateError::Io)?;
    sync_directory(root)
}

fn validate_record(
    record: &StoredRecord,
    prior_state: Option<&str>,
) -> Result<(), RoutingStateError> {
    if record.step_id == 0
        || record.task_ref.len() != "hmac-sha256:".len() + 64
        || !record.task_ref.starts_with("hmac-sha256:")
        || !valid_digest(&record.route_digest)
        || !valid_digest(&record.profile_digest)
        || (RoutingStep {
            signals: record.signals.clone(),
        })
        .validate()
        .is_err()
        || !bowline_core::routing::target_reason_coherent(record.reason, record.target)
    {
        return Err(RoutingStateError::Corrupt);
    }
    let expected_state = digest(
        b"bowline.routing.state.v1",
        &(
            prior_state.unwrap_or("empty"),
            &record.task_ref,
            record.step_id,
            &record.route_digest,
            &record.profile_digest,
            &record.signals,
            record.target,
            record.reason,
            record.source,
        ),
    );
    let expected_decision = digest(
        b"bowline.routing.decision.v1",
        &(
            &record.task_ref,
            record.step_id,
            &record.route_digest,
            &record.profile_digest,
            record.target,
            record.reason,
            record.source,
            &record.state_digest,
        ),
    );
    if record.state_digest != expected_state || record.decision_digest != expected_decision {
        return Err(RoutingStateError::Corrupt);
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    // Route/profile digests are produced by the validated enforcement bundle. The state store
    // keeps the representation opaque, but never permits an empty or non-domain value.
    value.starts_with("sha256:") && value.len() > "sha256:".len()
}

fn decode_segment(bytes: &[u8]) -> Result<(Vec<StoredRecord>, usize, bool), RoutingStateError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            return Ok((records, offset, true));
        }
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("slice length"))
            as usize;
        let expected = u32::from_be_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .expect("slice length"),
        );
        offset += 8;
        let end = offset.checked_add(len).ok_or(RoutingStateError::Corrupt)?;
        if end > bytes.len() {
            return Ok((records, offset - 8, true));
        }
        let payload = &bytes[offset..end];
        offset = end;
        let mut crc = Hasher::new();
        crc.update(payload);
        if crc.finalize() != expected {
            return Err(RoutingStateError::Corrupt);
        }
        let record: StoredRecord =
            serde_json::from_slice(payload).map_err(|_| RoutingStateError::Corrupt)?;
        records.push(record);
    }
    Ok((records, offset, false))
}

fn repair_torn_tail(path: &Path, committed_bytes: u64) -> Result<(), RoutingStateError> {
    let file = open_private_file(path, false, false)?;
    file.set_len(committed_bytes)
        .and_then(|_| file.sync_data())
        .map_err(|_| RoutingStateError::Io)
}

fn segment_paths(root: &Path) -> Result<Vec<(u32, PathBuf)>, RoutingStateError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| RoutingStateError::Io)? {
        let entry = entry.map_err(|_| RoutingStateError::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(RoutingStateError::UnsafePath)?;
        if let Some(index) = parse_segment_name(name) {
            let path = entry.path();
            validate_private_regular_file(&path)?;
            paths.push((index, path));
        } else if name == "writer.lock"
            || name == "metadata.json"
            || name == METADATA_COMMIT_JOURNAL
            || name == "salt"
            || is_metadata_temp(name)
            || is_journal_temp(name)
            || is_salt_temp(name)
        {
            validate_private_regular_file(&entry.path())?;
        } else {
            return Err(RoutingStateError::UnsafePath);
        }
    }
    Ok(paths)
}

fn segment_path(root: &Path, index: u32) -> PathBuf {
    root.join(format!("segment-{index:020}.log"))
}

fn parse_segment_name(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("segment-")?.strip_suffix(".log")?;
    (digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())?
}

fn open_private_file(
    path: &Path,
    create: bool,
    exclusive: bool,
) -> Result<File, RoutingStateError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_regular_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(RoutingStateError::Io),
    }
    let open = |create_new| {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(create_new)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.open(path)
    };
    let (file, created) = if exclusive {
        (open(true).map_err(|_| RoutingStateError::Io)?, true)
    } else {
        match open(false) {
            Ok(file) => (file, false),
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                (open(true).map_err(|_| RoutingStateError::Io)?, true)
            }
            Err(_) => return Err(RoutingStateError::Io),
        }
    };
    if created {
        let result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if result != 0 {
            return Err(RoutingStateError::Io);
        }
    }
    validate_private_regular_file(path)?;
    Ok(file)
}

fn validate_private_regular_file(path: &Path) -> Result<(), RoutingStateError> {
    let meta = fs::symlink_metadata(path).map_err(|_| RoutingStateError::Io)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o777 != 0o600
        || meta.uid() != effective_uid()
        || meta.nlink() != 1
    {
        return Err(RoutingStateError::UnsafePath);
    }
    Ok(())
}

// Both `StateMetadata` and `MetadataCommitJournal` carry `deny_unknown_fields`, so a strict parse
// of a directory written by a genuinely newer build (one that added a field along with its schema
// bump) fails on the unknown field before the version is ever compared, and the resulting
// `Corrupt` reads as "safe to reset" rather than "must not be deleted". These probes read only the
// version fields, ignoring anything else present, so the direction check always runs first.
#[derive(Deserialize)]
struct MetadataSchemaProbe {
    schema_version: u32,
}

#[derive(Deserialize)]
struct JournalSchemaProbe {
    schema_version: u32,
    committed: MetadataSchemaProbe,
    pending: MetadataSchemaProbe,
}

fn load_metadata(
    root: &Path,
    limits: RoutingStateLimits,
    salt: &[u8; 32],
) -> Result<Option<StateMetadata>, RoutingStateError> {
    let path = root.join("metadata.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_private_bounded(&path, max_metadata_bytes(limits))?;
    let probe: MetadataSchemaProbe =
        serde_json::from_slice(&bytes).map_err(|_| RoutingStateError::Corrupt)?;
    check_schema_direction(probe.schema_version)?;
    let metadata: StateMetadata =
        serde_json::from_slice(&bytes).map_err(|_| RoutingStateError::Corrupt)?;
    if !metadata_shape_is_valid(&metadata) {
        return Err(RoutingStateError::Corrupt);
    }
    if metadata.salt_digest != salt_fingerprint(salt) {
        return Err(RoutingStateError::SaltFingerprintMismatch);
    }
    Ok(Some(metadata))
}

fn load_metadata_commit_journal(
    root: &Path,
    limits: RoutingStateLimits,
    salt: &[u8; 32],
) -> Result<Option<MetadataCommitJournal>, RoutingStateError> {
    let path = root.join(METADATA_COMMIT_JOURNAL);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_private_bounded(&path, max_journal_bytes(limits))?;
    let probe: JournalSchemaProbe =
        serde_json::from_slice(&bytes).map_err(|_| RoutingStateError::Corrupt)?;
    check_journal_schema_direction(probe.schema_version)?;
    check_schema_direction(probe.committed.schema_version)?;
    check_schema_direction(probe.pending.schema_version)?;
    let journal: MetadataCommitJournal =
        serde_json::from_slice(&bytes).map_err(|_| RoutingStateError::Corrupt)?;
    if !metadata_shape_is_valid(&journal.committed)
        || !metadata_shape_is_valid(&journal.pending)
        || !metadata_commit_is_coherent(&journal.committed, &journal.pending)
    {
        return Err(RoutingStateError::Corrupt);
    }
    let expected = salt_fingerprint(salt);
    if journal.committed.salt_digest != expected || journal.pending.salt_digest != expected {
        return Err(RoutingStateError::SaltFingerprintMismatch);
    }
    Ok(Some(journal))
}

/// A store written under an older schema used an unkeyed task reference; its history is unreadable
/// under a salted derivation, and the one-time fix (delete the directory) is safe. A store written
/// under a *newer* schema is not something an older build may ever delete: a canary rollback to
/// this build must fail closed and say so distinctly, rather than repeat the older message and
/// invite an operator to destroy durable history the newer build could still read.
fn check_schema_direction(schema_version: u32) -> Result<(), RoutingStateError> {
    check_schema_direction_against(schema_version, ROUTING_STATE_SCHEMA_VERSION)
}

/// The commit-journal envelope carries its own schema version, independent of the `StateMetadata`
/// version it wraps. It has never needed a second revision, but a directory written by a build
/// that adds one must not be flattened into ordinary `Corrupt` any more than `StateMetadata` is.
const METADATA_COMMIT_JOURNAL_SCHEMA_VERSION: u32 = 1;

fn check_journal_schema_direction(schema_version: u32) -> Result<(), RoutingStateError> {
    check_schema_direction_against(schema_version, METADATA_COMMIT_JOURNAL_SCHEMA_VERSION)
}

fn check_schema_direction_against(
    schema_version: u32,
    expected: u32,
) -> Result<(), RoutingStateError> {
    if schema_version < expected {
        return Err(RoutingStateError::LegacyTaskReferenceSchema);
    }
    if schema_version > expected {
        return Err(RoutingStateError::NewerRoutingStateSchema);
    }
    Ok(())
}

fn max_metadata_bytes(limits: RoutingStateLimits) -> u64 {
    // Every segment entry has a fixed JSON schema and bounded decimal u32/u64 fields. The
    // generous constant leaves room for field names and whitespace without scaling with input.
    256 + u64::from(limits.max_segments) * 96
}

fn max_journal_bytes(limits: RoutingStateLimits) -> u64 {
    192 + max_metadata_bytes(limits).saturating_mul(2)
}

fn read_private_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, RoutingStateError> {
    let mut file = open_private_file(path, false, false)?;
    let metadata = file.metadata().map_err(|_| RoutingStateError::Io)?;
    let length = metadata.len();
    // Use descriptor metadata after O_NOFOLLOW open. A sparse regular file is never a valid
    // metadata object: accepting it would let a tiny allocation claim a huge logical payload.
    if length > maximum || metadata.blocks().saturating_mul(512) < length {
        return Err(RoutingStateError::Corrupt);
    }
    let capacity = usize::try_from(length).map_err(|_| RoutingStateError::Corrupt)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| RoutingStateError::Io)?;
    if bytes.len() as u64 != length || bytes.len() as u64 > maximum {
        return Err(RoutingStateError::Corrupt);
    }
    Ok(bytes)
}

fn metadata_shape_is_valid(metadata: &StateMetadata) -> bool {
    !metadata
        .segments
        .windows(2)
        .any(|window| window[0].index >= window[1].index)
        && metadata.active_segment == metadata.segments.last().map(|segment| segment.index)
}

fn metadata_commit_is_coherent(committed: &StateMetadata, pending: &StateMetadata) -> bool {
    if committed.salt_digest != pending.salt_digest {
        return false;
    }
    let committed_segments = &committed.segments;
    let pending_segments = &pending.segments;
    if pending_segments.len() == committed_segments.len() {
        let Some((pending_last, committed_last)) =
            pending_segments.last().zip(committed_segments.last())
        else {
            return false;
        };
        return pending_segments[..pending_segments.len() - 1]
            == committed_segments[..committed_segments.len() - 1]
            && pending_last.index == committed_last.index
            && pending_last.bytes > committed_last.bytes;
    }
    if pending_segments.len() != committed_segments.len() + 1
        || pending_segments[..committed_segments.len()] != committed_segments[..]
    {
        return false;
    }
    let expected_index = match committed_segments.last() {
        Some(segment) => match segment.index.checked_add(1) {
            Some(index) => index,
            None => return false,
        },
        None => 0,
    };
    pending_segments
        .last()
        .is_some_and(|segment| segment.index == expected_index && segment.bytes > 0)
}

fn validate_metadata(metadata: &StateMetadata, segments: &[SegmentState]) -> bool {
    metadata.segments.len() == segments.len()
        && metadata
            .segments
            .iter()
            .zip(segments)
            .all(|(metadata, segment)| {
                metadata.index == segment.index && metadata.bytes == segment.bytes
            })
}

fn write_metadata(
    root: &Path,
    segments: &[SegmentState],
    salt: &[u8; 32],
) -> Result<(), RoutingStateError> {
    write_metadata_value(root, &metadata_from_segments(segments, salt), false)
}

fn metadata_from_segments(segments: &[SegmentState], salt: &[u8; 32]) -> StateMetadata {
    StateMetadata {
        schema_version: ROUTING_STATE_SCHEMA_VERSION,
        segments: segments
            .iter()
            .map(|segment| MetadataSegment {
                index: segment.index,
                bytes: segment.bytes,
            })
            .collect(),
        active_segment: segments.last().map(|segment| segment.index),
        salt_digest: salt_fingerprint(salt),
    }
}

fn write_metadata_commit_journal(
    root: &Path,
    journal: &MetadataCommitJournal,
) -> Result<(), RoutingStateError> {
    let destination = root.join(METADATA_COMMIT_JOURNAL);
    if destination.exists() {
        return Err(RoutingStateError::Corrupt);
    }
    let bytes = serde_json::to_vec(journal).map_err(|_| RoutingStateError::Io)?;
    let temporary = root.join(format!(".routing-state-journal-{}.tmp", Uuid::new_v4()));
    let mut file = open_private_file(&temporary, true, true)?;
    fail_metadata_at(MetadataFailurePoint::BeforeJournalTempWrite)?;
    let split = bytes.len() / 2;
    file.write_all(&bytes[..split])
        .map_err(|_| RoutingStateError::Io)?;
    fail_metadata_at(MetadataFailurePoint::DuringJournalTempWrite)?;
    file.write_all(&bytes[split..])
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|_| RoutingStateError::Io)?;
    fail_metadata_at(MetadataFailurePoint::AfterJournalTempWrite)?;
    file.sync_all().map_err(|_| RoutingStateError::Io)?;
    fail_metadata_at(MetadataFailurePoint::AfterJournalTempSync)?;
    fs::rename(&temporary, &destination).map_err(|_| RoutingStateError::Io)?;
    fail_metadata_at(MetadataFailurePoint::AfterJournalRename)?;
    sync_directory(root)?;
    fail_metadata_at(MetadataFailurePoint::AfterJournalDirectorySync)
}

fn write_metadata_commit_journal_value(
    root: &Path,
    journal: &MetadataCommitJournal,
) -> Result<(), RoutingStateError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| RoutingStateError::Io)?;
    let destination = root.join(METADATA_COMMIT_JOURNAL);
    validate_private_regular_file(&destination)?;
    let temporary = root.join(format!(".routing-state-journal-{}.tmp", Uuid::new_v4()));
    let mut file = open_private_file(&temporary, true, true)?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|_| RoutingStateError::Io)?;
    fs::rename(&temporary, &destination).map_err(|_| RoutingStateError::Io)?;
    sync_directory(root)
}

fn write_metadata_value(
    root: &Path,
    metadata: &StateMetadata,
    _inject_failure: bool,
) -> Result<(), RoutingStateError> {
    let bytes = serde_json::to_vec(&metadata).map_err(|_| RoutingStateError::Io)?;
    let destination = root.join("metadata.json");
    if destination.exists() {
        validate_private_regular_file(&destination)?;
    }
    let temporary = root.join(format!(".routing-state-metadata-{}.tmp", Uuid::new_v4()));
    let mut file = open_private_file(&temporary, true, true)?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|_| RoutingStateError::Io)?;
    fs::rename(&temporary, &destination).map_err(|_| RoutingStateError::Io)?;
    sync_directory(root)?;
    Ok(())
}

fn load_or_create_salt(root: &Path) -> Result<[u8; 32], RoutingStateError> {
    if let Some(salt) = load_salt(root)? {
        return Ok(salt);
    }
    // A salt is only ever minted for a genuinely empty store. Minting one over surviving history
    // (metadata, a pending commit journal, or a segment) would silently start a second key: every
    // in-flight task would derive a reference that misses its recorded history, conflict forever,
    // and occupy `max_active_tasks` until the store wedges at capacity, with nothing here naming
    // the missing salt as the cause. Unlike a schema-version mismatch, this directory was written
    // by *this* build — the salt file itself was simply lost or never landed — so the fix is to
    // restore it, not to delete history a restored file could have recovered.
    if state_history_exists(root)? {
        return Err(RoutingStateError::MissingRoutingStateSalt);
    }
    let salt = generate_salt()?;
    write_salt(root, &salt)?;
    Ok(salt)
}

fn state_history_exists(root: &Path) -> Result<bool, RoutingStateError> {
    if root.join("metadata.json").exists() || root.join(METADATA_COMMIT_JOURNAL).exists() {
        return Ok(true);
    }
    for entry in fs::read_dir(root).map_err(|_| RoutingStateError::Io)? {
        let entry = entry.map_err(|_| RoutingStateError::Io)?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| parse_segment_name(name).is_some())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn load_salt(root: &Path) -> Result<Option<[u8; 32]>, RoutingStateError> {
    let path = root.join("salt");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_private_bounded(&path, 32)?;
    let salt: [u8; 32] = bytes.try_into().map_err(|_| RoutingStateError::Corrupt)?;
    // `generate_salt` already refuses to mint this value; reject it here too. A crash between
    // renaming a zeroed salt into place and publishing metadata otherwise lets the store adopt a
    // globally known key permanently, then stamp that key's own fingerprint into fresh metadata
    // so every later open agrees it is legitimate.
    if salt == [0u8; 32] {
        return Err(RoutingStateError::AllZeroRoutingStateSalt);
    }
    Ok(Some(salt))
}

fn generate_salt() -> Result<[u8; 32], RoutingStateError> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|_| RoutingStateError::Io)?;
    // A defence against a silently broken source: `getrandom` never returns success without
    // filling `salt`, so 32 zero bytes here means the backend is not actually producing randomness.
    if salt == [0u8; 32] {
        return Err(RoutingStateError::Io);
    }
    Ok(salt)
}

fn write_salt(root: &Path, salt: &[u8; 32]) -> Result<(), RoutingStateError> {
    let destination = root.join("salt");
    let temporary = root.join(format!(".routing-state-salt-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), RoutingStateError> {
        let mut file = open_private_file(&temporary, true, true)?;
        file.write_all(salt)
            .and_then(|_| file.sync_all())
            .map_err(|_| RoutingStateError::Io)?;
        fs::rename(&temporary, &destination).map_err(|_| RoutingStateError::Io)?;
        sync_directory(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Detects a replaced or lost `salt` file by binding `metadata.json` to the salt that wrote it.
/// Keyed by the salt itself so recovering the digest requires already holding the salt; it never
/// appears in a log, an error, or a response, and the salt cannot be recovered from it. Prefixed
/// `hmac-sha256:` rather than `sha256:` because it is keyed, matching `task_reference`'s wire
/// naming — an operator diagnosing a mismatch who runs `sha256sum salt` would otherwise find no
/// relation and conclude corruption rather than a replaced salt.
fn salt_fingerprint(salt: &[u8; 32]) -> String {
    let mac = bowline_core::routing::hmac_sha256(salt, b"bowline.routing.salt.v1");
    let mut fingerprint = String::with_capacity("hmac-sha256:".len() + mac.len() * 2);
    fingerprint.push_str("hmac-sha256:");
    for byte in mac {
        fingerprint.push_str(&format!("{byte:02x}"));
    }
    fingerprint
}

fn sync_directory(root: &Path) -> Result<(), RoutingStateError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RoutingStateError::Io)
}

// Every temp predicate requires a valid UUID body, not just the prefix and suffix, so a name a
// writer never produced (`.routing-state-metadata-not-a-uuid.tmp`) is neither silently swept nor
// silently accepted as a recognized file — it falls through to `UnsafePath`, the same as the
// journal counterpart this mirrors.
fn is_metadata_temp(name: &str) -> bool {
    metadata_temp_id(name).is_some()
}

fn metadata_temp_id(name: &str) -> Option<Uuid> {
    let id = name
        .strip_prefix(".routing-state-metadata-")?
        .strip_suffix(".tmp")?;
    Uuid::parse_str(id).ok()
}

fn is_salt_temp(name: &str) -> bool {
    salt_temp_id(name).is_some()
}

fn salt_temp_id(name: &str) -> Option<Uuid> {
    let id = name
        .strip_prefix(".routing-state-salt-")?
        .strip_suffix(".tmp")?;
    Uuid::parse_str(id).ok()
}

fn is_journal_temp(name: &str) -> bool {
    journal_temp_id(name).is_some()
}

fn journal_temp_id(name: &str) -> Option<Uuid> {
    let id = name
        .strip_prefix(".routing-state-journal-")?
        .strip_suffix(".tmp")?;
    Uuid::parse_str(id).ok()
}

/// Sweeps every kind of private temp file this store creates: a crash between `create` and
/// `rename` in the journal, metadata, or salt writers otherwise leaves that temp forever, one per
/// crash, and a salt temp is a 32-byte key-shaped file.
fn cleanup_orphan_temps(root: &Path) -> Result<(), RoutingStateError> {
    let mut removed = false;
    for entry in fs::read_dir(root).map_err(|_| RoutingStateError::Io)? {
        let entry = entry.map_err(|_| RoutingStateError::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(RoutingStateError::UnsafePath)?;
        if journal_temp_id(name).is_some() || is_salt_temp(name) || is_metadata_temp(name) {
            let path = entry.path();
            validate_private_regular_file(&path)?;
            fs::remove_file(path).map_err(|_| RoutingStateError::Io)?;
            removed = true;
        }
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowline_core::routing::{RoutingTarget, StageProfileKind};
    fn profile() -> StageRoutingProfile {
        StageRoutingProfile {
            profile_id: "stage".into(),
            kind: StageProfileKind::Stage,
            recent_window: 4,
            error_threshold: 2,
            exploration_threshold: 2,
            progress_threshold: 2,
            default_target: RoutingTarget::Capable,
        }
    }

    #[test]
    fn metadata_publish_failure_never_replays_an_unreturned_same_segment_decision() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();

        inject_metadata_failure(MetadataFailurePoint::AfterMetadataPublish);
        assert!(matches!(
            store.decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            ),
            Err(RoutingStateError::WriterFailure)
        ));
        drop(store);

        let reopened = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        let decision = reopened
            .decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        assert_eq!(decision.target, RoutingTarget::Efficient);
        assert!(!decision.replayed);
    }

    #[test]
    fn metadata_sync_failure_removes_only_an_uncommitted_rotated_segment() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 640,
            // This makes the schema-derived bound larger than one filesystem block, so
            // set_len creates a detectable sparse hole while still staying within the bound.
            max_segments: 128,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();

        inject_metadata_failure(MetadataFailurePoint::AfterMetadataPublish);
        assert!(matches!(
            store.decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            ),
            Err(RoutingStateError::WriterFailure)
        ));
        drop(store);

        let root = dir.path().join("routing-state");
        assert!(segment_path(&root, 1).exists());
        let reopened = RoutingStateStore::open(dir.path(), limits).unwrap();
        assert_eq!(reopened.active_tasks(), 1);
        assert!(!segment_path(&root, 1).exists());
        let decision = reopened
            .decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        assert_eq!(decision.target, RoutingTarget::Efficient);
        assert!(!decision.replayed);
    }

    #[test]
    fn unexpected_extra_segment_is_corrupt_without_an_uncommitted_metadata_marker() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 640,
            max_segments: 3,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);

        let root = dir.path().join("routing-state");
        open_private_file(&segment_path(&root, 1), true, true).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), limits),
            Err(RoutingStateError::Corrupt)
        ));
    }

    #[test]
    fn oversized_segment_is_rejected_before_recovery_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 640,
            max_segments: 1,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);

        let segment = segment_path(&dir.path().join("routing-state"), 0);
        OpenOptions::new()
            .write(true)
            .open(&segment)
            .unwrap()
            .set_len(limits.segment_bytes + 1)
            .unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), limits),
            Err(RoutingStateError::Corrupt)
        ));
    }

    #[test]
    fn oversized_and_sparse_metadata_files_are_rejected_before_reading() {
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 640,
            // This makes the schema-derived bound larger than one filesystem block, so
            // set_len creates a detectable sparse hole while still staying within the bound.
            max_segments: 128,
        };
        for (name, maximum) in [
            ("metadata.json", max_metadata_bytes(limits)),
            (METADATA_COMMIT_JOURNAL, max_journal_bytes(limits)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = RoutingStateStore::open(dir.path(), limits).unwrap();
            drop(store);
            let path = dir.path().join("routing-state").join(name);
            if !path.exists() {
                open_private_file(&path, true, true).unwrap();
            }
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(maximum + 1)
                .unwrap();
            assert!(matches!(
                RoutingStateStore::open(dir.path(), limits),
                Err(RoutingStateError::Corrupt)
            ));

            let dir = tempfile::tempdir().unwrap();
            let store = RoutingStateStore::open(dir.path(), limits).unwrap();
            drop(store);
            let path = dir.path().join("routing-state").join(name);
            if !path.exists() {
                open_private_file(&path, true, true).unwrap();
            }
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(maximum)
                .unwrap();
            assert!(matches!(
                RoutingStateStore::open(dir.path(), limits),
                Err(RoutingStateError::Corrupt)
            ));
        }
    }

    fn assert_rollback_fault_never_replays_unreturned(
        limits: RoutingStateLimits,
        point: MetadataFailurePoint,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        inject_metadata_failure(point);
        assert!(matches!(
            store.decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            ),
            Err(RoutingStateError::WriterFailure)
        ));
        drop(store);
        let reopened = RoutingStateStore::open(dir.path(), limits).unwrap();
        assert!(
            !reopened
                .decide(
                    "task",
                    2,
                    "sha256:route",
                    &profile(),
                    vec![RoutingSignal::Write],
                )
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn rollback_faults_never_replay_unreturned_same_segment_or_rotation_decisions() {
        for point in [
            MetadataFailurePoint::BeforeSegmentMutation,
            MetadataFailurePoint::AfterFrameSync,
            MetadataFailurePoint::AfterMetadataPublish,
        ] {
            assert_rollback_fault_never_replays_unreturned(RoutingStateLimits::default(), point);
            assert_rollback_fault_never_replays_unreturned(
                RoutingStateLimits {
                    max_active_tasks: 8,
                    segment_bytes: 640,
                    max_segments: 3,
                },
                point,
            );
        }
    }

    #[test]
    fn atomic_initial_journal_faults_recover_prior_prefix_for_same_segment_and_rotation() {
        for point in [
            MetadataFailurePoint::BeforeJournalTempWrite,
            MetadataFailurePoint::DuringJournalTempWrite,
            MetadataFailurePoint::AfterJournalTempWrite,
            MetadataFailurePoint::AfterJournalTempSync,
            MetadataFailurePoint::AfterJournalRename,
            MetadataFailurePoint::AfterJournalDirectorySync,
            MetadataFailurePoint::BeforeSegmentMutation,
        ] {
            assert_rollback_fault_never_replays_unreturned(RoutingStateLimits::default(), point);
            assert_rollback_fault_never_replays_unreturned(
                RoutingStateLimits {
                    max_active_tasks: 8,
                    segment_bytes: 640,
                    max_segments: 3,
                },
                point,
            );
        }
    }

    #[test]
    fn only_an_exact_private_journal_temp_is_removed_during_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let root = dir.path().join("routing-state");
        let temporary = root.join(format!(".routing-state-journal-{}.tmp", Uuid::new_v4()));
        open_private_file(&temporary, true, true).unwrap();
        RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert!(!temporary.exists());

        let invalid = root.join(".routing-state-journal-not-a-uuid.tmp");
        open_private_file(&invalid, true, true).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::UnsafePath)
        ));
    }

    fn assert_committed_cleanup_fault_preserves_returned_decision(
        limits: RoutingStateLimits,
        point: MetadataFailurePoint,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        inject_metadata_failure(point);
        let accepted = store
            .decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);
        let reopened = RoutingStateStore::open(dir.path(), limits).unwrap();
        let replay = reopened
            .decide(
                "task",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(accepted.decision_digest, replay.decision_digest);
    }

    #[test]
    fn committed_marker_and_cleanup_faults_preserve_returned_decisions() {
        for point in [
            MetadataFailurePoint::AfterCommittedMarker,
            MetadataFailurePoint::AfterJournalUnlink,
        ] {
            assert_committed_cleanup_fault_preserves_returned_decision(
                RoutingStateLimits::default(),
                point,
            );
            assert_committed_cleanup_fault_preserves_returned_decision(
                RoutingStateLimits {
                    max_active_tasks: 8,
                    segment_bytes: 640,
                    max_segments: 3,
                },
                point,
            );
        }
    }

    #[test]
    fn unavailable_error_causes_are_stable() {
        assert_eq!(
            RoutingStateError::StepConflict.unavailable_cause(),
            Some(RoutingUnavailableCauseV3::StepConflict)
        );
        assert_eq!(
            RoutingStateError::Capacity.unavailable_cause(),
            Some(RoutingUnavailableCauseV3::CapacityExhausted)
        );
        assert_eq!(
            RoutingStateError::Corrupt.startup_unavailable_cause(),
            RoutingUnavailableCauseV3::StateCorrupt
        );
        assert_eq!(
            RoutingStateError::WriterFailure.unavailable_cause(),
            Some(RoutingUnavailableCauseV3::WriterFailure)
        );
        assert_eq!(
            RoutingStateError::Io.startup_unavailable_cause(),
            RoutingUnavailableCauseV3::StartupUnavailable
        );
    }
    #[test]
    fn exact_replay_is_idempotent_and_conflicts_do_not_mutate() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        let first = store
            .decide(
                "task-1",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        assert!(!first.replayed);
        assert!(store
            .decide(
                "task-1",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::TestFailed]
            )
            .is_err());
        let replay = store
            .decide(
                "task-1",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(first.decision_digest, replay.decision_digest);
        assert!(store
            .decide("task-1", 3, "sha256:route", &profile(), vec![])
            .is_err());
    }
    #[test]
    fn state_recovers_without_raw_task_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        store
            .decide(
                "private-task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);
        for entry in fs::read_dir(dir.path().join("routing-state")).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes
                .windows(b"private-task".len())
                .any(|window| window == b"private-task"));
        }
        let reopened = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert_eq!(reopened.active_tasks(), 1);
    }

    #[test]
    fn a_pre_salt_schema_prefix_refuses_to_open_instead_of_mixing_derivations() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let path = dir.path().join("routing-state").join("metadata.json");
        // The schema this repeats is the field shape a store wrote before task references were
        // salted. Recovery must not treat this as ordinary corruption: mistaking it for `Corrupt`
        // would invite an operator to "recover" a directory whose `task_ref` values were derived
        // under a different, unkeyed algorithm.
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{"schema_version":2,"segments":[],"active_segment":null}"#)
            .unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::LegacyTaskReferenceSchema)
        ));
    }

    #[test]
    fn deleting_the_salt_after_history_exists_names_the_salt_as_missing_rather_than_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);

        let root = dir.path().join("routing-state");
        fs::remove_file(root.join("salt")).unwrap();
        // A fresh mint here would derive new, unrelated references over the surviving history
        // rather than refuse outright. The directory was written by this build, not an older
        // schema, so the error must name the missing file rather than recommend a reset that
        // would destroy history a restored salt file could have recovered.
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::MissingRoutingStateSalt)
        ));
    }

    #[test]
    fn an_all_zero_salt_file_refuses_to_open_even_before_any_history_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);

        let root = dir.path().join("routing-state");
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(root.join("salt"))
            .unwrap()
            .write_all(&[0u8; 32])
            .unwrap();
        // A crash between renaming a zeroed salt into place and publishing metadata must not let
        // the store silently adopt a globally known key and stamp its fingerprint as if it were
        // legitimate.
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::AllZeroRoutingStateSalt)
        ));
    }

    #[test]
    fn a_newer_schema_with_an_added_field_yields_the_newer_schema_error_not_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let path = dir.path().join("routing-state").join("metadata.json");
        let mut newer: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        newer["schema_version"] = serde_json::Value::from(ROUTING_STATE_SCHEMA_VERSION + 1);
        // A future release bumping the version *because* it added a field is exactly the case
        // where `deny_unknown_fields` must not turn this into `Corrupt` before the direction
        // check ever runs — that would tell an operator rolling back that the directory is safe
        // to reset when it is not.
        newer["reserved_for_a_later_release"] = serde_json::Value::from("placeholder");
        fs::write(&path, serde_json::to_vec(&newer).unwrap()).unwrap();

        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::NewerRoutingStateSchema)
        ));
    }

    #[test]
    fn the_salt_fingerprint_matches_a_known_hmac_sha256_vector() {
        // Verified independently against a reference HMAC-SHA256 implementation. Pins the
        // composed `salt_fingerprint` output (domain string and `hmac-sha256:` prefix included),
        // independent of whether the underlying HMAC is this crate's own or shared with
        // `bowline_core::routing`.
        assert_eq!(
            salt_fingerprint(&[7u8; 32]),
            "hmac-sha256:bbaa95d62ccdec816a5050577395feb0f716862f1bead5b3904bf7be9821fae2"
        );
    }

    #[test]
    fn a_replaced_salt_refuses_to_open_via_the_fingerprint_guard() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);

        let root = dir.path().join("routing-state");
        // The salt file itself is intact and well-formed, so `load_salt` succeeds; only the
        // fingerprint recorded in metadata.json can catch the swap.
        let replacement = [9u8; 32];
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(root.join("salt"))
            .unwrap()
            .write_all(&replacement)
            .unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::SaltFingerprintMismatch)
        ));
    }

    #[test]
    fn a_newer_schema_is_distinguished_from_an_older_one_and_neither_shares_a_message() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let path = dir.path().join("routing-state").join("metadata.json");
        let base: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        let mut newer = base.clone();
        newer["schema_version"] = serde_json::Value::from(ROUTING_STATE_SCHEMA_VERSION + 1);
        fs::write(&path, serde_json::to_vec(&newer).unwrap()).unwrap();
        let newer_result = RoutingStateStore::open(dir.path(), RoutingStateLimits::default());

        let mut older = base;
        older["schema_version"] = serde_json::Value::from(ROUTING_STATE_SCHEMA_VERSION - 1);
        fs::write(&path, serde_json::to_vec(&older).unwrap()).unwrap();
        let older_result = RoutingStateStore::open(dir.path(), RoutingStateLimits::default());

        let newer_error = match newer_result {
            Err(error) => error,
            Ok(_) => panic!("expected the newer-schema guard to refuse"),
        };
        let older_error = match older_result {
            Err(error) => error,
            Ok(_) => panic!("expected the legacy-schema guard to refuse"),
        };
        assert_eq!(newer_error, RoutingStateError::NewerRoutingStateSchema);
        assert_eq!(older_error, RoutingStateError::LegacyTaskReferenceSchema);
        assert_ne!(newer_error, older_error);
        assert_ne!(newer_error.to_string(), older_error.to_string());
        assert!(
            newer_error.to_string().contains("must not"),
            "a newer directory's message must not read as safe to delete"
        );
    }

    #[test]
    fn a_stray_salt_temp_is_swept_at_recovery_and_open_still_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let root = dir.path().join("routing-state");
        let stray = root.join(format!(".routing-state-salt-{}.tmp", Uuid::new_v4()));
        open_private_file(&stray, true, true).unwrap();
        assert!(stray.exists());

        RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert!(!stray.exists());
    }

    #[test]
    fn a_stray_metadata_temp_is_swept_at_recovery_and_open_still_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let root = dir.path().join("routing-state");
        let stray = root.join(format!(".routing-state-metadata-{}.tmp", Uuid::new_v4()));
        open_private_file(&stray, true, true).unwrap();
        assert!(stray.exists());

        RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert!(!stray.exists());
    }

    #[test]
    fn a_malformed_metadata_temp_name_is_not_silently_swept() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        drop(store);
        let root = dir.path().join("routing-state");
        // Bare prefix-plus-suffix matching would silently delete this at every open; the journal
        // predicate has always required a valid UUID body, and the metadata predicate must too.
        let invalid = root.join(".routing-state-metadata-not-a-uuid.tmp");
        open_private_file(&invalid, true, true).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::UnsafePath)
        ));
    }

    #[test]
    fn recovery_preserves_decision_source_and_rejects_semantic_record_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        store
            .decide_with_source(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![],
                RoutingDecisionSourceV3::LocalDecisionApi,
            )
            .unwrap();
        drop(store);
        let reopened = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert_eq!(
            reopened
                .decide("task", 1, "sha256:route", &profile(), vec![])
                .unwrap()
                .source,
            RoutingDecisionSourceV3::LocalDecisionApi
        );
        drop(reopened);

        let root = dir.path().join("routing-state");
        let segment = segment_path(&root, 0);
        let mut frame = fs::read(&segment).unwrap();
        let payload_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let mut record: serde_json::Value =
            serde_json::from_slice(&frame[8..8 + payload_len]).unwrap();
        record["reason"] = serde_json::Value::String("recent-progress".into());
        let payload = serde_json::to_vec(&record).unwrap();
        assert_eq!(payload.len(), payload_len);
        let mut crc = Hasher::new();
        crc.update(&payload);
        frame[4..8].copy_from_slice(&crc.finalize().to_be_bytes());
        frame[8..8 + payload_len].copy_from_slice(&payload);
        fs::write(segment, frame).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::Corrupt)
        ));
    }

    #[test]
    fn configured_capacity_refuses_new_history_without_deleting_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 640,
            max_segments: 1,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task-1",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        assert!(matches!(
            store.decide(
                "task-2",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write]
            ),
            Err(RoutingStateError::Capacity)
        ));
        assert_eq!(store.active_tasks(), 1);
    }

    #[test]
    fn a_saturated_store_reports_not_ready_rather_than_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 640,
            max_segments: 1,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        assert!(store.health().ready, "a fresh store is ready");

        // This release does not reclaim, so the store stops at its budget. Readiness has to say so:
        // a gateway that silently pins every routed request to the capable supply is not healthy.
        let mut refusal = None;
        for index in 0..64u64 {
            let task_id = format!("task-{index}");
            if let Err(error) = store.decide(
                &task_id,
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            ) {
                refusal = Some(error);
                break;
            }
        }
        assert!(
            matches!(refusal, Some(RoutingStateError::Capacity)),
            "the store must refuse for capacity"
        );

        let health = store.health();
        assert!(!health.ready, "a store refusing new history is not ready");
        assert!(health.capacity_exhausted);
    }

    #[test]
    fn a_capacity_refusal_clears_once_the_store_commits_again() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 1,
            segment_bytes: 1 << 20,
            max_segments: 16,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task-one",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();

        // A second task exceeds the task cap and is refused.
        assert!(matches!(
            store.decide(
                "task-two",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write]
            ),
            Err(RoutingStateError::Capacity)
        ));
        assert!(!store.health().ready);

        // The established task can still continue, so the store is working again and must say so.
        store
            .decide(
                "task-one",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        let health = store.health();
        assert!(health.ready, "a store that just committed is ready");
        assert!(!health.capacity_exhausted);
    }

    #[test]
    fn rotates_segments_and_recovers_all_valid_history_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            // Two framed routing records do not fit in one 640-byte segment, so each accepted
            // decision forces a new segment rather than sharing one with the record before it.
            segment_bytes: 640,
            max_segments: 3,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        store
            .decide(
                "task-one",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        store
            .decide(
                "task-two",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);

        let root = dir.path().join("routing-state");
        let segment_count = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("segment-"))
            .count();
        assert_eq!(segment_count, 2);
        let reopened = RoutingStateStore::open(dir.path(), limits).unwrap();
        assert_eq!(reopened.active_tasks(), 2);
        assert!(
            reopened
                .decide(
                    "task-one",
                    1,
                    "sha256:route",
                    &profile(),
                    vec![RoutingSignal::Write]
                )
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn only_a_final_torn_tail_is_repaired_and_crc_damage_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        store
            .decide(
                "task",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .unwrap();
        drop(store);
        let root = dir.path().join("routing-state");
        let segment = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("segment-")
            })
            .unwrap();
        let original_len = fs::metadata(&segment).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(&[0, 0, 0])
            .unwrap();
        let reopened = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert_eq!(reopened.active_tasks(), 1);
        assert_eq!(fs::metadata(&segment).unwrap().len(), original_len);
        drop(reopened);

        let mut bytes = fs::read(&segment).unwrap();
        bytes[4] ^= 1;
        fs::write(&segment, bytes).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::Corrupt)
        ));
    }

    #[test]
    fn private_paths_and_exclusive_writer_ownership_are_required() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let store = RoutingStateStore::open(dir.path(), RoutingStateLimits::default()).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::Locked)
        ));
        drop(store);

        let root = dir.path().join("routing-state");
        fs::set_permissions(root.join("writer.lock"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::UnsafePath)
        ));
        fs::set_permissions(root.join("writer.lock"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            RoutingStateStore::open(dir.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::UnsafePath)
        ));

        let symlink_root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), symlink_root.path().join("routing-state")).unwrap();
        assert!(matches!(
            RoutingStateStore::open(symlink_root.path(), RoutingStateLimits::default()),
            Err(RoutingStateError::UnsafePath)
        ));
    }
}

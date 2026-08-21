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
    /// Least-recently-used first. Every committed decision moves its task to the back. Rebuilt
    /// deterministically by `recover()` by replaying commits in order, so it never needs its own
    /// durable representation.
    tasks_order: std::collections::VecDeque<String>,
    /// The segment index holding each currently-retained task's first record. A reused task id
    /// overwrites its entry when refounded, so a stale founding segment can never evict a task's
    /// current history.
    task_founding_segment: BTreeMap<String, u32>,
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
            Self::UnsafePath | Self::Io | Self::Locked | Self::Invalid => None,
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
        let data = recover(&root, limits)?;
        write_metadata(&root, &data.segments)?;
        Ok(Self {
            root,
            limits,
            data: Mutex::new(data),
            _writer_lock: writer_lock,
        })
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
        let task_ref = task_reference(task_id).map_err(|_| RoutingStateError::Invalid)?;
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
        let task_is_new = history.is_none();
        if task_is_new && data.tasks.len() >= self.limits.max_active_tasks {
            // Evict the least recently used task rather than refusing forever. An evicted task
            // that returns mid-flight sees a step conflict, which already retains the capable
            // target.
            if let Some(evicted) = data.tasks_order.pop_front() {
                data.tasks.remove(&evicted);
                data.task_founding_segment.remove(&evicted);
            }
        }
        let history = data.tasks.get(&task_ref);
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
            Err(RoutingStateError::Capacity) => return Err(RoutingStateError::Capacity),
            Err(_) => {
                data.failed = true;
                return Err(RoutingStateError::WriterFailure);
            }
        };
        // Segments present before this plan but absent from it were rolled off the front to make
        // room for the rotation. Every task whose retained history began in one is evicted once
        // this commit is durable.
        let rolled_off: Vec<u32> = data
            .segments
            .iter()
            .filter(|old| !segments.iter().any(|new| new.index == old.index))
            .map(|old| old.index)
            .collect();
        let mut journal = MetadataCommitJournal {
            schema_version: 1,
            phase: MetadataCommitPhase::Rollback,
            committed: metadata_from_segments(&data.segments),
            pending: metadata_from_segments(&segments),
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
        // Eviction and cleanup below are best-effort bookkeeping: the commit above is already
        // durable, and a crash here leaves stale segment files that the next `recover()` unlinks
        // and stale task entries that the next `recover()` rebuilds identically by replay. The
        // task in this very decision is excluded: its full history is already held above and
        // remains valid for the life of this process, even though the segment holding its
        // earliest steps is gone. Only a restart re-derives state from disk and, having no step
        // one for it there, starts it over.
        if !rolled_off.is_empty() {
            let mut evicted_tasks: Vec<String> = Vec::new();
            for (candidate, founding_segment) in &data.task_founding_segment {
                if candidate != &task_ref && rolled_off.contains(founding_segment) {
                    evicted_tasks.push(candidate.clone());
                }
            }
            for evicted in &evicted_tasks {
                data.tasks.remove(evicted);
                data.task_founding_segment.remove(evicted);
            }
            data.tasks_order
                .retain(|candidate| !evicted_tasks.contains(candidate));
            for index in &rolled_off {
                let _ = fs::remove_file(segment_path(&self.root, *index));
            }
        }
        if task_is_new {
            let active_index = segments.last().expect("a segment was allocated").index;
            data.task_founding_segment
                .insert(task_ref.clone(), active_index);
        }
        data.segments = segments;
        data.tasks.entry(task_ref.clone()).or_default().push(record);
        data.tasks_order.retain(|candidate| candidate != &task_ref);
        data.tasks_order.push_back(task_ref.clone());
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
            ready: !data.failed,
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
        // The next index is derived from the pre-roll-off tail so it can never collide with an
        // index this same commit is about to drop: segment indices only ever increase.
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
        // A full store no longer refuses new history: the oldest segment rolls off to make room.
        // The caller evicts every task whose retained history began there once this commit lands.
        while segments.len() >= limits.max_segments as usize {
            segments.remove(0);
        }
        segments.push(SegmentState { index, bytes: 0 });
    }
    let active = segments.last_mut().expect("a segment was allocated");
    active.bytes = active
        .bytes
        .checked_add(frame_bytes)
        .ok_or(RoutingStateError::Capacity)?;
    Ok(segments)
}

fn recover(root: &Path, limits: RoutingStateLimits) -> Result<StateData, RoutingStateError> {
    cleanup_orphan_journal_temps(root)?;
    if let Some(journal) = load_metadata_commit_journal(root, limits)? {
        recover_metadata_journal(root, limits, &journal)?;
    }
    let metadata = load_metadata(root, limits)?;
    let committed = metadata
        .as_ref()
        .map(|metadata| metadata.segments.as_slice())
        .unwrap_or(&[]);
    // A crash between the metadata commit publishing a roll-off and this store unlinking the
    // rolled-off files leaves them on disk with an index below the committed prefix. They hold
    // no state any live commit still references, so removing them here is the same best-effort
    // cleanup a successful commit already performs, just retried at open.
    cleanup_rolled_off_segments(root, committed)?;
    let mut paths = segment_paths(root)?;
    if paths.len() > limits.max_segments as usize {
        return Err(RoutingStateError::Capacity);
    }
    paths.sort_by_key(|(index, _)| *index);
    let mut data = StateData::default();
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
            let task_ref = record.task_ref.clone();
            let task_is_new = !data.tasks.contains_key(&task_ref);
            if task_is_new && record.step_id != 1 {
                // No prior history and this is not a founding record: the segment that held its
                // earlier steps already rolled off before this open. The live store evicted this
                // task the moment that happened; replay reaches the identical state by silently
                // dropping the orphaned tail instead of treating it as corruption.
                continue;
            }
            if task_is_new && data.tasks.len() >= limits.max_active_tasks {
                if let Some(evicted) = data.tasks_order.pop_front() {
                    data.tasks.remove(&evicted);
                    data.task_founding_segment.remove(&evicted);
                }
            }
            let history = data.tasks.entry(task_ref.clone()).or_default();
            if record.step_id != history.len() as u64 + 1 {
                return Err(RoutingStateError::Corrupt);
            }
            validate_record(
                &record,
                history.last().map(|prior| prior.state_digest.as_str()),
            )?;
            history.push(record);
            data.tasks_order.retain(|candidate| candidate != &task_ref);
            data.tasks_order.push_back(task_ref.clone());
            if task_is_new {
                data.task_founding_segment.insert(task_ref, *index);
            }
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
            // No metadata has ever been committed, so no rotation and no roll-off has ever
            // happened: the only legitimate first segment is index 0.
            if *index != 0 {
                return Err(RoutingStateError::Corrupt);
            }
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
) -> Result<(), RoutingStateError> {
    let current = load_metadata(root, limits)?;
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
        || record.task_ref.len() != "sha256:".len() + 64
        || !record.task_ref.starts_with("sha256:")
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
            || is_metadata_temp(name)
            || is_journal_temp(name)
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

fn cleanup_rolled_off_segments(
    root: &Path,
    committed: &[MetadataSegment],
) -> Result<(), RoutingStateError> {
    let Some(floor) = committed.first().map(|segment| segment.index) else {
        // Nothing has ever been committed, so nothing has ever rolled off.
        return Ok(());
    };
    let mut removed = false;
    for (index, path) in segment_paths(root)? {
        if index < floor {
            validate_private_regular_file(&path)?;
            fs::remove_file(&path).map_err(|_| RoutingStateError::Io)?;
            removed = true;
        }
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
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

fn load_metadata(
    root: &Path,
    limits: RoutingStateLimits,
) -> Result<Option<StateMetadata>, RoutingStateError> {
    let path = root.join("metadata.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_private_bounded(&path, max_metadata_bytes(limits))?;
    let metadata: StateMetadata =
        serde_json::from_slice(&bytes).map_err(|_| RoutingStateError::Corrupt)?;
    if !metadata_shape_is_valid(&metadata) {
        return Err(RoutingStateError::Corrupt);
    }
    Ok(Some(metadata))
}

fn load_metadata_commit_journal(
    root: &Path,
    limits: RoutingStateLimits,
) -> Result<Option<MetadataCommitJournal>, RoutingStateError> {
    let path = root.join(METADATA_COMMIT_JOURNAL);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_private_bounded(&path, max_journal_bytes(limits))?;
    let journal: MetadataCommitJournal =
        serde_json::from_slice(&bytes).map_err(|_| RoutingStateError::Corrupt)?;
    if journal.schema_version != 1
        || !metadata_shape_is_valid(&journal.committed)
        || !metadata_shape_is_valid(&journal.pending)
        || !metadata_commit_is_coherent(&journal.committed, &journal.pending)
    {
        return Err(RoutingStateError::Corrupt);
    }
    Ok(Some(journal))
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
    metadata.schema_version == 2
        && !metadata
            .segments
            .windows(2)
            .any(|window| window[0].index >= window[1].index)
        && metadata.active_segment == metadata.segments.last().map(|segment| segment.index)
}

fn metadata_commit_is_coherent(committed: &StateMetadata, pending: &StateMetadata) -> bool {
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
    // Every other coherent transition appends exactly one new segment, optionally rolling the
    // oldest `dropped` segments off the front in the same commit (roll-off is `dropped >= 1`;
    // an ordinary rotation is `dropped == 0`).
    if pending_segments.is_empty() || pending_segments.len() > committed_segments.len() + 1 {
        return false;
    }
    let dropped = committed_segments.len() + 1 - pending_segments.len();
    if pending_segments[..pending_segments.len() - 1] != committed_segments[dropped..] {
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

fn write_metadata(root: &Path, segments: &[SegmentState]) -> Result<(), RoutingStateError> {
    write_metadata_value(root, &metadata_from_segments(segments), false)
}

fn metadata_from_segments(segments: &[SegmentState]) -> StateMetadata {
    StateMetadata {
        schema_version: 2,
        segments: segments
            .iter()
            .map(|segment| MetadataSegment {
                index: segment.index,
                bytes: segment.bytes,
            })
            .collect(),
        active_segment: segments.last().map(|segment| segment.index),
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

fn sync_directory(root: &Path) -> Result<(), RoutingStateError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RoutingStateError::Io)
}

fn is_metadata_temp(name: &str) -> bool {
    name.starts_with(".routing-state-metadata-") && name.ends_with(".tmp")
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

fn cleanup_orphan_journal_temps(root: &Path) -> Result<(), RoutingStateError> {
    let mut removed = false;
    for entry in fs::read_dir(root).map_err(|_| RoutingStateError::Io)? {
        let entry = entry.map_err(|_| RoutingStateError::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(RoutingStateError::UnsafePath)?;
        if journal_temp_id(name).is_some() {
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

    fn decide_once(
        store: &RoutingStateStore,
        task_id: &str,
        step_id: u64,
    ) -> Result<RoutingStoredDecision, RoutingStateError> {
        store.decide(
            task_id,
            step_id,
            "sha256:route",
            &profile(),
            vec![RoutingSignal::Write],
        )
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
            segment_bytes: 512,
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
            segment_bytes: 512,
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
            segment_bytes: 512,
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
            segment_bytes: 512,
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
                    segment_bytes: 512,
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
                    segment_bytes: 512,
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
                    segment_bytes: 512,
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
    fn exceeding_the_task_cap_evicts_the_least_recently_used_task_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 2,
            segment_bytes: 1 << 20,
            max_segments: 16,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();

        decide_once(&store, "task-a", 1).expect("first task is stored");
        decide_once(&store, "task-b", 1).expect("second task is stored");
        // task-a is now the least recently used.
        decide_once(&store, "task-c", 1).expect("third task evicts task-a, it does not fail");

        assert_eq!(store.active_tasks(), 2);
        // task-a's history is gone, so its next step is a conflict, never an efficient decision.
        let err = decide_once(&store, "task-a", 2).expect_err("evicted history conflicts");
        assert!(matches!(err, RoutingStateError::StepConflict));
    }

    #[test]
    fn segment_exhaustion_rolls_off_the_oldest_segment_and_keeps_accepting_decisions() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 4096,
            segment_bytes: 2048,
            max_segments: 2,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();

        // Far more decisions than two 2 KiB segments can hold.
        for index in 0..200u64 {
            let task_id = format!("task-{index}");
            decide_once(&store, &task_id, 1)
                .unwrap_or_else(|error| panic!("decision {index} must not fail: {error:?}"));
        }

        assert!(
            store.health().segments <= 2,
            "roll-off must respect max_segments"
        );

        // The store survives a restart with the rolled-off prefix gone.
        drop(store);
        let reopened = RoutingStateStore::open(dir.path(), limits).unwrap();
        decide_once(&reopened, "task-after-restart", 1).expect("still accepting");
    }

    #[test]
    fn a_tasks_own_continuation_can_roll_off_its_own_founding_segment_without_wedging() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 512,
            max_segments: 2,
        };
        let store = RoutingStateStore::open(dir.path(), limits).unwrap();
        for step in 1..=4u64 {
            decide_once(&store, "long-lived", step).expect("continuation must not fail");
        }
        // The task's own founding segment rolled off mid-flight; the live process kept its full
        // in-memory continuity, so the very next step is not a phantom conflict.
        decide_once(&store, "long-lived", 5).expect("no phantom step conflict after self roll-off");

        // A restart has no step one on disk for this task, so it starts over rather than reading
        // a gapped history or refusing to open.
        drop(store);
        let reopened = RoutingStateStore::open(dir.path(), limits).unwrap();
        assert!(matches!(
            reopened.decide(
                "long-lived",
                6,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write]
            ),
            Err(RoutingStateError::StepConflict)
        ));
        decide_once(&reopened, "long-lived", 1).expect("restarts cleanly at step one");
    }

    #[test]
    fn configured_capacity_refuses_new_history_without_deleting_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            segment_bytes: 512,
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
        // Segment exhaustion no longer refuses: the single segment rolls off to make room.
        store
            .decide(
                "task-2",
                1,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write],
            )
            .expect("roll-off makes room instead of failing forever");
        assert_eq!(store.active_tasks(), 1);
        // task-1's history rolled off with the segment, so its next step conflicts rather than
        // reading a truncated history.
        assert!(matches!(
            store.decide(
                "task-1",
                2,
                "sha256:route",
                &profile(),
                vec![RoutingSignal::Write]
            ),
            Err(RoutingStateError::StepConflict)
        ));
    }

    #[test]
    fn rotates_segments_and_recovers_all_valid_history_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let limits = RoutingStateLimits {
            max_active_tasks: 8,
            // A framed routing record is deliberately larger than this, so each accepted
            // decision has to occupy its own segment.
            segment_bytes: 512,
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

use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::ffi::OsStrExt,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const RUN_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const AUTHORITY_RUN_MANIFEST_SCHEMA_VERSION: u32 = 2;
pub const MAX_RUN_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_RUN_MANIFESTS: usize = 4096;
const MAX_RUN_MANIFEST_FILENAME_BYTES: usize = 160;
// 4,096 runs × (1,024 segments + one manifest), plus lock/legacy-file headroom.
const MAX_RUN_DIRECTORY_ENTRIES_SCAN: usize = 4_200_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSegment {
    pub name: String,
    pub bytes: u64,
    pub records: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDigests {
    pub policy: String,
    pub registry: String,
    pub attribution: Option<String>,
    pub owned_cost: Option<String>,
    pub passive_profile: Option<String>,
    pub passive_input: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    pub segment_bytes: u64,
    pub max_segments: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub clean_shutdown: bool,
    pub policy_digest: String,
    pub registry_digest: String,
    #[serde(default)]
    pub attribution_digest: Option<String>,
    #[serde(default)]
    pub owned_cost_digest: Option<String>,
    #[serde(default)]
    pub passive_profile_digest: Option<String>,
    #[serde(default)]
    pub passive_input_digest: Option<String>,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub truncated: u64,
    pub unmapped: u64,
    pub unpriceable: u64,
    pub untrusted_identity_headers: u64,
    pub next_sequence: u64,
    pub writer_healthy: bool,
    pub writer_error: Option<String>,
    pub last_flush_at_ms: Option<u64>,
    pub segment_bytes: u64,
    pub max_segments: u32,
    pub segments: Vec<String>,
    #[serde(default)]
    pub segment_inventory: Vec<RunSegment>,
    #[serde(default)]
    pub records_digest: Option<String>,
}

/// A separate manifest for authority-bearing records. Schema-v1 observation manifests are never
/// extended or reinterpreted as allocation authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRunManifestV2 {
    pub schema_version: u32,
    pub run_id: String,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub clean_shutdown: bool,
    pub writer_healthy: bool,
    pub writer_error: Option<String>,
    pub enforcement_digest: String,
    pub actuator_set_digest: String,
    pub grant_set_digest: String,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub next_sequence: u64,
    pub records_file: String,
    pub records_bytes: Option<u64>,
    pub records_digest: Option<String>,
    pub last_flush_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRunDigestsV2 {
    pub enforcement: String,
    pub actuator_set: String,
    pub grant_set: String,
}

#[derive(Debug)]
pub struct AuthorityRunStoreV2 {
    directory: PathBuf,
    manifest_path: PathBuf,
    #[allow(dead_code)]
    lock_file: File,
    manifest: Mutex<AuthorityRunManifestV2>,
}

impl AuthorityRunStoreV2 {
    pub fn create(directory: &Path, digests: AuthorityRunDigestsV2) -> Result<Self, RunError> {
        create_private_dir(directory)?;
        let directory = fs::canonicalize(directory)?;
        let directory_metadata = fs::metadata(&directory)?;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.permissions().mode() & 0o077 != 0
            || directory_metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(RunError::InvalidManifest);
        }
        if !valid_digest(&digests.enforcement)
            || !valid_digest(&digests.actuator_set)
            || !valid_digest(&digests.grant_set)
        {
            return Err(RunError::InvalidManifest);
        }
        let lock_file = acquire_named_writer_lock(&directory, "authority-writer.lock")?;
        let run_id = Uuid::new_v4().to_string();
        let records_file = format!("authority-{run_id}.bwl");
        let manifest_path = directory.join(format!("authority-run-{run_id}.json"));
        let manifest = AuthorityRunManifestV2 {
            schema_version: AUTHORITY_RUN_MANIFEST_SCHEMA_VERSION,
            run_id,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            clean_shutdown: false,
            writer_healthy: true,
            writer_error: None,
            enforcement_digest: digests.enforcement,
            actuator_set_digest: digests.actuator_set,
            grant_set_digest: digests.grant_set,
            accepted: 0,
            recorded: 0,
            dropped: 0,
            next_sequence: 1,
            records_file,
            records_bytes: None,
            records_digest: None,
            last_flush_at_ms: None,
        };
        atomic_write_authority_manifest(&directory, &manifest_path, &manifest)?;
        Ok(Self {
            directory,
            manifest_path,
            lock_file,
            manifest: Mutex::new(manifest),
        })
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn snapshot(&self) -> AuthorityRunManifestV2 {
        self.lock_authority_manifest().clone()
    }

    pub fn accept(&self) -> Result<u64, RunError> {
        let mut manifest = self.lock_authority_manifest();
        let sequence = manifest.next_sequence;
        manifest.next_sequence = manifest
            .next_sequence
            .checked_add(1)
            .ok_or(RunError::CounterOverflow("next_sequence"))?;
        increment(&mut manifest.accepted, "accepted")?;
        Ok(sequence)
    }

    pub fn recorded(&self, sequence: u64) -> Result<(), RunError> {
        self.validate_authority_sequence(sequence)?;
        increment(&mut self.lock_authority_manifest().recorded, "recorded")
    }

    pub fn dropped(&self, sequence: u64) -> Result<(), RunError> {
        self.validate_authority_sequence(sequence)?;
        increment(&mut self.lock_authority_manifest().dropped, "dropped")
    }

    pub fn set_writer_error(&self, error: impl Into<String>) {
        let mut manifest = self.lock_authority_manifest();
        manifest.writer_healthy = false;
        manifest.writer_error = Some(error.into());
    }

    pub fn flush(&self) -> Result<(), RunError> {
        let manifest = {
            let mut manifest = self.lock_authority_manifest();
            manifest.last_flush_at_ms = Some(now_ms());
            manifest.clone()
        };
        atomic_write_authority_manifest(&self.directory, &self.manifest_path, &manifest)
    }

    pub fn finish(
        &self,
        clean_shutdown: bool,
        records_bytes: Option<u64>,
        records_digest: Option<String>,
    ) -> Result<(), RunError> {
        if records_digest
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
        {
            return Err(RunError::InvalidIntegrity);
        }
        let manifest = {
            let mut manifest = self.lock_authority_manifest();
            manifest.clean_shutdown = clean_shutdown
                && manifest.writer_healthy
                && manifest.dropped == 0
                && manifest.accepted == manifest.recorded;
            manifest.ended_at_ms = Some(now_ms());
            manifest.last_flush_at_ms = Some(now_ms());
            manifest.records_bytes = records_bytes;
            manifest.records_digest = records_digest;
            manifest.clone()
        };
        atomic_write_authority_manifest(&self.directory, &self.manifest_path, &manifest)
    }

    pub fn load_manifest(path: &Path) -> Result<AuthorityRunManifestV2, RunError> {
        let parent = path.parent().ok_or(RunError::InvalidManifest)?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(RunError::InvalidManifest)?;
        let directory = open_anchored_directory(parent)?;
        let directory_metadata = directory.metadata()?;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.permissions().mode() & 0o077 != 0
            || directory_metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(RunError::InvalidManifest);
        }
        load_authority_manifest_at(&directory, filename)
    }

    fn validate_authority_sequence(&self, sequence: u64) -> Result<(), RunError> {
        if sequence == 0 || sequence >= self.lock_authority_manifest().next_sequence {
            Err(RunError::UnallocatedSequence(sequence))
        } else {
            Ok(())
        }
    }

    fn lock_authority_manifest(&self) -> std::sync::MutexGuard<'_, AuthorityRunManifestV2> {
        self.manifest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn load_authority_manifest_at(
    directory: &File,
    filename: &str,
) -> Result<AuthorityRunManifestV2, RunError> {
    let component = CString::new(filename).map_err(|_| RunError::InvalidManifest)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.len() > MAX_RUN_MANIFEST_BYTES as u64
    {
        return Err(RunError::InvalidManifest);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(metadata.len()).map_err(|_| RunError::ManifestLimit)?)
        .map_err(|_| RunError::ManifestLimit)?;
    file.take(MAX_RUN_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(RunError::ManifestLimit);
    }
    let manifest: AuthorityRunManifestV2 = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != AUTHORITY_RUN_MANIFEST_SCHEMA_VERSION {
        return Err(RunError::UnsupportedSchema(manifest.schema_version));
    }
    if filename != format!("authority-run-{}.json", manifest.run_id)
        || manifest.records_file != format!("authority-{}.bwl", manifest.run_id)
    {
        return Err(RunError::InvalidManifest);
    }
    Ok(manifest)
}

#[derive(Debug)]
pub struct RunStore {
    directory: PathBuf,
    manifest_path: PathBuf,
    lock_file: File,
    manifest: Mutex<RunManifest>,
}

impl RunStore {
    pub fn create(
        directory: &Path,
        digests: RunDigests,
        limits: RunLimits,
    ) -> Result<Self, RunError> {
        create_private_dir(directory)?;
        let directory = fs::canonicalize(directory)?;
        let directory = directory.as_path();
        let lock_file = acquire_writer_lock(directory)?;
        let run_id = Uuid::new_v4().to_string();
        let manifest_path = manifest_path(directory, &run_id);
        let manifest = RunManifest {
            schema_version: RUN_MANIFEST_SCHEMA_VERSION,
            run_id,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            clean_shutdown: false,
            policy_digest: digests.policy,
            registry_digest: digests.registry,
            attribution_digest: digests.attribution,
            owned_cost_digest: digests.owned_cost,
            passive_profile_digest: digests.passive_profile,
            passive_input_digest: digests.passive_input,
            accepted: 0,
            recorded: 0,
            dropped: 0,
            truncated: 0,
            unmapped: 0,
            unpriceable: 0,
            untrusted_identity_headers: 0,
            next_sequence: 1,
            writer_healthy: true,
            writer_error: None,
            last_flush_at_ms: None,
            segment_bytes: limits.segment_bytes,
            max_segments: limits.max_segments,
            segments: Vec::new(),
            segment_inventory: Vec::new(),
            records_digest: None,
        };
        atomic_write_manifest(directory, &manifest_path, &manifest)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            manifest_path,
            lock_file,
            manifest: Mutex::new(manifest),
        })
    }

    pub fn resume(directory: &Path, run_id: &str) -> Result<Self, RunError> {
        create_private_dir(directory)?;
        let directory = fs::canonicalize(directory)?;
        let directory = directory.as_path();
        let lock_file = acquire_writer_lock(directory)?;
        let manifest_path = manifest_path(directory, run_id);
        let mut manifest = Self::load_manifest(&manifest_path)?;
        manifest.clean_shutdown = false;
        manifest.ended_at_ms = None;
        atomic_write_manifest(directory, &manifest_path, &manifest)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            manifest_path,
            lock_file,
            manifest: Mutex::new(manifest),
        })
    }

    pub fn run_id(&self) -> String {
        self.lock_manifest().run_id.clone()
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn snapshot(&self) -> RunManifest {
        self.lock_manifest().clone()
    }

    pub fn accept(&self) -> Result<u64, RunError> {
        let mut manifest = self.lock_manifest();
        let sequence = manifest.next_sequence;
        manifest.next_sequence = manifest
            .next_sequence
            .checked_add(1)
            .ok_or(RunError::CounterOverflow("next_sequence"))?;
        manifest.accepted = manifest
            .accepted
            .checked_add(1)
            .ok_or(RunError::CounterOverflow("accepted"))?;
        Ok(sequence)
    }

    pub fn recorded(&self, sequence: u64) -> Result<(), RunError> {
        self.validate_allocated_sequence(sequence)?;
        increment(&mut self.lock_manifest().recorded, "recorded")
    }

    pub fn dropped(&self, sequence: u64) -> Result<(), RunError> {
        self.validate_allocated_sequence(sequence)?;
        increment(&mut self.lock_manifest().dropped, "dropped")
    }

    pub fn increment_truncated(&self) -> Result<(), RunError> {
        increment(&mut self.lock_manifest().truncated, "truncated")
    }

    pub fn increment_unmapped(&self) -> Result<(), RunError> {
        increment(&mut self.lock_manifest().unmapped, "unmapped")
    }

    pub fn increment_unpriceable(&self) -> Result<(), RunError> {
        increment(&mut self.lock_manifest().unpriceable, "unpriceable")
    }

    pub fn increment_untrusted_identity_headers(&self) -> Result<(), RunError> {
        increment(
            &mut self.lock_manifest().untrusted_identity_headers,
            "untrusted_identity_headers",
        )
    }

    pub fn set_writer_error(&self, error: impl Into<String>) {
        let mut manifest = self.lock_manifest();
        manifest.writer_healthy = false;
        manifest.writer_error = Some(error.into());
    }

    pub fn add_segment(&self, filename: String) -> Result<(), RunError> {
        let mut manifest = self.lock_manifest();
        if manifest.segments.iter().any(|value| value == &filename) {
            return Ok(());
        }
        if manifest.segments.len() >= manifest.max_segments as usize {
            return Err(RunError::SegmentLimit(manifest.max_segments));
        }
        manifest.segments.push(filename);
        Ok(())
    }

    pub fn bind_integrity(
        &self,
        inventory: Vec<RunSegment>,
        records_digest: String,
    ) -> Result<(), RunError> {
        let mut manifest = self.lock_manifest();
        if manifest.clean_shutdown
            || inventory
                .iter()
                .map(|segment| &segment.name)
                .ne(manifest.segments.iter())
            || inventory.len() > manifest.max_segments as usize
            || !valid_digest(&records_digest)
            || inventory.iter().any(|segment| {
                segment.bytes > manifest.segment_bytes
                    || !valid_digest(&segment.digest)
                    || (segment.records == 0)
                        != (segment.first_sequence.is_none() && segment.last_sequence.is_none())
            })
        {
            return Err(RunError::InvalidIntegrity);
        }
        manifest.segment_inventory = inventory;
        manifest.records_digest = Some(records_digest);
        Ok(())
    }

    pub fn flush(&self) -> Result<(), RunError> {
        let manifest = {
            let mut manifest = self.lock_manifest();
            manifest.last_flush_at_ms = Some(now_ms());
            manifest.clone()
        };
        atomic_write_manifest(&self.directory, &self.manifest_path, &manifest)
    }

    pub fn finish(&self, clean_shutdown: bool) -> Result<(), RunError> {
        let manifest = {
            let mut manifest = self.lock_manifest();
            manifest.clean_shutdown = clean_shutdown;
            manifest.ended_at_ms = Some(now_ms());
            manifest.last_flush_at_ms = Some(now_ms());
            manifest.clone()
        };
        atomic_write_manifest(&self.directory, &self.manifest_path, &manifest)
    }

    pub fn load_manifest(path: &Path) -> Result<RunManifest, RunError> {
        let mut source = String::new();
        File::open(path)?.read_to_string(&mut source)?;
        let manifest: RunManifest = serde_json::from_str(&source)?;
        if manifest.schema_version != RUN_MANIFEST_SCHEMA_VERSION {
            return Err(RunError::UnsupportedSchema(manifest.schema_version));
        }
        Ok(manifest)
    }

    pub fn list_manifests(directory: &Path) -> Result<Vec<RunManifest>, RunError> {
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut manifests = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("run-") && name.ends_with(".json") {
                manifests.push(Self::load_manifest(&entry.path())?);
            }
        }
        manifests.sort_by(|left, right| {
            left.started_at_ms
                .cmp(&right.started_at_ms)
                .then_with(|| left.run_id.cmp(&right.run_id))
        });
        Ok(manifests)
    }

    pub fn list_manifests_hardened(directory: &Path) -> Result<Vec<RunManifest>, RunError> {
        list_manifests_hardened_inner(directory, MAX_RUN_MANIFESTS, MAX_RUN_MANIFEST_BYTES)
    }

    fn validate_allocated_sequence(&self, sequence: u64) -> Result<(), RunError> {
        let next = self.lock_manifest().next_sequence;
        if sequence == 0 || sequence >= next {
            Err(RunError::UnallocatedSequence(sequence))
        } else {
            Ok(())
        }
    }

    fn lock_manifest(&self) -> std::sync::MutexGuard<'_, RunManifest> {
        self.manifest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for RunStore {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

fn list_manifests_hardened_inner(
    directory: &Path,
    maximum_manifests: usize,
    maximum_bytes: usize,
) -> Result<Vec<RunManifest>, RunError> {
    let directory = open_anchored_directory(directory)?;
    let names = manifest_candidate_names(directory.as_raw_fd(), maximum_manifests)?;
    let mut ids = BTreeSet::new();
    let mut manifests = Vec::with_capacity(names.len());
    for name in names {
        let component = CString::new(name.as_str()).map_err(|_| RunError::InvalidManifest)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.len() > maximum_bytes as u64
        {
            return Err(RunError::InvalidManifest);
        }
        let length = usize::try_from(metadata.len()).map_err(|_| RunError::ManifestLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| RunError::ManifestLimit)?;
        file.take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(RunError::ManifestLimit);
        }
        let manifest: RunManifest = serde_json::from_slice(&bytes)?;
        if manifest.schema_version != RUN_MANIFEST_SCHEMA_VERSION
            || name != format!("run-{}.json", manifest.run_id)
            || !ids.insert(manifest.run_id.clone())
        {
            return Err(RunError::InvalidManifest);
        }
        manifests.push(manifest);
    }
    manifests.sort_by(|left, right| {
        left.started_at_ms
            .cmp(&right.started_at_ms)
            .then_with(|| left.run_id.cmp(&right.run_id))
    });
    Ok(manifests)
}

fn open_anchored_directory(path: &Path) -> Result<File, RunError> {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = CString::new("/").map_err(|_| RunError::InvalidManifest)?;
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for component in absolute.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes()).map_err(|_| RunError::InvalidManifest)?;
        let next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(next) };
    }
    Ok(directory)
}

fn manifest_candidate_names(
    directory_fd: RawFd,
    maximum_manifests: usize,
) -> Result<Vec<String>, RunError> {
    manifest_candidate_names_inner(
        directory_fd,
        maximum_manifests,
        MAX_RUN_DIRECTORY_ENTRIES_SCAN,
    )
}

fn manifest_candidate_names_inner(
    directory_fd: RawFd,
    maximum_manifests: usize,
    maximum_entries_scan: usize,
) -> Result<Vec<String>, RunError> {
    let duplicated = unsafe { libc::dup(directory_fd) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        unsafe {
            libc::close(duplicated);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = DirectoryStream(stream);
    let limit = maximum_manifests.min(MAX_RUN_MANIFESTS);
    let mut names = Vec::new();
    let mut scanned = 0usize;
    names
        .try_reserve_exact(limit)
        .map_err(|_| RunError::ManifestLimit)?;
    loop {
        reset_errno();
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if readdir_finished(current_errno())? {
                break;
            }
            unreachable!("readdir_finished only returns false by error");
        }
        let raw_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(raw_name.to_bytes(), b"." | b"..") {
            continue;
        }
        scanned = scanned.checked_add(1).ok_or(RunError::ManifestLimit)?;
        if scanned > maximum_entries_scan {
            return Err(RunError::ManifestLimit);
        }
        let name = raw_name.to_string_lossy();
        if !name.starts_with("run-") || !name.ends_with(".json") {
            continue;
        }
        if raw_name.to_bytes().len() > MAX_RUN_MANIFEST_FILENAME_BYTES {
            return Err(RunError::InvalidManifest);
        }
        if names.len() >= limit {
            return Err(RunError::ManifestLimit);
        }
        names.push(name.into_owned());
    }
    names.sort();
    Ok(names)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn readdir_finished(errno: libc::c_int) -> Result<bool, RunError> {
    if errno == 0 {
        Ok(true)
    } else {
        Err(std::io::Error::from_raw_os_error(errno).into())
    }
}

#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

fn reset_errno() {
    unsafe {
        *errno_location() = 0;
    }
}

fn current_errno() -> libc::c_int {
    unsafe { *errno_location() }
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("run-state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("run manifest JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("another Bowline writer holds the ledger-directory lock")]
    Locked,
    #[error("unsupported run manifest schema version {0}")]
    UnsupportedSchema(u32),
    #[error("run counter overflow: {0}")]
    CounterOverflow(&'static str),
    #[error("sequence {0} was not allocated by this run")]
    UnallocatedSequence(u64),
    #[error("run reached configured segment limit {0}")]
    SegmentLimit(u32),
    #[error("invalid run integrity binding")]
    InvalidIntegrity,
    #[error("invalid run manifest")]
    InvalidManifest,
    #[error("run manifest limit exceeded")]
    ManifestLimit,
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn create_private_dir(path: &Path) -> Result<(), RunError> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    Ok(())
}

fn acquire_writer_lock(directory: &Path) -> Result<File, RunError> {
    acquire_named_writer_lock(directory, "writer.lock")
}

fn acquire_named_writer_lock(directory: &Path, name: &str) -> Result<File, RunError> {
    let path = directory.join(name);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => RunError::Locked,
        std::fs::TryLockError::Error(error) => RunError::Io(error),
    })?;
    Ok(file)
}

fn atomic_write_authority_manifest(
    directory: &Path,
    destination: &Path,
    manifest: &AuthorityRunManifestV2,
) -> Result<(), RunError> {
    let temp_path = directory.join(format!(".authority-manifest-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(manifest)?;
    if bytes.len() > MAX_RUN_MANIFEST_BYTES {
        return Err(RunError::ManifestLimit);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp_path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp_path, destination)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn manifest_path(directory: &Path, run_id: &str) -> PathBuf {
    directory.join(format!("run-{run_id}.json"))
}

fn atomic_write_manifest(
    directory: &Path,
    destination: &Path,
    manifest: &RunManifest,
) -> Result<(), RunError> {
    let temp_path = directory.join(format!(".manifest-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(manifest)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp_path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp_path, destination)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn increment(value: &mut u64, field: &'static str) -> Result<(), RunError> {
    *value = value
        .checked_add(1)
        .ok_or(RunError::CounterOverflow(field))?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    use crate::attribution::{AttributionResolver, AttributionRule};
    use crate::config::load_owned_cost_catalog;
    use crate::supply::Registry;

    #[test]
    fn authority_manifest_load_rejects_symlinks_and_filename_substitution() {
        let insecure = tempdir().expect("temporary insecure directory");
        std::fs::set_permissions(insecure.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let digest = |value: u8| format!("sha256:{value:064x}");
        assert!(AuthorityRunStoreV2::create(
            insecure.path(),
            AuthorityRunDigestsV2 {
                enforcement: digest(1),
                actuator_set: digest(2),
                grant_set: digest(3),
            },
        )
        .is_err());

        let temp = tempdir().expect("temporary run directory");
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = AuthorityRunStoreV2::create(
            temp.path(),
            AuthorityRunDigestsV2 {
                enforcement: digest(1),
                actuator_set: digest(2),
                grant_set: digest(3),
            },
        )
        .expect("authority run starts");
        let path = store.manifest_path().to_path_buf();
        let alias = temp.path().join("authority-run-forged.json");
        std::fs::copy(&path, &alias).unwrap();
        assert!(AuthorityRunStoreV2::load_manifest(&alias).is_err());

        let target = temp.path().join("manifest-target");
        std::fs::copy(&path, &target).unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert!(AuthorityRunStoreV2::load_manifest(&path).is_err());

        std::fs::remove_file(&path).unwrap();
        std::fs::copy(&target, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AuthorityRunStoreV2::load_manifest(&path).is_err());
    }

    #[test]
    fn manifest_is_private_atomic_and_monotonic() {
        let temp = tempdir().expect("temporary run directory");
        let store = RunStore::create(temp.path(), digests(), limits()).expect("run starts");

        let first = store.accept().expect("first sequence allocated");
        let second = store.accept().expect("second sequence allocated");
        store.recorded(first).expect("first record counted");
        store
            .dropped(second)
            .expect("second record disclosed as dropped");
        store.flush().expect("manifest flushed");

        let manifest = store.snapshot();
        assert_eq!((first, second), (1, 2));
        assert_eq!(
            (manifest.accepted, manifest.recorded, manifest.dropped),
            (2, 1, 1)
        );
        assert_eq!(manifest.next_sequence, 3);
        assert!(!manifest.clean_shutdown);
        assert_eq!(
            std::fs::metadata(store.manifest_path())
                .expect("manifest metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let loaded = RunStore::load_manifest(store.manifest_path()).expect("manifest reloads");
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn second_writer_in_same_ledger_directory_is_refused() {
        let temp = tempdir().expect("temporary run directory");
        let first = RunStore::create(temp.path(), digests(), limits()).expect("first run starts");

        let error = RunStore::resume(temp.path(), &first.run_id())
            .expect_err("second writer must not acquire the directory lock");

        assert!(matches!(error, RunError::Locked));
    }

    #[test]
    fn clean_finish_is_durable_and_unknown_schema_is_rejected() {
        let temp = tempdir().expect("temporary run directory");
        let store = RunStore::create(temp.path(), digests(), limits()).expect("run starts");
        let path = store.manifest_path().to_path_buf();
        store.finish(true).expect("run finishes cleanly");
        drop(store);

        let manifest = RunStore::load_manifest(&path).expect("finished manifest reloads");
        assert!(manifest.clean_shutdown);
        assert!(manifest.ended_at_ms.is_some());

        let source = std::fs::read_to_string(&path).expect("manifest readable");
        std::fs::write(
            &path,
            source.replace("\"schema_version\": 1", "\"schema_version\": 99"),
        )
        .expect("future manifest written");
        assert!(matches!(
            RunStore::load_manifest(&path),
            Err(RunError::UnsupportedSchema(99))
        ));
    }

    #[test]
    fn list_manifests_returns_runs_in_start_order() {
        let temp = tempdir().expect("temporary run directory");
        let first = RunStore::create(temp.path(), digests(), limits()).expect("first run starts");
        let first_id = first.run_id();
        first.finish(true).expect("first run finishes");
        drop(first);
        let second = RunStore::create(temp.path(), digests(), limits()).expect("second run starts");
        let second_id = second.run_id();
        second.finish(true).expect("second run finishes");
        drop(second);

        let manifests = RunStore::list_manifests(temp.path()).expect("manifests list");

        assert_eq!(manifests.len(), 2);
        assert!(manifests.iter().any(|manifest| manifest.run_id == first_id));
        assert!(manifests
            .iter()
            .any(|manifest| manifest.run_id == second_id));
        assert!(manifests
            .windows(2)
            .all(|pair| pair[0].started_at_ms <= pair[1].started_at_ms));
    }

    #[test]
    fn provenance_digests_change_with_attribution_and_tco() {
        let registry = Registry::from_json(
            r#"{"feed_version":"test","entries":[
              {"id":"owned/a","model":"a","location":"a","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}},
              {"id":"owned/b","model":"b","location":"b","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}}
            ]}"#,
        )
        .expect("registry parses");
        let first_resolver = AttributionResolver::new(
            vec![AttributionRule {
                namespace: "deployment".to_string(),
                value: "one".to_string(),
                supply_id: "owned/a".to_string(),
            }],
            Some("owned/a".to_string()),
            &registry,
        )
        .expect("resolver one");
        let second_resolver = AttributionResolver::new(
            vec![AttributionRule {
                namespace: "deployment".to_string(),
                value: "two".to_string(),
                supply_id: "owned/b".to_string(),
            }],
            Some("owned/a".to_string()),
            &registry,
        )
        .expect("resolver two");
        assert_ne!(
            first_resolver.normalized_digest(),
            second_resolver.normalized_digest()
        );

        let first_tco = load_owned_cost_catalog(
            Some("monthly_amortization_usd: 100\nmonthly_power_usd: 0\nmonthly_ops_usd: 0\nmonthly_capacity_mtok: 100\n"),
            Some("owned/a"),
            &registry,
        )
        .expect("first TCO");
        let second_tco = load_owned_cost_catalog(
            Some("monthly_amortization_usd: 200\nmonthly_power_usd: 0\nmonthly_ops_usd: 0\nmonthly_capacity_mtok: 100\n"),
            Some("owned/a"),
            &registry,
        )
        .expect("second TCO");
        assert_ne!(
            first_tco.normalized_digest(),
            second_tco.normalized_digest()
        );

        let legacy_json = r#"{
          "schema_version":1,"run_id":"legacy","started_at_ms":1,"ended_at_ms":2,
          "clean_shutdown":true,"policy_digest":"sha256:policy","registry_digest":"sha256:registry",
          "accepted":0,"recorded":0,"dropped":0,"truncated":0,"unmapped":0,"unpriceable":0,
          "untrusted_identity_headers":0,"next_sequence":1,"writer_healthy":true,"writer_error":null,
          "last_flush_at_ms":2,"segment_bytes":1024,"max_segments":4,"segments":[]
        }"#;
        let legacy: RunManifest =
            serde_json::from_str(legacy_json).expect("legacy manifest parses");
        assert_eq!(legacy.attribution_digest, None);
        assert_eq!(legacy.owned_cost_digest, None);
        assert_eq!(legacy.passive_profile_digest, None);
        assert_eq!(legacy.passive_input_digest, None);
    }

    fn digests() -> RunDigests {
        RunDigests {
            policy: "sha256:policy".to_string(),
            registry: "sha256:registry".to_string(),
            attribution: None,
            owned_cost: None,
            passive_profile: None,
            passive_input: None,
        }
    }

    fn limits() -> RunLimits {
        RunLimits {
            segment_bytes: 1024,
            max_segments: 4,
        }
    }

    #[test]
    fn hardened_manifest_listing_is_bounded_descriptor_rooted_and_type_safe() {
        let temp = tempfile::tempdir().unwrap();
        let directory = fs::canonicalize(temp.path()).unwrap();
        let first = RunStore::create(&directory, digests(), limits()).unwrap();
        first.finish(true).unwrap();
        let first_name = format!("run-{}.json", first.run_id());
        drop(first);
        let second = RunStore::create(&directory, digests(), limits()).unwrap();
        second.finish(true).unwrap();
        drop(second);
        assert_eq!(
            list_manifests_hardened_inner(&directory, 2, MAX_RUN_MANIFEST_BYTES)
                .unwrap()
                .len(),
            2
        );
        for index in 0..256 {
            fs::write(directory.join(format!("irrelevant-{index}")), b"ignored").unwrap();
        }
        let entries = fs::read_dir(&directory).unwrap().count();
        let anchored = open_anchored_directory(&directory).unwrap();
        assert_eq!(
            manifest_candidate_names_inner(anchored.as_raw_fd(), 2, entries)
                .unwrap()
                .len(),
            2
        );
        let over_scan_limit = directory.join("irrelevant-over-scan-limit");
        fs::write(&over_scan_limit, b"ignored").unwrap();
        let anchored = open_anchored_directory(&directory).unwrap();
        assert!(matches!(
            manifest_candidate_names_inner(anchored.as_raw_fd(), 2, entries),
            Err(RunError::ManifestLimit)
        ));
        fs::remove_file(over_scan_limit).unwrap();
        assert_eq!(
            list_manifests_hardened_inner(&directory, 2, MAX_RUN_MANIFEST_BYTES)
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            list_manifests_hardened_inner(&directory, 1, MAX_RUN_MANIFEST_BYTES),
            Err(RunError::ManifestLimit)
        ));

        let oversized_name = directory.join(format!("run-{}.json", "x".repeat(170)));
        fs::write(&oversized_name, b"{}").unwrap();
        assert!(matches!(
            RunStore::list_manifests_hardened(&directory),
            Err(RunError::InvalidManifest)
        ));
        fs::remove_file(oversized_name).unwrap();

        let first_path = directory.join(&first_name);
        let size = fs::metadata(&first_path).unwrap().len() as usize;
        assert_eq!(
            list_manifests_hardened_inner(&directory, 2, size)
                .unwrap()
                .len(),
            2
        );
        assert!(list_manifests_hardened_inner(&directory, 2, size - 1).is_err());

        let symlink_name = directory.join("run-symlink.json");
        std::os::unix::fs::symlink(&first_path, &symlink_name).unwrap();
        assert!(RunStore::list_manifests_hardened(&directory).is_err());
        fs::remove_file(&symlink_name).unwrap();

        let fifo_name = directory.join("run-fifo.json");
        let fifo = CString::new(fifo_name.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(RunStore::list_manifests_hardened(&directory).is_err());
        fs::remove_file(&fifo_name).unwrap();

        let directory_name = directory.join("run-directory.json");
        fs::create_dir(&directory_name).unwrap();
        assert!(RunStore::list_manifests_hardened(&directory).is_err());
        fs::remove_dir(directory_name).unwrap();

        let mismatched = directory.join("run-mismatched.json");
        fs::copy(&first_path, &mismatched).unwrap();
        fs::set_permissions(&mismatched, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(RunStore::list_manifests_hardened(&directory).is_err());
    }

    #[test]
    fn readdir_end_distinguishes_eof_from_error() {
        assert!(readdir_finished(0).unwrap());
        assert!(matches!(
            readdir_finished(libc::EIO),
            Err(RunError::Io(error)) if error.raw_os_error() == Some(libc::EIO)
        ));
    }
}

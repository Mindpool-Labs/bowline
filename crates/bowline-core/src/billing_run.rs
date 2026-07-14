use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::billing::{
    validate_normalized_rows, BillingRow, BillingTotals, ChargeBasis, ValidatedBilling,
    MAX_BILLING_ROWS, MAX_BILLING_TIMESTAMP_MS,
};

const MANIFEST: &str = "manifest.json";
const LOCK: &str = ".billing-writer.lock";
const INCOMPLETE: &str = ".billing-incomplete";
const COMPLETE: &str = ".billing-complete";
const MAGIC: &[u8; 5] = b"BWB1\n";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_FRAME_BYTES: usize = 32 * 1024;
pub const BILLING_RUN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancellationState {
    Active,
    Cancelled,
    Complete,
}

#[derive(Debug, Clone)]
pub struct BillingCancellation {
    state: Arc<Mutex<CancellationState>>,
}

impl Default for BillingCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl BillingCancellation {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CancellationState::Active)),
        }
    }

    /// Returns true only when cancellation linearizes before durable completion.
    pub fn cancel(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match *state {
            CancellationState::Active => {
                *state = CancellationState::Cancelled;
                true
            }
            CancellationState::Cancelled | CancellationState::Complete => false,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        *state == CancellationState::Cancelled
    }

    fn checkpoint(&self) -> Result<(), BillingRunError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if *state == CancellationState::Cancelled {
            Err(BillingRunError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn complete<T>(
        &self,
        transition: impl FnOnce() -> Result<T, BillingRunError>,
    ) -> Result<T, BillingRunError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if *state == CancellationState::Cancelled {
            return Err(BillingRunError::Cancelled);
        }
        let result = transition()?;
        *state = CancellationState::Complete;
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingImportPhase {
    BeforeCompleteTransition,
    AfterCompleteTransition,
}

struct TrustedDir {
    file: File,
}

impl TrustedDir {
    fn open_existing(path: &Path) -> Result<Self, BillingRunError> {
        let mut current = if path.is_absolute() {
            Self::open_root(OsStr::new("/"))?
        } else {
            Self::open_root(OsStr::new("."))?
        };
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => current = current.open_directory(name)?,
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(BillingRunError::UnsafePath)
                }
            }
        }
        Ok(current)
    }

    fn create_with_hook<F>(path: &Path, hook: F) -> Result<CreatedDirectory, BillingRunError>
    where
        F: FnOnce(),
    {
        let parent_path = path.parent().ok_or(BillingRunError::UnsafePath)?;
        let name = path.file_name().ok_or(BillingRunError::UnsafePath)?;
        let parent = Self::open_existing(parent_path)?;
        validate_private_directory_fd(&parent.file)?;
        let name = component_name(name)?;
        let result = unsafe { libc::mkdirat(parent.file.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0 {
            return Err(BillingRunError::Io(std::io::Error::last_os_error()));
        }
        let created_identity = identity_at(&parent, &name)?;
        let creation_result = (|| {
            hook();
            #[cfg(target_os = "macos")]
            {
                inject_creation_fault(CreationFault::Certification)?;
                inject_creation_fault(CreationFault::Identity)?;
                if identity_at(&parent, &name)? != created_identity {
                    return Err(BillingRunError::UnsafePath);
                }
                inject_creation_fault(CreationFault::Chmod)?;
                if unsafe {
                    libc::fchmodat(
                        parent.file.as_raw_fd(),
                        name.as_ptr(),
                        0o700,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(BillingRunError::UnsafePath);
                }
                if identity_at(&parent, &name)? != created_identity {
                    return Err(BillingRunError::UnsafePath);
                }
            }
            #[cfg(target_os = "linux")]
            {
                inject_creation_fault(CreationFault::Certification)?;
                let certified = parent.open_certification_directory(&name)?;
                inject_creation_fault(CreationFault::Identity)?;
                if file_identity(&certified.file)? != created_identity {
                    return Err(BillingRunError::UnsafePath);
                }
                inject_creation_fault(CreationFault::Chmod)?;
                chmod_certified_directory(&certified.file)?;
            }
            inject_creation_fault(CreationFault::FinalOpen)?;
            let directory = parent.open_directory(OsStr::from_bytes(name.as_bytes()))?;
            inject_creation_fault(CreationFault::FinalValidation)?;
            if file_identity(&directory.file)? != created_identity {
                return Err(BillingRunError::UnsafePath);
            }
            if unsafe { libc::fchmod(directory.file.as_raw_fd(), 0o700) } != 0 {
                return Err(BillingRunError::Io(std::io::Error::last_os_error()));
            }
            validate_private_directory_fd(&directory.file)?;
            Ok(directory)
        })();
        let directory = match creation_result {
            Ok(directory) => directory,
            Err(error) => {
                return cleanup_created_directory(&parent, &name, created_identity, error)
            }
        };
        Ok(CreatedDirectory {
            parent,
            name,
            directory,
            identity: created_identity,
        })
    }

    fn open_root(path: &OsStr) -> Result<Self, BillingRunError> {
        let path = CString::new(path.as_bytes()).map_err(|_| BillingRunError::UnsafePath)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        file_from_fd(fd).map(|file| Self { file })
    }

    fn open_directory(&self, name: &OsStr) -> Result<Self, BillingRunError> {
        let name = component_name(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                return Err(BillingRunError::UnsafePath);
            }
            return Err(BillingRunError::Io(error));
        }
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
        })
    }

    #[cfg(target_os = "linux")]
    fn open_certification_directory(&self, name: &CString) -> Result<Self, BillingRunError> {
        let access = libc::O_PATH | libc::O_DIRECTORY;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                return Err(BillingRunError::UnsafePath);
            }
            return Err(BillingRunError::Io(error));
        }
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
        })
    }

    fn create_file(&self, name: &str) -> Result<File, BillingRunError> {
        self.open_file(name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600)
    }

    fn open_read(&self, name: &str) -> Result<File, BillingRunError> {
        self.open_file(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
    }

    fn open_file(
        &self,
        name: &str,
        flags: i32,
        mode: libc::mode_t,
    ) -> Result<File, BillingRunError> {
        let name = component_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                libc::c_uint::from(mode),
            )
        };
        let file = file_from_fd(fd)?;
        if flags & libc::O_CREAT != 0 && unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(BillingRunError::Io(std::io::Error::last_os_error()));
        }
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || !exact_private_mode(metadata.permissions().mode(), 0o600)
            || metadata.uid() != effective_uid()
        {
            return Err(BillingRunError::UnsafePath);
        }
        Ok(file)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), BillingRunError> {
        let from = component_name(OsStr::new(from))?;
        let to = component_name(OsStr::new(to))?;
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                from.as_ptr(),
                self.file.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(BillingRunError::Io(std::io::Error::last_os_error()))
        }
    }

    fn unlink_file(&self, name: &str) {
        if let Ok(name) = component_name(OsStr::new(name)) {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0);
            }
        }
    }

    fn remove_file(&self, name: &str) -> Result<(), BillingRunError> {
        let name = component_name(OsStr::new(name))?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(BillingRunError::Io(std::io::Error::last_os_error()))
        }
    }

    fn has_private_file(&self, name: &str) -> Result<bool, BillingRunError> {
        match self.open_read(name) {
            Ok(_) => Ok(true),
            Err(BillingRunError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn sync(&self) -> Result<(), BillingRunError> {
        self.file.sync_all().map_err(BillingRunError::Io)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn file_identity(file: &File) -> Result<FileIdentity, BillingRunError> {
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn identity_at(parent: &TrustedDir, name: &CString) -> Result<FileIdentity, BillingRunError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.file.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(BillingRunError::Io(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    // libc::dev_t is already u64 on Linux but narrower on macOS.
    #[allow(clippy::unnecessary_cast)]
    let device = stat.st_dev as u64;
    Ok(FileIdentity {
        device,
        inode: stat.st_ino,
    })
}

fn cleanup_if_identity_matches(parent: &TrustedDir, name: &CString, expected: FileIdentity) {
    if identity_at(parent, name).ok() == Some(expected) {
        unsafe {
            libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }
}

fn cleanup_created_directory<T>(
    parent: &TrustedDir,
    name: &CString,
    identity: FileIdentity,
    error: BillingRunError,
) -> Result<T, BillingRunError> {
    cleanup_if_identity_matches(parent, name, identity);
    Err(error)
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn chmod_certified_directory(file: &File) -> Result<(), BillingRunError> {
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| BillingRunError::UnsafePath)?;
    if unsafe { libc::chmod(path.as_ptr(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(BillingRunError::Io(std::io::Error::last_os_error()))
    }
}

fn validate_private_directory_fd(file: &File) -> Result<(), BillingRunError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_dir()
        || !exact_private_mode(metadata.permissions().mode(), 0o700)
        || metadata.uid() != effective_uid()
    {
        return Err(BillingRunError::UnsafePath);
    }
    Ok(())
}

fn exact_private_mode(actual: u32, expected: u32) -> bool {
    actual & 0o7777 == expected
}

struct CreatedDirectory {
    parent: TrustedDir,
    name: CString,
    directory: TrustedDir,
    identity: FileIdentity,
}

impl CreatedDirectory {
    fn cleanup_before_manifest(&self) {
        self.directory.unlink_file(COMPLETE);
        self.directory.unlink_file(INCOMPLETE);
        self.directory.unlink_file(LOCK);
        cleanup_if_identity_matches(&self.parent, &self.name, self.identity);
    }
}

fn component_name(name: &OsStr) -> Result<CString, BillingRunError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(BillingRunError::UnsafePath);
    }
    CString::new(bytes).map_err(|_| BillingRunError::UnsafePath)
}

fn file_from_fd(fd: i32) -> Result<File, BillingRunError> {
    if fd < 0 {
        Err(BillingRunError::Io(std::io::Error::last_os_error()))
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BillingSourceFormat {
    CanonicalJsonl,
    MappedCsv,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingProvenance {
    pub source_format: BillingSourceFormat,
    pub source_digest: String,
    pub mapping_digest: Option<String>,
    pub registry_digest: String,
    pub charge_basis: ChargeBasis,
}

impl BillingProvenance {
    pub fn validate(&self) -> Result<(), BillingRunError> {
        validate_digest(&self.source_digest)?;
        validate_digest(&self.registry_digest)?;
        if let Some(value) = &self.mapping_digest {
            validate_digest(value)?;
        }
        if (self.source_format == BillingSourceFormat::MappedCsv) != self.mapping_digest.is_some()
            || self.charge_basis != ChargeBasis::InferenceUsageNet
        {
            return Err(BillingRunError::InvalidProvenance);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BillingRunError> {
        self.validate()?;
        Ok(domain_digest(
            b"bowline.billing.provenance.v1",
            &serde_json::to_vec(self)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingSegment {
    pub name: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub records: u64,
    pub bytes: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingRunManifest {
    pub schema_version: u32,
    pub binary_version: String,
    pub run_id: String,
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub clean_shutdown: bool,
    pub provenance: BillingProvenance,
    pub provenance_digest: String,
    pub normalized_digest: String,
    pub totals: BillingTotals,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub recovery_records: u64,
    pub next_sequence: u64,
    pub segments: Vec<BillingSegment>,
}

impl BillingRunManifest {
    pub fn reconciled(&self) -> bool {
        self.recorded == self.accepted
            && self.totals.rows == self.accepted
            && self.dropped == 0
            && self.recovery_records == 0
            && self.next_sequence == self.accepted.checked_add(1).unwrap_or(0)
    }
    fn validate(&self) -> Result<(), BillingRunError> {
        if self.schema_version != BILLING_RUN_SCHEMA_VERSION
            || Uuid::parse_str(&self.run_id).is_err()
            || self.binary_version.is_empty()
            || self.binary_version.len() > 128
            || self.accepted == 0
            || self.accepted > MAX_BILLING_ROWS as u64
            || self.totals.rows != self.accepted
            || self.recorded > self.accepted
            || self.dropped != 0
            || self.recovery_records != 0
            || self.started_at_ms > MAX_BILLING_TIMESTAMP_MS
            || self.provenance.digest()? != self.provenance_digest
            || !valid_digest(&self.normalized_digest)
            || self
                .completed_at_ms
                .is_some_and(|value| value < self.started_at_ms || value > MAX_BILLING_TIMESTAMP_MS)
            || self.next_sequence
                != self
                    .recorded
                    .checked_add(1)
                    .ok_or(BillingRunError::InvalidManifest)?
            || (self.clean_shutdown && (self.completed_at_ms.is_none() || !self.reconciled()))
            || (!self.clean_shutdown && self.completed_at_ms.is_some())
        {
            return Err(BillingRunError::InvalidManifest);
        }
        let mut expected = 1u64;
        let mut count = 0u64;
        for (index, segment) in self.segments.iter().enumerate() {
            let expected_name = format!("rows-{:06}.bwb", index + 1);
            if segment.name != expected_name
                || segment.first_sequence != expected
                || segment.records == 0
                || segment.last_sequence < segment.first_sequence
                || segment.last_sequence - segment.first_sequence + 1 != segment.records
                || !valid_digest(&segment.digest)
            {
                return Err(BillingRunError::InvalidManifest);
            }
            expected = segment
                .last_sequence
                .checked_add(1)
                .ok_or(BillingRunError::InvalidManifest)?;
            count = count
                .checked_add(segment.records)
                .ok_or(BillingRunError::InvalidManifest)?;
        }
        if count != self.recorded || expected != self.recorded.saturating_add(1) {
            return Err(BillingRunError::InvalidManifest);
        }
        Ok(())
    }
}

pub struct BillingRunStore {
    directory: PathBuf,
    manifest: BillingRunManifest,
    _lock: File,
    _directory_fd: TrustedDir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportFault {
    InitialManifest,
    Segment,
    IntermediateManifest,
    FinalManifest,
    TempWrite,
    FileSync,
    Rename,
    RunDirectorySync,
    ParentDirectorySync,
    CreationParentDirectorySync,
    PostTransitionSync,
    RollbackRename,
    RollbackSync,
    Lock,
    RealPostTransitionSync,
    FallbackMarkerCreate,
    FallbackMarkerWrite,
    FallbackMarkerFileSync,
    FallbackFirstDirectorySync,
    FallbackCompleteRemoval,
    FallbackFinalDirectorySync,
}

struct ImportControl<'a> {
    fault: Option<ImportFault>,
    cancellation: Option<&'a BillingCancellation>,
    observer: Option<&'a mut dyn FnMut(BillingImportPhase)>,
}

impl ImportControl<'_> {
    fn normal() -> Self {
        Self {
            fault: None,
            cancellation: None,
            observer: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreationFault {
    Certification,
    Identity,
    Chmod,
    FinalOpen,
    FinalValidation,
}

fn inject_creation_fault(stage: CreationFault) -> Result<(), BillingRunError> {
    #[cfg(test)]
    if CREATION_FAULT.with(|slot| slot.get()) == Some(stage) {
        return Err(BillingRunError::InjectedFailure("directory-creation"));
    }
    #[cfg(not(test))]
    let _ = stage;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupStage {
    ParentSync,
    Lock,
    InitialManifest,
}

#[cfg(test)]
type CleanupHook = Option<(CleanupStage, Box<dyn FnOnce()>)>;

#[cfg(test)]
thread_local! {
    static CLEANUP_HOOK: std::cell::RefCell<CleanupHook> = std::cell::RefCell::new(None);
    static CREATION_FAULT: std::cell::Cell<Option<CreationFault>> = const { std::cell::Cell::new(None) };
}

fn run_cleanup_hook(stage: CleanupStage) {
    #[cfg(test)]
    CLEANUP_HOOK.with(|slot| {
        let should_run = slot
            .borrow()
            .as_ref()
            .is_some_and(|(expected, _)| *expected == stage);
        if should_run {
            if let Some((_, hook)) = slot.borrow_mut().take() {
                hook();
            }
        }
    });
    #[cfg(not(test))]
    let _ = stage;
}

impl BillingRunStore {
    pub fn import_under(
        root: &Path,
        provenance: BillingProvenance,
        rows: &ValidatedBilling,
    ) -> Result<Self, BillingRunError> {
        Self::import_at(
            root.join(Uuid::new_v4().to_string()),
            provenance,
            rows,
            10_000,
        )
    }

    pub fn import_under_cancellable<F>(
        root: &Path,
        provenance: BillingProvenance,
        rows: &ValidatedBilling,
        cancellation: &BillingCancellation,
        mut observer: F,
    ) -> Result<Self, BillingRunError>
    where
        F: FnMut(BillingImportPhase),
    {
        import_at_inner(
            root.join(Uuid::new_v4().to_string()),
            provenance,
            rows,
            10_000,
            || {},
            ImportControl {
                fault: None,
                cancellation: Some(cancellation),
                observer: Some(&mut observer),
            },
        )
    }

    pub fn import_at(
        directory: PathBuf,
        provenance: BillingProvenance,
        rows: &ValidatedBilling,
        segment_rows: usize,
    ) -> Result<Self, BillingRunError> {
        import_at_inner(
            directory,
            provenance,
            rows,
            segment_rows,
            || {},
            ImportControl::normal(),
        )
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn manifest(&self) -> &BillingRunManifest {
        &self.manifest
    }

    pub fn load_manifest(directory: &Path) -> Result<BillingRunManifest, BillingRunError> {
        let directory = open_private_run(directory)?;
        load_manifest_from(&directory)
    }

    pub fn read_complete(directory: &Path) -> Result<BillingRunRead, BillingRunError> {
        read_complete_with_hook(directory, || {})
    }
}

fn import_at_inner<F>(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
    after_create: F,
    control: ImportControl<'_>,
) -> Result<BillingRunStore, BillingRunError>
where
    F: FnOnce(),
{
    let ImportControl {
        fault,
        cancellation,
        observer,
    } = control;
    provenance.validate()?;
    if segment_rows == 0 || segment_rows > MAX_BILLING_ROWS {
        return Err(BillingRunError::InvalidSegmentLimit);
    }
    let created = TrustedDir::create_with_hook(&directory, after_create)?;
    if fault == Some(ImportFault::CreationParentDirectorySync) {
        run_cleanup_hook(CleanupStage::ParentSync);
        created.cleanup_before_manifest();
        return Err(BillingRunError::InjectedFailure("parent-directory-sync"));
    }
    if let Err(error) = created.parent.sync() {
        run_cleanup_hook(CleanupStage::ParentSync);
        created.cleanup_before_manifest();
        return Err(error);
    }
    let lock = match if fault == Some(ImportFault::Lock) {
        Err(BillingRunError::InjectedFailure("lock"))
    } else {
        created.directory.create_file(LOCK)
    } {
        Ok(lock) => lock,
        Err(error) => {
            run_cleanup_hook(CleanupStage::Lock);
            created.cleanup_before_manifest();
            return Err(error);
        }
    };
    let run_id = directory
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| Uuid::parse_str(value).is_ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let started = now_ms();
    let mut manifest = BillingRunManifest {
        schema_version: BILLING_RUN_SCHEMA_VERSION,
        binary_version: crate::VERSION.to_owned(),
        run_id,
        started_at_ms: started,
        completed_at_ms: None,
        clean_shutdown: false,
        provenance_digest: provenance.digest()?,
        provenance,
        normalized_digest: rows.canonical_digest().to_owned(),
        totals: rows.totals().clone(),
        accepted: rows.rows().len() as u64,
        recorded: 0,
        dropped: 0,
        recovery_records: 0,
        next_sequence: 1,
        segments: Vec::new(),
    };
    if fault == Some(ImportFault::InitialManifest) {
        drop(lock);
        run_cleanup_hook(CleanupStage::InitialManifest);
        created.cleanup_before_manifest();
        return Err(BillingRunError::InjectedFailure("initial-manifest"));
    }
    if let Err(error) = write_manifest(&created.directory, &manifest) {
        drop(lock);
        run_cleanup_hook(CleanupStage::InitialManifest);
        created.cleanup_before_manifest();
        return Err(error);
    }
    let write_result = if fault == Some(ImportFault::Segment) {
        Err(BillingRunError::InjectedFailure("segment"))
    } else {
        cancellation_checkpoint(cancellation).and_then(|()| {
            write_segments(
                &created.directory,
                rows.rows(),
                segment_rows,
                &mut manifest,
                fault,
                cancellation,
            )
        })
    };
    let marker_result = (|| {
        let mut marker = created.directory.create_file(INCOMPLETE)?;
        marker.write_all(b"incomplete\n")?;
        marker.sync_all()?;
        created.directory.sync()
    })();
    if let Err(error) = marker_result {
        drop(lock);
        created.cleanup_before_manifest();
        return Err(error);
    }
    write_result?;
    manifest.completed_at_ms = Some(now_ms().max(started));
    manifest.clean_shutdown = true;
    manifest.validate()?;
    if fault == Some(ImportFault::FinalManifest) {
        return Err(BillingRunError::InjectedFailure("final-manifest"));
    }
    cancellation_checkpoint(cancellation)?;
    publish_complete_manifest(
        &created.parent,
        &created.directory,
        &manifest,
        fault,
        cancellation,
        observer,
    )?;
    Ok(BillingRunStore {
        directory,
        manifest,
        _lock: lock,
        _directory_fd: created.directory,
    })
}

fn cancellation_checkpoint(
    cancellation: Option<&BillingCancellation>,
) -> Result<(), BillingRunError> {
    cancellation.map_or(Ok(()), BillingCancellation::checkpoint)
}

#[cfg(test)]
fn import_at_with_fault(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
    fault: ImportFault,
) -> Result<BillingRunStore, BillingRunError> {
    import_at_inner(
        directory,
        provenance,
        rows,
        segment_rows,
        || {},
        ImportControl {
            fault: Some(fault),
            cancellation: None,
            observer: None,
        },
    )
}

#[cfg(test)]
fn import_at_with_sync_error(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
) -> Result<BillingRunStore, BillingRunError> {
    import_at_with_fault(
        directory,
        provenance,
        rows,
        segment_rows,
        ImportFault::RealPostTransitionSync,
    )
}

#[cfg(test)]
fn import_at_with_cleanup_swap<F>(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
    stage: CleanupStage,
    hook: F,
) -> Result<BillingRunStore, BillingRunError>
where
    F: FnOnce() + 'static,
{
    CLEANUP_HOOK.with(|slot| *slot.borrow_mut() = Some((stage, Box::new(hook))));
    let fault = match stage {
        CleanupStage::ParentSync => ImportFault::CreationParentDirectorySync,
        CleanupStage::Lock => ImportFault::Lock,
        CleanupStage::InitialManifest => ImportFault::InitialManifest,
    };
    import_at_with_fault(directory, provenance, rows, segment_rows, fault)
}

#[cfg(test)]
fn import_at_with_creation_fault<F>(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
    fault: CreationFault,
    hook: F,
) -> Result<BillingRunStore, BillingRunError>
where
    F: FnOnce(),
{
    CREATION_FAULT.with(|slot| slot.set(Some(fault)));
    let result = import_at_inner(
        directory,
        provenance,
        rows,
        segment_rows,
        hook,
        ImportControl::normal(),
    );
    CREATION_FAULT.with(|slot| slot.set(None));
    result
}

#[cfg(test)]
fn import_at_with_hook<F>(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
    hook: F,
) -> Result<BillingRunStore, BillingRunError>
where
    F: FnOnce(),
{
    import_at_inner(
        directory,
        provenance,
        rows,
        segment_rows,
        hook,
        ImportControl::normal(),
    )
}

#[cfg(test)]
fn import_at_cancellable_with_hook<F>(
    directory: PathBuf,
    provenance: BillingProvenance,
    rows: &ValidatedBilling,
    segment_rows: usize,
    cancellation: &BillingCancellation,
    mut observer: F,
) -> Result<BillingRunStore, BillingRunError>
where
    F: FnMut(BillingImportPhase),
{
    import_at_inner(
        directory,
        provenance,
        rows,
        segment_rows,
        || {},
        ImportControl {
            fault: None,
            cancellation: Some(cancellation),
            observer: Some(&mut observer),
        },
    )
}

fn load_manifest_from(directory: &TrustedDir) -> Result<BillingRunManifest, BillingRunError> {
    let bytes = read_bounded_file(
        directory,
        MANIFEST,
        MAX_MANIFEST_BYTES,
        BillingRunError::ManifestTooLarge,
    )?;
    let mut manifest: BillingRunManifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    let incomplete = directory.has_private_file(INCOMPLETE)?;
    let complete = directory.has_private_file(COMPLETE)?;
    if incomplete || !complete {
        manifest.clean_shutdown = false;
        manifest.completed_at_ms = None;
    }
    Ok(manifest)
}

fn read_complete_with_hook<F>(directory: &Path, hook: F) -> Result<BillingRunRead, BillingRunError>
where
    F: FnOnce(),
{
    let directory = open_private_run(directory)?;
    hook();
    let manifest = load_manifest_from(&directory)?;
    if !manifest.clean_shutdown || !manifest.reconciled() {
        return Err(BillingRunError::Incomplete);
    }
    let capacity =
        usize::try_from(manifest.recorded).map_err(|_| BillingRunError::CounterOverflow)?;
    let mut rows = Vec::with_capacity(capacity);
    let mut sequence = 1u64;
    for segment in &manifest.segments {
        let maximum = max_segment_bytes(segment.records)?;
        if segment.bytes > maximum {
            return Err(BillingRunError::SegmentTooLarge);
        }
        let bytes = read_exact_bounded_file(&directory, &segment.name, segment.bytes, maximum)?;
        let frames = decode_segment(&bytes)?;
        if bytes.len() as u64 != segment.bytes
            || domain_digest(b"bowline.billing.segment.v1", &bytes) != segment.digest
        {
            return Err(BillingRunError::CorruptEvidence);
        }
        if frames.len() as u64 != segment.records
            || frames.first().map(|frame| frame.sequence) != Some(segment.first_sequence)
            || frames.last().map(|frame| frame.sequence) != Some(segment.last_sequence)
        {
            return Err(BillingRunError::InvalidSegmentInventory);
        }
        for frame in frames {
            if frame.sequence != sequence {
                return Err(BillingRunError::InvalidSequence);
            }
            sequence = sequence
                .checked_add(1)
                .ok_or(BillingRunError::InvalidSequence)?;
            rows.push(frame.row);
        }
    }
    if rows.len() as u64 != manifest.recorded {
        return Err(BillingRunError::InvalidSequence);
    }
    let validated =
        validate_normalized_rows(rows.clone()).map_err(|_| BillingRunError::UndecodableEvidence)?;
    if validated.canonical_digest() != manifest.normalized_digest
        || validated.totals() != &manifest.totals
    {
        return Err(BillingRunError::SemanticMismatch);
    }
    Ok(BillingRunRead {
        rows,
        recovery: BillingRecovery::Clean {
            records: manifest.recorded,
        },
        normalized_digest: validated.canonical_digest().to_owned(),
        manifest,
    })
}

fn open_private_run(path: &Path) -> Result<TrustedDir, BillingRunError> {
    let directory = TrustedDir::open_existing(path)?;
    validate_private_directory_fd(&directory.file)?;
    Ok(directory)
}

fn read_bounded_file(
    directory: &TrustedDir,
    name: &str,
    maximum: u64,
    too_large: BillingRunError,
) -> Result<Vec<u8>, BillingRunError> {
    let file = directory.open_read(name)?;
    let metadata = file.metadata()?;
    if metadata.len() > maximum {
        return Err(too_large);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| BillingRunError::SegmentTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(
        maximum
            .checked_add(1)
            .ok_or(BillingRunError::CounterOverflow)?,
    )
    .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(BillingRunError::CorruptEvidence);
    }
    Ok(bytes)
}

fn read_exact_bounded_file(
    directory: &TrustedDir,
    name: &str,
    expected: u64,
    maximum: u64,
) -> Result<Vec<u8>, BillingRunError> {
    if expected < MAGIC.len() as u64 || expected > maximum {
        return Err(BillingRunError::SegmentTooLarge);
    }
    let file = directory.open_read(name)?;
    let metadata = file.metadata()?;
    if metadata.len() > maximum {
        return Err(BillingRunError::SegmentTooLarge);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| BillingRunError::SegmentTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(
        maximum
            .checked_add(1)
            .ok_or(BillingRunError::CounterOverflow)?,
    )
    .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(BillingRunError::CorruptEvidence);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingRecovery {
    Clean { records: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingRunRead {
    pub rows: Vec<BillingRow>,
    pub recovery: BillingRecovery,
    pub normalized_digest: String,
    pub manifest: BillingRunManifest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingFrame {
    sequence: u64,
    row: BillingRow,
}

fn write_segments(
    directory: &TrustedDir,
    rows: &[BillingRow],
    segment_rows: usize,
    manifest: &mut BillingRunManifest,
    fault: Option<ImportFault>,
    cancellation: Option<&BillingCancellation>,
) -> Result<(), BillingRunError> {
    for (index, chunk) in rows.chunks(segment_rows).enumerate() {
        cancellation_checkpoint(cancellation)?;
        let name = format!("rows-{:06}.bwb", index + 1);
        let first = manifest.next_sequence;
        let mut file = directory.create_file(&name)?;
        file.write_all(MAGIC)?;
        let mut next_sequence = first;
        for row in chunk {
            let frame = BillingFrame {
                sequence: next_sequence,
                row: row.clone(),
            };
            let payload = serde_json::to_vec(&frame)?;
            if payload.len() > MAX_FRAME_BYTES {
                return Err(BillingRunError::FrameTooLarge);
            }
            let length =
                u32::try_from(payload.len()).map_err(|_| BillingRunError::FrameTooLarge)?;
            file.write_all(&length.to_le_bytes())?;
            file.write_all(&crc32fast::hash(&payload).to_le_bytes())?;
            file.write_all(&payload)?;
            next_sequence = next_sequence
                .checked_add(1)
                .ok_or(BillingRunError::CounterOverflow)?;
        }
        file.sync_all()?;
        let records = u64::try_from(chunk.len()).map_err(|_| BillingRunError::CounterOverflow)?;
        let bytes = read_bounded_file(
            directory,
            &name,
            max_segment_bytes(records)?,
            BillingRunError::SegmentTooLarge,
        )?;
        manifest.recorded = manifest
            .recorded
            .checked_add(records)
            .ok_or(BillingRunError::CounterOverflow)?;
        manifest.next_sequence = next_sequence;
        manifest.segments.push(BillingSegment {
            name,
            first_sequence: first,
            last_sequence: manifest.next_sequence - 1,
            records,
            bytes: bytes.len() as u64,
            digest: domain_digest(b"bowline.billing.segment.v1", &bytes),
        });
        if fault == Some(ImportFault::IntermediateManifest) {
            return Err(BillingRunError::InjectedFailure("intermediate-manifest"));
        }
        write_manifest(directory, manifest)?;
        cancellation_checkpoint(cancellation)?;
    }
    directory.sync()?;
    Ok(())
}

fn max_segment_bytes(records: u64) -> Result<u64, BillingRunError> {
    if records == 0 || records > MAX_BILLING_ROWS as u64 {
        return Err(BillingRunError::InvalidSegmentInventory);
    }
    records
        .checked_mul(8 + MAX_FRAME_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(MAGIC.len() as u64))
        .ok_or(BillingRunError::CounterOverflow)
}

fn decode_segment(bytes: &[u8]) -> Result<Vec<BillingFrame>, BillingRunError> {
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err(BillingRunError::CorruptEvidence);
    }
    let mut offset = MAGIC.len();
    let mut frames = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            return Err(BillingRunError::TornEvidence);
        }
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        offset += 8;
        if length > MAX_FRAME_BYTES {
            return Err(BillingRunError::CorruptEvidence);
        }
        if bytes.len() - offset < length {
            return Err(BillingRunError::TornEvidence);
        }
        let payload = &bytes[offset..offset + length];
        if crc32fast::hash(payload) != crc {
            return Err(BillingRunError::CorruptEvidence);
        }
        let frame: BillingFrame =
            serde_json::from_slice(payload).map_err(|_| BillingRunError::UndecodableEvidence)?;
        frames.push(frame);
        offset += length;
    }
    Ok(frames)
}

fn write_manifest(
    directory: &TrustedDir,
    value: &BillingRunManifest,
) -> Result<(), BillingRunError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BillingRunError::ManifestTooLarge);
    }
    let temporary = format!(".manifest-{}.tmp", Uuid::new_v4());
    let result = (|| {
        let mut file = directory.create_file(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        directory.sync()?;
        directory.rename(&temporary, MANIFEST)
    })();
    if result.is_err() {
        directory.unlink_file(&temporary);
    }
    result
}

fn publish_complete_manifest(
    parent: &TrustedDir,
    directory: &TrustedDir,
    value: &BillingRunManifest,
    fault: Option<ImportFault>,
    cancellation: Option<&BillingCancellation>,
    mut observer: Option<&mut dyn FnMut(BillingImportPhase)>,
) -> Result<(), BillingRunError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BillingRunError::ManifestTooLarge);
    }
    let temporary = format!(".manifest-{}.tmp", Uuid::new_v4());
    let result = (|| {
        let mut file = directory.create_file(&temporary)?;
        if fault == Some(ImportFault::TempWrite) {
            file.write_all(&bytes[..bytes.len().min(16)])?;
            return Err(BillingRunError::InjectedFailure("temp-write"));
        }
        file.write_all(&bytes)?;
        if fault == Some(ImportFault::FileSync) {
            return Err(BillingRunError::InjectedFailure("file-sync"));
        }
        file.sync_all()?;
        directory.sync()?;
        if fault == Some(ImportFault::Rename) {
            return Err(BillingRunError::InjectedFailure("rename"));
        }
        directory.rename(&temporary, MANIFEST)?;
        if fault == Some(ImportFault::RunDirectorySync) {
            return Err(BillingRunError::InjectedFailure("run-directory-sync"));
        }
        directory.sync()?;
        if fault == Some(ImportFault::ParentDirectorySync) {
            return Err(BillingRunError::InjectedFailure("parent-directory-sync"));
        }
        parent.sync()?;
        if let Some(observer) = observer.as_deref_mut() {
            observer(BillingImportPhase::BeforeCompleteTransition);
        }
        let transition = || {
            directory.rename(INCOMPLETE, COMPLETE)?;
            sync_completed_transition(directory, fault)
        };
        match cancellation {
            Some(cancellation) => cancellation.complete(transition)?,
            None => transition()?,
        }
        if let Some(observer) = observer.as_deref_mut() {
            observer(BillingImportPhase::AfterCompleteTransition);
        }
        Ok(())
    })();
    if result.is_err() {
        directory.unlink_file(&temporary);
    }
    result
}

fn sync_completed_transition(
    directory: &TrustedDir,
    fault: Option<ImportFault>,
) -> Result<(), BillingRunError> {
    let sync_result = if fault == Some(ImportFault::PostTransitionSync)
        || fault == Some(ImportFault::RollbackSync)
        || fault == Some(ImportFault::RollbackRename)
        || fault == Some(ImportFault::RealPostTransitionSync)
        || fault == Some(ImportFault::FallbackMarkerCreate)
        || fault == Some(ImportFault::FallbackMarkerWrite)
        || fault == Some(ImportFault::FallbackMarkerFileSync)
        || fault == Some(ImportFault::FallbackFirstDirectorySync)
        || fault == Some(ImportFault::FallbackCompleteRemoval)
        || fault == Some(ImportFault::FallbackFinalDirectorySync)
    {
        Err(BillingRunError::Io(std::io::Error::other(
            "injected post-transition sync failure",
        )))
    } else {
        directory.sync()
    };
    let error = match sync_result {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };

    if establish_incomplete_fallback(directory, fault).is_err() {
        let removed_complete = directory
            .remove_file(COMPLETE)
            .and_then(|()| directory.sync());
        return if removed_complete.is_ok() {
            Err(error)
        } else {
            Err(BillingRunError::CompletionIndeterminate)
        };
    }
    if fault == Some(ImportFault::FallbackCompleteRemoval)
        || fault == Some(ImportFault::RollbackRename)
    {
        return Err(error);
    }
    if directory.remove_file(COMPLETE).is_err() {
        return Err(error);
    }
    if fault == Some(ImportFault::FallbackFinalDirectorySync)
        || fault == Some(ImportFault::RollbackSync)
    {
        return Err(error);
    }
    directory.sync()?;
    Err(error)
}

fn establish_incomplete_fallback(
    directory: &TrustedDir,
    fault: Option<ImportFault>,
) -> Result<(), BillingRunError> {
    if fault == Some(ImportFault::FallbackMarkerCreate) {
        return Err(BillingRunError::InjectedFailure("fallback-marker-create"));
    }
    let mut marker = directory.create_file(INCOMPLETE)?;
    if fault == Some(ImportFault::FallbackMarkerWrite) {
        return Err(BillingRunError::InjectedFailure("fallback-marker-write"));
    }
    marker.write_all(b"incomplete\n")?;
    if fault == Some(ImportFault::FallbackMarkerFileSync) {
        return Err(BillingRunError::InjectedFailure(
            "fallback-marker-file-sync",
        ));
    }
    marker.sync_all()?;
    if fault == Some(ImportFault::FallbackFirstDirectorySync) {
        return Err(BillingRunError::InjectedFailure(
            "fallback-first-directory-sync",
        ));
    }
    directory.sync()
}
fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}
fn validate_digest(value: &str) -> Result<(), BillingRunError> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(BillingRunError::InvalidDigest)
    }
}
fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Error)]
pub enum BillingRunError {
    #[error("billing import cancelled before durable completion")]
    Cancelled,
    #[error("invalid billing provenance")]
    InvalidProvenance,
    #[error("invalid evidence digest")]
    InvalidDigest,
    #[error("invalid billing manifest")]
    InvalidManifest,
    #[error("billing manifest exceeds byte limit")]
    ManifestTooLarge,
    #[error("invalid segment row limit")]
    InvalidSegmentLimit,
    #[error("billing frame exceeds byte limit")]
    FrameTooLarge,
    #[error("billing segment exceeds its checked byte limit")]
    SegmentTooLarge,
    #[error("billing segment inventory disagrees with decoded frames")]
    InvalidSegmentInventory,
    #[error("billing counter overflow")]
    CounterOverflow,
    #[error("unsafe billing evidence path or mode")]
    UnsafePath,
    #[error("billing evidence is incomplete")]
    Incomplete,
    #[error("billing evidence has a torn frame")]
    TornEvidence,
    #[error("billing evidence is corrupt")]
    CorruptEvidence,
    #[error("billing evidence is undecodable or semantically invalid")]
    UndecodableEvidence,
    #[error("billing sequence is invalid")]
    InvalidSequence,
    #[error("billing manifest and rows disagree")]
    SemanticMismatch,
    #[error("billing completion is indeterminate after transition and fallback errors")]
    CompletionIndeterminate,
    #[error("injected billing import failure at {0}")]
    InjectedFailure(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_before_complete_transition_preserves_incomplete_evidence() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000099");
        let cancellation = BillingCancellation::new();
        let result = import_at_cancellable_with_hook(
            run.clone(),
            provenance(),
            &validated(2),
            1,
            &cancellation,
            |phase| {
                if phase == BillingImportPhase::BeforeCompleteTransition {
                    assert!(cancellation.cancel());
                }
            },
        );
        assert!(matches!(result, Err(BillingRunError::Cancelled)));
        let manifest = BillingRunStore::load_manifest(&run).unwrap();
        assert!(!manifest.clean_shutdown);
        assert!(run.join(INCOMPLETE).is_file());
        assert!(!run.join(COMPLETE).exists());
    }

    #[test]
    fn cancellation_after_complete_transition_is_ignored_for_success_linearization() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000100");
        let cancellation = BillingCancellation::new();
        let store = import_at_cancellable_with_hook(
            run.clone(),
            provenance(),
            &validated(2),
            1,
            &cancellation,
            |phase| {
                if phase == BillingImportPhase::AfterCompleteTransition {
                    assert!(!cancellation.cancel());
                }
            },
        )
        .unwrap();
        assert!(store.manifest().clean_shutdown);
        assert!(run.join(COMPLETE).is_file());
        assert!(!run.join(INCOMPLETE).exists());
    }
    use crate::{
        billing::{validate_billing_rows, BillingInputRow},
        supply::Registry,
    };
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{symlink, PermissionsExt},
        process::Command,
    };

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }
    fn validated(count: u64) -> ValidatedBilling {
        let registry = Registry::from_json(r#"{"feed_version":"fixture","entries":[{"id":"public/east","model":"model","location":"fixture","attributes":{"class":"public-api","jurisdiction":"us","retention":"unknown","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}}]}"#).unwrap();
        let rows = (0..count)
            .map(|i| BillingInputRow {
                schema_version: 1,
                row_id: format!("row-{i}"),
                period_start_ms: i,
                period_end_ms: i + 1,
                supply_id: "public/east".into(),
                currency: "USD".into(),
                charge_basis: "inference-usage-net".into(),
                charge_usd: "1".into(),
                request_count: Some(1),
                input_tokens: None,
                output_tokens: None,
            })
            .collect();
        validate_billing_rows(rows, &registry).unwrap()
    }
    fn provenance() -> BillingProvenance {
        BillingProvenance {
            source_format: BillingSourceFormat::CanonicalJsonl,
            source_digest: digest('a'),
            mapping_digest: None,
            registry_digest: digest('b'),
            charge_basis: ChargeBasis::InferenceUsageNet,
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let system_temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("bowline-billing-")
            .tempdir_in(system_temp)
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn imports_private_framed_reconciled_run_and_reads_semantically() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000001");
        let store = BillingRunStore::import_at(run, provenance(), &validated(3), 2).unwrap();
        let manifest = store.manifest().clone();
        assert!(manifest.clean_shutdown && manifest.reconciled());
        assert_eq!(manifest.accepted, 3);
        assert_eq!(manifest.recorded, 3);
        assert_eq!(manifest.dropped, 0);
        assert_eq!(manifest.segments.len(), 2);
        let mode = fs::metadata(store.directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        for name in ["manifest.json", "rows-000001.bwb", "rows-000002.bwb"] {
            assert_eq!(
                fs::metadata(store.directory().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let read = BillingRunStore::read_complete(store.directory()).unwrap();
        assert_eq!(read.rows.len(), 3);
        assert_eq!(read.recovery, BillingRecovery::Clean { records: 3 });
        assert_eq!(read.normalized_digest, manifest.normalized_digest);
    }

    #[test]
    fn writer_exclusion_and_corrupt_torn_undecodable_semantic_refusal() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000002");
        let store =
            BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 10).unwrap();
        assert!(BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 10).is_err());
        let segment = run.join("rows-000001.bwb");
        let original = fs::read(&segment).unwrap();
        fs::write(&segment, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            BillingRunStore::read_complete(&run),
            Err(BillingRunError::TornEvidence)
        ));
        fs::write(&segment, &original).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&segment, corrupt).unwrap();
        assert!(matches!(
            BillingRunStore::read_complete(&run),
            Err(BillingRunError::CorruptEvidence)
        ));
        drop(store);
    }

    #[test]
    fn undecodable_and_semantically_invalid_crc_valid_frames_are_refused() {
        let temp = private_tempdir();
        let undecodable_run = temp.path().join("00000000-0000-4000-8000-000000000003");
        let undecodable =
            BillingRunStore::import_at(undecodable_run.clone(), provenance(), &validated(1), 10)
                .unwrap();
        let segment = undecodable_run.join("rows-000001.bwb");
        let mut bytes = fs::read(&segment).unwrap();
        let payload_start = MAGIC.len() + 8;
        bytes[payload_start] = b'!';
        let crc = crc32fast::hash(&bytes[payload_start..]);
        bytes[MAGIC.len() + 4..MAGIC.len() + 8].copy_from_slice(&crc.to_le_bytes());
        fs::write(&segment, bytes).unwrap();
        assert!(matches!(
            BillingRunStore::read_complete(&undecodable_run),
            Err(BillingRunError::UndecodableEvidence)
        ));
        drop(undecodable);

        let semantic_run = temp.path().join("00000000-0000-4000-8000-000000000004");
        let semantic =
            BillingRunStore::import_at(semantic_run.clone(), provenance(), &validated(1), 10)
                .unwrap();
        let segment = semantic_run.join("rows-000001.bwb");
        let mut bytes = fs::read(&segment).unwrap();
        let payload_start = MAGIC.len() + 8;
        let mut frame: serde_json::Value = serde_json::from_slice(&bytes[payload_start..]).unwrap();
        frame["row"]["row_id"] = serde_json::Value::String("bad/id".into());
        let payload = serde_json::to_vec(&frame).unwrap();
        let length = u32::try_from(payload.len()).unwrap();
        bytes.truncate(MAGIC.len());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        bytes.extend_from_slice(&payload);
        fs::write(&segment, &bytes).unwrap();
        let mut manifest = semantic.manifest().clone();
        manifest.segments[0].bytes = bytes.len() as u64;
        manifest.segments[0].digest = domain_digest(b"bowline.billing.segment.v1", &bytes);
        write_manifest(&open_private_run(&semantic_run).unwrap(), &manifest).unwrap();
        assert!(matches!(
            BillingRunStore::read_complete(&semantic_run),
            Err(BillingRunError::UndecodableEvidence)
        ));
    }

    #[test]
    fn provenance_is_strict_content_free_and_mapping_is_format_consistent() {
        let mut p = provenance();
        p.mapping_digest = Some(digest('c'));
        assert!(p.validate().is_err());
        p.source_format = BillingSourceFormat::MappedCsv;
        assert!(p.validate().is_ok());
        let json = serde_json::to_string(&p).unwrap();
        for forbidden in ["path", "prompt", "response", "authorization", "raw"] {
            assert!(!json.contains(forbidden));
        }
    }

    #[test]
    fn rejects_symlink_components_and_survives_directory_swap_after_trusted_open() {
        let temp = private_tempdir();
        let real_parent = temp.path().join("real");
        fs::create_dir(&real_parent).unwrap();
        let alias = temp.path().join("alias");
        symlink(&real_parent, &alias).unwrap();
        let through_symlink = alias.join("00000000-0000-4000-8000-000000000005");
        assert!(BillingRunStore::import_at(
            through_symlink.clone(),
            provenance(),
            &validated(1),
            10
        )
        .is_err());
        assert!(!real_parent
            .join(through_symlink.file_name().unwrap())
            .exists());

        let create_run = temp.path().join("00000000-0000-4000-8000-000000000015");
        let create_moved = temp.path().join("create-moved");
        let create_attacker = temp.path().join("create-attacker");
        fs::create_dir(&create_attacker).unwrap();
        fs::set_permissions(&create_attacker, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(create_attacker.join("sentinel"), b"untouched").unwrap();
        let result =
            import_at_with_hook(create_run.clone(), provenance(), &validated(2), 1, || {
                fs::rename(&create_run, &create_moved).unwrap();
                symlink(&create_attacker, &create_run).unwrap();
            });
        assert!(matches!(result, Err(BillingRunError::UnsafePath)));
        assert_eq!(
            fs::read(create_attacker.join("sentinel")).unwrap(),
            b"untouched"
        );
        assert!(!create_attacker.join(LOCK).exists());
        assert!(!create_attacker.join(MANIFEST).exists());

        let run = temp.path().join("00000000-0000-4000-8000-000000000006");
        let store =
            BillingRunStore::import_at(run.clone(), provenance(), &validated(2), 1).unwrap();
        drop(store);
        let moved = temp.path().join("moved");
        let attacker = temp.path().join("attacker");
        fs::create_dir(&attacker).unwrap();
        fs::set_permissions(&attacker, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(attacker.join("sentinel"), b"untouched").unwrap();
        let read = read_complete_with_hook(&run, || {
            fs::rename(&run, &moved).unwrap();
            symlink(&attacker, &run).unwrap();
        })
        .unwrap();
        assert_eq!(read.rows.len(), 2);
        assert_eq!(fs::read(attacker.join("sentinel")).unwrap(), b"untouched");
    }

    #[test]
    fn segment_reads_are_bounded_before_allocation() {
        let temp = private_tempdir();
        for sparse in [false, true] {
            let run = temp.path().join(if sparse {
                "00000000-0000-4000-8000-000000000007"
            } else {
                "00000000-0000-4000-8000-000000000008"
            });
            let store =
                BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 10).unwrap();
            let path = run.join("rows-000001.bwb");
            let excessive = max_segment_bytes(1).unwrap() + 1;
            if sparse {
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(excessive)
                    .unwrap();
            } else {
                fs::write(&path, vec![0; usize::try_from(excessive).unwrap()]).unwrap();
            }
            assert!(matches!(
                BillingRunStore::read_complete(&run),
                Err(BillingRunError::SegmentTooLarge)
            ));
            drop(store);
        }
    }

    #[test]
    fn segment_inventory_rejects_digest_valid_frame_redistribution() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000009");
        let store =
            BillingRunStore::import_at(run.clone(), provenance(), &validated(4), 2).unwrap();
        let mut first = split_raw_frames(&fs::read(run.join("rows-000001.bwb")).unwrap());
        let mut second = split_raw_frames(&fs::read(run.join("rows-000002.bwb")).unwrap());
        let moved = first.pop().unwrap();
        second.insert(0, moved);
        let first_bytes = join_raw_frames(&first);
        let second_bytes = join_raw_frames(&second);
        fs::write(run.join("rows-000001.bwb"), &first_bytes).unwrap();
        fs::write(run.join("rows-000002.bwb"), &second_bytes).unwrap();
        let mut manifest = store.manifest().clone();
        for (segment, bytes) in manifest
            .segments
            .iter_mut()
            .zip([first_bytes, second_bytes])
        {
            segment.bytes = bytes.len() as u64;
            segment.digest = domain_digest(b"bowline.billing.segment.v1", &bytes);
        }
        write_manifest(&open_private_run(&run).unwrap(), &manifest).unwrap();
        assert!(matches!(
            BillingRunStore::read_complete(&run),
            Err(BillingRunError::InvalidSegmentInventory)
        ));
    }

    #[test]
    fn failure_boundaries_cleanup_before_initial_manifest_and_preserve_after() {
        let temp = private_tempdir();
        let stages = [
            ImportFault::InitialManifest,
            ImportFault::Segment,
            ImportFault::IntermediateManifest,
            ImportFault::FinalManifest,
        ];
        for (index, fault) in stages.into_iter().enumerate() {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 10));
            assert!(
                import_at_with_fault(run.clone(), provenance(), &validated(3), 2, fault).is_err()
            );
            if fault == ImportFault::InitialManifest {
                assert!(!run.exists());
            } else {
                let manifest = BillingRunStore::load_manifest(&run).unwrap();
                assert!(!manifest.clean_shutdown);
                assert!(manifest.completed_at_ms.is_none());
            }
        }
    }

    #[test]
    fn parent_and_opened_objects_require_exact_private_owner_modes() {
        let temp = private_tempdir();
        let insecure_parent = temp.path().join("insecure");
        fs::create_dir(&insecure_parent).unwrap();
        fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o755)).unwrap();
        let rejected = insecure_parent.join("00000000-0000-4000-8000-000000000020");
        assert!(BillingRunStore::import_at(rejected, provenance(), &validated(1), 1).is_err());

        for (index, mode) in [0o700, 0o400].into_iter().enumerate() {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 21));
            let store =
                BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 1).unwrap();
            drop(store);
            fs::set_permissions(run.join(MANIFEST), fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                BillingRunStore::load_manifest(&run),
                Err(BillingRunError::UnsafePath)
            ));
        }

        let run = temp.path().join("00000000-0000-4000-8000-000000000023");
        let store =
            BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 1).unwrap();
        drop(store);
        fs::set_permissions(&run, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            BillingRunStore::load_manifest(&run),
            Err(BillingRunError::UnsafePath)
        ));

        for mode in [0o4600, 0o2600, 0o1600] {
            assert!(!exact_private_mode(mode, 0o600));
        }
        for mode in [0o4700, 0o2700, 0o1700] {
            assert!(!exact_private_mode(mode, 0o700));
        }
        assert!(exact_private_mode(0o600, 0o600));
        assert!(exact_private_mode(0o700, 0o700));
    }

    #[test]
    fn real_post_transition_sync_error_uses_fail_closed_rollback() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000064");
        assert!(import_at_with_sync_error(run.clone(), provenance(), &validated(1), 1).is_err());
        assert!(matches!(
            BillingRunStore::read_complete(&run),
            Err(BillingRunError::Incomplete)
        ));
    }

    #[test]
    fn cleanup_boundaries_never_remove_replacement_inode() {
        let temp = private_tempdir();
        for (index, stage) in [
            CleanupStage::ParentSync,
            CleanupStage::Lock,
            CleanupStage::InitialManifest,
        ]
        .into_iter()
        .enumerate()
        {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 65));
            let moved = temp.path().join(format!("moved-{index}"));
            let swapped_run = run.clone();
            let swapped_moved = moved.clone();
            let result = import_at_with_cleanup_swap(
                run.clone(),
                provenance(),
                &validated(1),
                1,
                stage,
                move || {
                    fs::rename(&swapped_run, &swapped_moved).unwrap();
                    fs::create_dir(&swapped_run).unwrap();
                    fs::set_permissions(&swapped_run, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::write(swapped_run.join("sentinel"), b"untouched").unwrap();
                    fs::set_permissions(
                        swapped_run.join("sentinel"),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                },
            );
            assert!(result.is_err());
            assert_eq!(fs::read(run.join("sentinel")).unwrap(), b"untouched");
        }
    }

    #[test]
    fn publication_faults_never_leave_a_clean_manifest() {
        let temp = private_tempdir();
        for (index, fault) in [
            ImportFault::TempWrite,
            ImportFault::FileSync,
            ImportFault::Rename,
            ImportFault::RunDirectorySync,
            ImportFault::ParentDirectorySync,
            ImportFault::CreationParentDirectorySync,
        ]
        .into_iter()
        .enumerate()
        {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 30));
            assert!(
                import_at_with_fault(run.clone(), provenance(), &validated(2), 1, fault).is_err()
            );
            if fault == ImportFault::CreationParentDirectorySync {
                assert!(!run.exists());
            } else {
                let manifest = BillingRunStore::load_manifest(&run).unwrap();
                assert!(!manifest.clean_shutdown);
            }
        }
    }

    #[test]
    fn post_transition_failures_are_fail_closed_or_return_success() {
        let temp = private_tempdir();
        for (index, fault) in [ImportFault::PostTransitionSync, ImportFault::RollbackSync]
            .into_iter()
            .enumerate()
        {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 50));
            assert!(
                import_at_with_fault(run.clone(), provenance(), &validated(1), 1, fault).is_err()
            );
            assert!(matches!(
                BillingRunStore::read_complete(&run),
                Err(BillingRunError::Incomplete)
            ));
        }
        let run = temp.path().join("00000000-0000-4000-8000-000000000052");
        assert!(import_at_with_fault(
            run.clone(),
            provenance(),
            &validated(1),
            1,
            ImportFault::RollbackRename
        )
        .is_err());
        assert!(matches!(
            BillingRunStore::read_complete(&run),
            Err(BillingRunError::Incomplete)
        ));
    }

    #[test]
    fn fallback_wrapper_failures_never_return_error_with_complete_evidence() {
        let temp = private_tempdir();
        for (index, fault) in [
            ImportFault::FallbackMarkerCreate,
            ImportFault::FallbackMarkerWrite,
            ImportFault::FallbackMarkerFileSync,
            ImportFault::FallbackFirstDirectorySync,
            ImportFault::FallbackCompleteRemoval,
            ImportFault::FallbackFinalDirectorySync,
        ]
        .into_iter()
        .enumerate()
        {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 70));
            let result = import_at_with_fault(run.clone(), provenance(), &validated(1), 1, fault);
            assert!(result.is_err(), "{fault:?} unexpectedly succeeded");
            assert!(matches!(
                BillingRunStore::read_complete(&run),
                Err(BillingRunError::Incomplete)
            ));
        }
    }

    #[test]
    fn every_post_mkdir_failure_cleans_original_and_preserves_replacement() {
        let temp = private_tempdir();
        for (index, fault) in [
            CreationFault::Certification,
            CreationFault::Identity,
            CreationFault::Chmod,
            CreationFault::FinalOpen,
            CreationFault::FinalValidation,
        ]
        .into_iter()
        .enumerate()
        {
            let run = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 80));
            assert!(import_at_with_creation_fault(
                run.clone(),
                provenance(),
                &validated(1),
                1,
                fault,
                || {}
            )
            .is_err());
            assert!(!run.exists(), "{fault:?} left the original directory");
            drop(BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 1).unwrap());

            let swapped = temp
                .path()
                .join(format!("00000000-0000-4000-8000-{:012}", index + 90));
            let replacement = temp.path().join(format!("replacement-{index}"));
            fs::create_dir(&replacement).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(replacement.join("sentinel"), b"untouched").unwrap();
            fs::set_permissions(
                replacement.join("sentinel"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let swapped_path = swapped.clone();
            let replacement_path = replacement.clone();
            assert!(import_at_with_creation_fault(
                swapped.clone(),
                provenance(),
                &validated(1),
                1,
                fault,
                move || fs::rename(&replacement_path, &swapped_path).unwrap()
            )
            .is_err());
            assert_eq!(fs::read(swapped.join("sentinel")).unwrap(), b"untouched");
            fs::remove_file(swapped.join("sentinel")).unwrap();
            fs::remove_dir(&swapped).unwrap();
            drop(BillingRunStore::import_at(swapped, provenance(), &validated(1), 1).unwrap());
        }
    }

    #[test]
    fn manifest_counter_and_timestamp_contract_is_checked() {
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000053");
        assert!(import_at_with_fault(
            run.clone(),
            provenance(),
            &validated(2),
            1,
            ImportFault::Segment
        )
        .is_err());
        let base = BillingRunStore::load_manifest(&run).unwrap();
        assert!(base.validate().is_ok());
        type ManifestMutation = Box<dyn Fn(&mut BillingRunManifest)>;
        let mutations: Vec<ManifestMutation> = vec![
            Box::new(|m| m.accepted = 0),
            Box::new(|m| m.accepted = MAX_BILLING_ROWS as u64 + 1),
            Box::new(|m| m.totals.rows = m.accepted + 1),
            Box::new(|m| m.recorded = m.accepted + 1),
            Box::new(|m| m.dropped = 1),
            Box::new(|m| m.recovery_records = 1),
            Box::new(|m| m.next_sequence = 2),
            Box::new(|m| m.started_at_ms = crate::billing::MAX_BILLING_TIMESTAMP_MS + 1),
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert!(changed.validate().is_err());
        }

        let complete_run = temp.path().join("00000000-0000-4000-8000-000000000054");
        let store =
            BillingRunStore::import_at(complete_run, provenance(), &validated(1), 1).unwrap();
        let mut boundary = store.manifest().clone();
        boundary.started_at_ms = crate::billing::MAX_BILLING_TIMESTAMP_MS;
        boundary.completed_at_ms = Some(crate::billing::MAX_BILLING_TIMESTAMP_MS);
        assert!(boundary.validate().is_ok());
        boundary.completed_at_ms = Some(crate::billing::MAX_BILLING_TIMESTAMP_MS + 1);
        assert!(boundary.validate().is_err());
    }

    #[test]
    fn exact_creation_modes_ignore_process_umask() {
        for mask in ["000", "777"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "billing_run::tests::umask_creation_child",
                    "--nocapture",
                ])
                .env("BOWLINE_BILLING_UMASK", mask)
                .status()
                .unwrap();
            assert!(status.success(), "umask child failed for {mask}");
        }
    }

    #[test]
    fn umask_creation_child() {
        let Ok(mask) = std::env::var("BOWLINE_BILLING_UMASK") else {
            return;
        };
        let mask = u32::from_str_radix(&mask, 8).unwrap();
        let previous = unsafe { libc::umask(mask as libc::mode_t) };
        let temp = private_tempdir();
        let run = temp.path().join("00000000-0000-4000-8000-000000000040");
        let store =
            BillingRunStore::import_at(run.clone(), provenance(), &validated(1), 1).unwrap();
        unsafe { libc::umask(previous) };
        assert_eq!(
            fs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [LOCK, MANIFEST, "rows-000001.bwb"] {
            assert_eq!(
                fs::metadata(run.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(store);
    }

    fn split_raw_frames(bytes: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(&bytes[..MAGIC.len()], MAGIC);
        let mut offset = MAGIC.len();
        let mut frames = Vec::new();
        while offset < bytes.len() {
            let start = offset;
            let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 8 + length;
            frames.push(bytes[start..offset].to_vec());
        }
        frames
    }

    fn join_raw_frames(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        for frame in frames {
            bytes.extend_from_slice(frame);
        }
        bytes
    }
}

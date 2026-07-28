use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::Read,
    path::{Component, Path},
};

use anyhow::Result;

/// A bounded, symlink-rejecting file read, factored out so every caller (import prevalidation,
/// the conformance runner) applies the identical file-safety and size-bound rules from a single
/// code path rather than parallel reimplementations.
pub(crate) enum BoundedReadFailure {
    Open(std::io::Error),
    Metadata(std::io::Error),
    NotRegular,
    Read(std::io::Error),
    TooLarge,
}

impl std::fmt::Display for BoundedReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(error) => write!(f, "failed to open: {error}"),
            Self::Metadata(error) => write!(f, "failed to inspect opened file: {error}"),
            Self::NotRegular => write!(f, "must be a regular file"),
            Self::Read(error) => write!(f, "failed to read: {error}"),
            Self::TooLarge => write!(f, "exceeds byte limit"),
        }
    }
}

pub(crate) fn read_bounded_bytes(path: &Path, max: usize) -> Result<Vec<u8>, BoundedReadFailure> {
    let file = open_regular_file_raw(path).map_err(BoundedReadFailure::Open)?;
    let metadata = file.metadata().map_err(BoundedReadFailure::Metadata)?;
    if !metadata.file_type().is_file() {
        return Err(BoundedReadFailure::NotRegular);
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(max.saturating_add(1)));
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(BoundedReadFailure::Read)?;
    if bytes.len() > max {
        return Err(BoundedReadFailure::TooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_file_raw(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular_file_raw(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

pub(crate) fn anchored_components(path: &Path, label: &str) -> Result<Vec<OsString>> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name.to_owned())),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => {
                Some(Err(anyhow::anyhow!("unsafe {label} path component")))
            }
        })
        .collect()
}

use std::{
    ffi::CString,
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;

use super::ServingLease;

pub struct FileServingLease {
    path: PathBuf,
    file: File,
    held: bool,
}

impl FileServingLease {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::open_for_uid(path, effective_uid())
    }

    fn open_for_uid(path: &Path, expected_uid: u32) -> anyhow::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .context("failed to resolve current directory for serving lease")?
                .join(path)
        };
        let parent = absolute
            .parent()
            .context("serving lease path has no parent directory")?;
        let filename = absolute
            .file_name()
            .filter(|name| !name.is_empty())
            .context("serving lease path has no filename")?;
        let directory = open_anchored_directory(parent)?;
        validate_private_directory(&directory, expected_uid)?;
        let file = open_or_create_private_file(&directory, filename.as_bytes(), expected_uid)?;
        Ok(Self {
            path: absolute,
            file,
            held: false,
        })
    }

    fn publish_diagnostic_metadata(&mut self) -> anyhow::Result<()> {
        let acquired_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let metadata = serde_json::json!({
            "diagnostic_version": 1,
            "pid": std::process::id(),
            "acquired_at_ms": acquired_at_ms,
        });
        let bytes = serde_json::to_vec(&metadata)?;
        self.file
            .set_len(0)
            .with_context(|| format!("failed to truncate serving lease {}", self.path.display()))?;
        self.file
            .seek(SeekFrom::Start(0))
            .with_context(|| format!("failed to seek serving lease {}", self.path.display()))?;
        self.file
            .write_all(&bytes)
            .with_context(|| format!("failed to write serving lease {}", self.path.display()))?;
        self.file
            .sync_data()
            .with_context(|| format!("failed to sync serving lease {}", self.path.display()))
    }
}

impl ServingLease for FileServingLease {
    fn try_acquire(&mut self) -> anyhow::Result<bool> {
        if self.held {
            return Ok(true);
        }
        match self.file.try_lock() {
            Ok(()) => {
                self.held = true;
                if let Err(error) = self.publish_diagnostic_metadata() {
                    self.held = false;
                    let _ = self.file.unlock();
                    return Err(error);
                }
                Ok(true)
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(false),
            Err(std::fs::TryLockError::Error(error)) => Err(error).with_context(|| {
                format!("failed to acquire serving lease {}", self.path.display())
            }),
        }
    }

    fn may_admit(&self) -> bool {
        self.held
    }

    fn release(&mut self) -> anyhow::Result<()> {
        if !self.held {
            return Ok(());
        }
        self.file
            .unlock()
            .with_context(|| format!("failed to release serving lease {}", self.path.display()))?;
        self.held = false;
        Ok(())
    }
}

impl Drop for FileServingLease {
    fn drop(&mut self) {
        if self.held {
            let _ = self.file.unlock();
            self.held = false;
        }
    }
}

fn open_anchored_directory(path: &Path) -> anyhow::Result<File> {
    let root = CString::new("/")?;
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open filesystem root");
    }
    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    for component in path.components() {
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            anyhow::bail!("unsafe serving lease path component");
        };
        let component = CString::new(component.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open serving lease parent");
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

fn validate_private_directory(directory: &File, expected_uid: u32) -> anyhow::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != expected_uid
    {
        anyhow::bail!("serving lease parent is not a private operator-owned directory");
    }
    Ok(())
}

fn open_or_create_private_file(
    directory: &File,
    filename: &[u8],
    expected_uid: u32,
) -> anyhow::Result<File> {
    let filename = CString::new(filename)?;
    let mut created = false;
    let fd = loop {
        let existing = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if existing >= 0 {
            break existing;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error).context("failed to open serving lease file");
        }
        let new_file = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if new_file >= 0 {
            created = true;
            break new_file;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).context("failed to create serving lease file");
        }
    };
    let file = unsafe { File::from_raw_fd(fd) };
    if created {
        let result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set serving lease permissions");
        }
    }
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
    {
        anyhow::bail!("serving lease is not a private operator-owned regular file");
    }
    Ok(file)
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn wrong_owner_is_rejected_before_locking() {
        let root = tempfile::tempdir_in("/private/tmp").unwrap();
        let parent = root.path().join("lease");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let wrong_uid = effective_uid().checked_add(1).unwrap();

        assert!(FileServingLease::open_for_uid(&parent.join("active.lock"), wrong_uid).is_err());
    }
}

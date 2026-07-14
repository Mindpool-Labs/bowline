use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use bowline_core::enforcement::{KillReadResult, MAX_PATH_BYTES};
use bowline_gateway::enforcement_loader::{
    atomic_write_kill_state, BoundedKillStateReader, KillStateReader, KillWriteState,
};

struct TestRoot {
    _temp: tempfile::TempDir,
    path: PathBuf,
}

impl TestRoot {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn root() -> TestRoot {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = fs::canonicalize(temp.path()).unwrap();
    TestRoot { _temp: temp, path }
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
}

#[test]
fn kill_reader_validates_dedicated_root_and_bounded_relative_path() {
    let root = root();
    assert!(KillStateReader::open(root.path(), "state").is_ok());

    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(KillStateReader::open(root.path(), "state").is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();

    for relative in ["", "/absolute", "../escape", "child/../escape"] {
        assert!(
            KillStateReader::open(root.path(), relative).is_err(),
            "{relative}"
        );
    }
    assert!(KillStateReader::open(root.path(), &"x".repeat(MAX_PATH_BYTES + 1)).is_err());

    let not_directory = root.path().join("file-root");
    private_file(&not_directory, b"armed\n");
    assert!(KillStateReader::open(&not_directory, "state").is_err());
}

#[test]
fn kill_reader_is_descriptor_relative_no_follow_and_reads_exact_state_each_time() {
    let root = root();
    let child = root.path().join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let reader = KillStateReader::open(root.path(), "child/state").unwrap();

    assert_eq!(reader.read_kill_state(), KillReadResult::Missing);
    private_file(&child.join("state"), b"malformed\n");
    assert_eq!(reader.read_kill_state(), KillReadResult::Malformed);
    private_file(&child.join("state"), b"bypass\n");
    assert_eq!(reader.read_kill_state(), KillReadResult::Bypass);
    private_file(&child.join("state"), b"armed\n");
    assert_eq!(reader.read_kill_state(), KillReadResult::Armed);

    fs::set_permissions(child.join("state"), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(reader.read_kill_state(), KillReadResult::Unsafe);
    fs::set_permissions(child.join("state"), fs::Permissions::from_mode(0o600)).unwrap();

    private_file(&child.join("replacement"), b"bypass\n");
    fs::rename(child.join("replacement"), child.join("state")).unwrap();
    assert_eq!(reader.read_kill_state(), KillReadResult::Bypass);

    fs::remove_file(child.join("state")).unwrap();
    let outside = root.path().join("outside");
    private_file(&outside, b"armed\n");
    symlink(&outside, child.join("state")).unwrap();
    assert_eq!(reader.read_kill_state(), KillReadResult::Unsafe);

    fs::remove_file(child.join("state")).unwrap();
    fs::remove_dir(&child).unwrap();
    symlink(root.path(), &child).unwrap();
    assert_eq!(reader.read_kill_state(), KillReadResult::Unsafe);
}

#[tokio::test]
async fn bounded_reader_reports_queue_saturation_and_shutdown_without_cached_authority() {
    let root = root();
    private_file(&root.path().join("state"), b"armed\n");
    let unavailable =
        BoundedKillStateReader::new(KillStateReader::open(root.path(), "state").unwrap(), 0);
    assert_eq!(
        unavailable.read_kill_state().await,
        KillReadResult::QueueUnavailable
    );

    let reader =
        BoundedKillStateReader::new(KillStateReader::open(root.path(), "state").unwrap(), 1);
    assert_eq!(reader.read_kill_state().await, KillReadResult::Armed);
    reader.shutdown();
    assert_eq!(
        reader.read_kill_state().await,
        KillReadResult::QueueUnavailable
    );
}

#[test]
fn atomic_kill_writes_are_private_and_concurrent_readers_never_see_partial_state() {
    let root = root();
    let reader = Arc::new(KillStateReader::open(root.path(), "state").unwrap());
    atomic_write_kill_state(root.path(), "state", KillWriteState::Bypass).unwrap();
    assert_eq!(reader.read_kill_state(), KillReadResult::Bypass);
    assert_eq!(
        fs::metadata(root.path().join("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );

    let writers = (0..8)
        .map(|index| {
            let path = root.path().to_owned();
            std::thread::spawn(move || {
                let state = if index % 2 == 0 {
                    KillWriteState::Armed
                } else {
                    KillWriteState::Bypass
                };
                for _ in 0..32 {
                    atomic_write_kill_state(&path, "state", state).unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for _ in 0..512 {
        assert!(matches!(
            reader.read_kill_state(),
            KillReadResult::Armed | KillReadResult::Bypass
        ));
    }
    for writer in writers {
        writer.join().unwrap();
    }
}

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

use bowline_gateway::serving_lease::{FileServingLease, ServingLease};

#[test]
fn file_lease_is_exclusive_and_released_for_takeover() {
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    let parent = root.path().join("lease");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let path = parent.join("active.lock");
    let mut first = FileServingLease::open(&path).unwrap();
    let mut second = FileServingLease::open(&path).unwrap();

    assert!(first.try_acquire().unwrap());
    assert!(first.may_admit());
    assert!(!second.try_acquire().unwrap());
    assert!(!second.may_admit());

    first.release().unwrap();
    assert!(!first.may_admit());
    assert!(second.try_acquire().unwrap());
    assert!(second.may_admit());

    let metadata = fs::metadata(path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[test]
fn file_lease_rejects_unsafe_parent_and_file_shapes() {
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    let loose = root.path().join("loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(FileServingLease::open(&loose.join("active.lock")).is_err());

    let private = root.path().join("private");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(private.join("directory.lock")).unwrap();
    assert!(FileServingLease::open(&private.join("directory.lock")).is_err());

    let target = root.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = root.path().join("linked");
    symlink(&target, &linked).unwrap();
    assert!(FileServingLease::open(&linked.join("active.lock")).is_err());

    let loose_file = private.join("loose.lock");
    fs::write(&loose_file, b"").unwrap();
    fs::set_permissions(&loose_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(FileServingLease::open(&loose_file).is_err());
}

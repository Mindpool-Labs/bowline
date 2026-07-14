use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn local_kill_command_atomically_arms_and_bypasses_configured_state() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let temp_path = fs::canonicalize(temp.path()).unwrap();
    let config = temp_path.join("enforcement.yaml");
    fs::write(
        &config,
        format!(
            "version: 1\nglobal_candidate_in_flight: 1\nkill_switch:\n  trust_root: {}\n  relative_path: state\nactuators: []\nroutes: []\n",
            temp_path.display()
        ),
    )
    .unwrap();

    for (command, expected) in [
        ("arm", b"armed\n".as_slice()),
        ("bypass", b"bypass\n".as_slice()),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
            .args(["kill", command, "--enforcement"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(temp_path.join("state")).unwrap(), expected);
    }
}

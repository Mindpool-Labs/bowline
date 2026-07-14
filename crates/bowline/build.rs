fn main() {
    println!("cargo:rerun-if-env-changed=BOWLINE_SOURCE_REVISION");
    if let Ok(value) = std::env::var("BOWLINE_SOURCE_REVISION") {
        let valid = (value.len() == 40 || value.len() == 64)
            && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        assert!(
            valid,
            "BOWLINE_SOURCE_REVISION must be a 40- or 64-character hexadecimal revision"
        );
    }
}

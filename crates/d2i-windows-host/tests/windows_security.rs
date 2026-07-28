#![cfg(windows)]

use d2i_windows_host::{
    appcontainer_profile, delete_appcontainer_profile, harden_path_for_current_user,
    path_security_descriptor, protect_current_user, provision_appcontainer_profile,
    spawn_zero_capability_appcontainer, unprotect_current_user,
};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

struct Profile(String);

impl Drop for Profile {
    fn drop(&mut self) {
        let _ = delete_appcontainer_profile(&self.0);
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("d2i-windows-host-security-{}", std::process::id()));
        if path.exists() {
            let _ = std::fs::remove_dir_all(&path);
        }
        ok(std::fs::create_dir(&path));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn current_user_dpapi_round_trips_and_rejects_tampering() {
    let purpose = b"d2i-test-purpose";
    let protected = ok(protect_current_user(b"secret material", purpose));
    assert_ne!(protected, b"secret material");
    assert_eq!(
        ok(unprotect_current_user(&protected, purpose)),
        b"secret material"
    );
    let mut tampered = protected;
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    assert!(unprotect_current_user(&tampered, purpose).is_err());
    assert!(unprotect_current_user(
        &ok(protect_current_user(b"secret material", purpose)),
        b"different-purpose"
    )
    .is_err());
}

#[test]
fn protected_path_security_descriptor_is_stable() {
    let temp = TempDirectory::new();
    let first = ok(harden_path_for_current_user(&temp.0));
    let second = ok(path_security_descriptor(&temp.0));
    assert_eq!(first, second);
    assert!(!first.is_empty());
}

#[test]
fn zero_capability_appcontainer_process_has_reviewed_sid() {
    let profile_name = format!("D2I.Test.{}", std::process::id());
    let _cleanup = Profile(profile_name.clone());
    let profile = ok(provision_appcontainer_profile(&profile_name));
    assert_eq!(ok(appcontainer_profile(&profile_name)), profile);
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let system32 = ok(std::fs::canonicalize(
        Path::new(&system_root).join("System32"),
    ));
    let command = system32.join("cmd.exe");
    let child = ok(spawn_zero_capability_appcontainer(
        &profile_name,
        &profile.profile_sid,
        &command,
        &["/D".to_owned(), "/C".to_owned(), "exit 23".to_owned()],
        &system32,
    ));
    assert_ne!(child.id(), 0);
    assert_eq!(ok(child.wait_timeout(Duration::from_secs(10))), Some(23));
}

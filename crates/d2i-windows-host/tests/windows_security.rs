#![cfg(windows)]

use d2i_windows_host::{
    appcontainer_profile, atomic_move, delete_appcontainer_profile,
    ensure_appcontainer_profile_deleted, grant_appcontainer_child_query_to_verifier,
    grant_current_process_query_to_verifier, harden_path_for_current_user,
    inspect_verifier_process, path_security_descriptor, process_parent_id,
    process_peak_working_set_bytes, protect_current_user, provision_appcontainer_profile,
    spawn_zero_capability_appcontainer, unprotect_current_user, WindowsJobLimits,
};
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

#[test]
fn model_job_memory_bound_accepts_eight_gib_and_rejects_more() {
    let eight_gib = 8 * 1024 * 1024 * 1024;
    assert!(WindowsJobLimits {
        active_process_limit: 2,
        per_process_memory_bytes: eight_gib,
    }
    .validate()
    .is_ok());
    assert!(WindowsJobLimits {
        active_process_limit: 2,
        per_process_memory_bytes: eight_gib + 1,
    }
    .validate()
    .is_err());
}

#[test]
fn live_process_peak_working_set_is_measured() {
    let bytes = ok(process_peak_working_set_bytes(std::process::id()));
    assert!(bytes > 0);
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
fn atomic_move_retries_only_until_a_transient_destination_lock_is_released() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "d2i-windows-host-atomic-move-{}-{suffix}",
        std::process::id()
    ));
    ok(std::fs::create_dir(&root));
    let source = root.join("state.new");
    let destination = root.join("state.json");
    ok(std::fs::write(&source, b"new-state"));
    ok(std::fs::write(&destination, b"old-state"));

    let locked = ok(OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&destination));
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        drop(locked);
    });
    let started = Instant::now();
    ok(atomic_move(&source, &destination, true));
    ok(release.join());

    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(!source.exists());
    assert_eq!(ok(std::fs::read(&destination)), b"new-state");
    ok(std::fs::remove_dir_all(root));
}

#[test]
fn atomic_move_fails_closed_when_destination_lock_persists() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "d2i-windows-host-atomic-move-locked-{}-{suffix}",
        std::process::id()
    ));
    ok(std::fs::create_dir(&root));
    let source = root.join("state.new");
    let destination = root.join("state.json");
    ok(std::fs::write(&source, b"new-state"));
    ok(std::fs::write(&destination, b"old-state"));
    let locked = ok(OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&destination));

    let started = Instant::now();
    let error = atomic_move(&source, &destination, true);
    assert!(error.is_err());
    assert!(started.elapsed() >= Duration::from_millis(300));
    drop(locked);
    assert_eq!(ok(std::fs::read(&source)), b"new-state");
    assert_eq!(ok(std::fs::read(&destination)), b"old-state");

    ok(std::fs::remove_dir_all(root));
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
        &[
            "/D".to_owned(),
            "/C".to_owned(),
            "ping -n 3 127.0.0.1 >nul & exit 23".to_owned(),
        ],
        &system32,
    ));
    assert_ne!(child.id(), 0);
    let verifier_sid = "S-1-5-80-1-2-3-4-5";
    ok(grant_current_process_query_to_verifier(verifier_sid));
    ok(grant_appcontainer_child_query_to_verifier(
        &child,
        verifier_sid,
    ));
    let identity = ok(inspect_verifier_process(child.id()));
    eprintln!("AppContainer test identity: {identity:?}");
    assert!(identity.is_appcontainer);
    assert_eq!(identity.integrity_level_rid, 4_096);
    assert_eq!(identity.elevation_type, "limited");
    assert_eq!(
        identity.appcontainer_sid.as_deref(),
        Some(profile.profile_sid.as_str())
    );
    assert_eq!(ok(process_parent_id(child.id())), std::process::id());
    assert_eq!(ok(child.wait_timeout(Duration::from_secs(10))), Some(23));
}

#[test]
fn appcontainer_profile_cleanup_is_idempotent_and_absence_checked() {
    let profile_name = format!("D2I.Test.Cleanup.{}", std::process::id());
    ok(provision_appcontainer_profile(&profile_name));
    ok(ensure_appcontainer_profile_deleted(&profile_name));
    ok(ensure_appcontainer_profile_deleted(&profile_name));
}

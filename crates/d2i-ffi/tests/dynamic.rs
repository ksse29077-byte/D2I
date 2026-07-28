#[cfg(feature = "score-kernel")]
use d2i_ffi::NativeScoreKernel;
use d2i_ffi::{file_sha256, FfiError, NativeModule, NativeModulePolicy};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("d2i-native-{}-{sequence}", std::process::id()));
        ok(fs::create_dir_all(&path));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn library_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "d2i_native_fixture.dll"
    } else if cfg!(target_os = "macos") {
        "libd2i_native_fixture.dylib"
    } else {
        "libd2i_native_fixture.so"
    }
}

fn build_fixture(root: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_module.rs");
    let library = root.join(library_name());
    let output = ok(Command::new("rustc")
        .arg("--crate-type")
        .arg("cdylib")
        .arg("--edition")
        .arg("2021")
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output());
    assert!(
        output.status.success(),
        "fixture rustc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    library
}

#[test]
fn dynamically_loaded_rust_module_cross_executes_through_c_abi() {
    let temporary = TempDirectory::new();
    let library = build_fixture(&temporary.0);
    let hash = ok(file_sha256(&library));
    let policy = NativeModulePolicy {
        allowed_root: temporary.0.clone(),
        expected_sha256: hash,
        maximum_library_bytes: 16 * 1024 * 1024,
        maximum_input_bytes: 1024,
        maximum_output_bytes: 1024,
    };
    let mut module = ok(NativeModule::load(&library, &policy, b"config"));

    assert_eq!(module.metadata().module_id, "uppercase-fixture");
    assert_eq!(ok(module.run(b"native abi")), b"NATIVE ABI");
    ok(module.reset());
    assert_eq!(module.copy_metrics().boundary_copy_count, 0);
    assert_eq!(module.copy_metrics().boundary_copy_bytes, 0);
    assert_eq!(module.copy_metrics().input_view_count, 1);
    assert_eq!(module.copy_metrics().output_view_count, 1);
}

fn c_compiler() -> Option<String> {
    if let Ok(compiler) = std::env::var("CC") {
        return Some(compiler);
    }
    ["cc", "gcc", "clang"].into_iter().find_map(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|_| candidate.to_owned())
    })
}

fn build_c_fixture(root: &Path) -> Option<PathBuf> {
    let compiler = c_compiler()?;
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = manifest.join("tests/fixtures/native_module.c");
    let include = manifest.join("include");
    let library = root.join(if cfg!(target_os = "windows") {
        "d2i_c_fixture.dll"
    } else if cfg!(target_os = "macos") {
        "libd2i_c_fixture.dylib"
    } else {
        "libd2i_c_fixture.so"
    });
    let mut command = Command::new(compiler);
    if cfg!(target_os = "macos") {
        command.arg("-dynamiclib");
    } else {
        command.arg("-shared");
    }
    if !cfg!(target_os = "windows") {
        command.arg("-fPIC");
    }
    let output = ok(command
        .arg("-std=c11")
        .arg("-I")
        .arg(include)
        .arg(source)
        .arg("-o")
        .arg(&library)
        .output());
    assert!(
        output.status.success(),
        "C fixture build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(library)
}

#[cfg(feature = "score-kernel")]
fn build_score_fixture(root: &Path) -> Option<PathBuf> {
    let compiler = c_compiler()?;
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = manifest.join("tests/fixtures/score_kernel.c");
    let include = manifest.join("include");
    let library = root.join(if cfg!(target_os = "windows") {
        "d2i_score_fixture.dll"
    } else if cfg!(target_os = "macos") {
        "libd2i_score_fixture.dylib"
    } else {
        "libd2i_score_fixture.so"
    });
    let mut command = Command::new(compiler);
    if cfg!(target_os = "macos") {
        command.arg("-dynamiclib");
    } else {
        command.arg("-shared");
    }
    if !cfg!(target_os = "windows") {
        command.arg("-fPIC");
    }
    let output = ok(command
        .arg("-std=c11")
        .arg("-I")
        .arg(include)
        .arg(source)
        .arg("-o")
        .arg(&library)
        .output());
    assert!(
        output.status.success(),
        "score fixture build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(library)
}

#[test]
fn c_module_from_published_header_cross_executes_with_rust_host() {
    let temporary = TempDirectory::new();
    let Some(library) = build_c_fixture(&temporary.0) else {
        eprintln!("skipping C module test because CC/cc/gcc/clang is unavailable");
        return;
    };
    let policy = NativeModulePolicy {
        allowed_root: temporary.0.clone(),
        expected_sha256: ok(file_sha256(&library)),
        maximum_library_bytes: 16 * 1024 * 1024,
        maximum_input_bytes: 1024,
        maximum_output_bytes: 1024,
    };
    let mut module = ok(NativeModule::load(&library, &policy, b""));

    assert_eq!(module.metadata().module_id, "c-uppercase-fixture");
    assert_eq!(ok(module.run(b"cross language")), b"CROSS LANGUAGE");
    assert_eq!(module.copy_metrics().boundary_copy_bytes, 0);
}

#[test]
fn hash_allowlist_rejects_module_before_loading() {
    let temporary = TempDirectory::new();
    let library = build_fixture(&temporary.0);
    let policy = NativeModulePolicy {
        allowed_root: temporary.0.clone(),
        expected_sha256: format!("sha256:{}", "0".repeat(64)),
        maximum_library_bytes: 16 * 1024 * 1024,
        maximum_input_bytes: 1024,
        maximum_output_bytes: 1024,
    };

    assert!(matches!(
        NativeModule::load(&library, &policy, b""),
        Err(FfiError::HashMismatch { .. })
    ));
}

#[test]
fn module_reports_required_size_without_exposing_unowned_memory() {
    let temporary = TempDirectory::new();
    let library = build_fixture(&temporary.0);
    let policy = NativeModulePolicy {
        allowed_root: temporary.0.clone(),
        expected_sha256: ok(file_sha256(&library)),
        maximum_library_bytes: 16 * 1024 * 1024,
        maximum_input_bytes: 1024,
        maximum_output_bytes: 4,
    };
    let mut module = ok(NativeModule::load(&library, &policy, b""));

    assert!(matches!(
        module.run(b"larger"),
        Err(FfiError::BufferTooSmall {
            required: 6,
            capacity: 4
        })
    ));
}

#[cfg(feature = "score-kernel")]
#[test]
fn isolated_score_kernel_matches_integer_contract_without_boundary_copies() {
    let temporary = TempDirectory::new();
    let Some(library) = build_score_fixture(&temporary.0) else {
        eprintln!("skipping score-kernel test because CC/cc/gcc/clang is unavailable");
        return;
    };
    let policy = NativeModulePolicy {
        allowed_root: temporary.0.clone(),
        expected_sha256: ok(file_sha256(&library)),
        maximum_library_bytes: 16 * 1024 * 1024,
        maximum_input_bytes: 8,
        maximum_output_bytes: 16,
    };
    let mut kernel = ok(NativeScoreKernel::load(&library, &policy));
    let masks = [0, 1, 2, 3, 4, 5, 6, 7];
    let mut scores = [0_u16; 8];

    ok(kernel.score_into(&masks, &mut scores));

    assert_eq!(scores, [0, 45, 45, 90, 10, 55, 55, 100]);
    assert_eq!(kernel.copy_metrics().boundary_copy_count, 0);
    assert_eq!(kernel.copy_metrics().boundary_copy_bytes, 0);
}

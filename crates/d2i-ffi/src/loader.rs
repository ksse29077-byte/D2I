use crate::abi::{
    D2iBufferMut, D2iBufferView, D2iDestroyFn, D2iInitFn, D2iModuleV1, D2iResetFn, D2iRunFn,
    D2iStatus, D2I_ABI_VERSION_V1,
};
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::ffi::c_void;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::Read;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

const ENTRY_SYMBOL: &[u8] = b"d2i_module_v1\0";
const MAX_ID_BYTES: u64 = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct D2iModuleHeader {
    abi_version: u32,
    struct_size: u32,
}

/// Allowlist and resource limits applied before loading native code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeModulePolicy {
    pub allowed_root: PathBuf,
    pub expected_sha256: String,
    pub maximum_library_bytes: u64,
    pub maximum_input_bytes: u64,
    pub maximum_output_bytes: u64,
}

/// Native module identity read from the validated function table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeModuleMetadata {
    pub module_id: String,
    pub module_version: String,
    pub abi_version: u32,
    pub library_sha256: String,
}

/// Copies and allocations attributable to the ABI boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiCopyMetrics {
    pub input_view_count: u64,
    pub input_view_bytes: u64,
    pub output_view_count: u64,
    pub output_view_bytes: u64,
    pub boundary_copy_count: u64,
    pub boundary_copy_bytes: u64,
    pub host_allocation_count: u64,
}

/// Structured native ABI load or invocation failure.
#[derive(Debug)]
pub enum FfiError {
    Io { path: String, message: String },
    UnsafePath(String),
    HashMismatch { expected: String, actual: String },
    Load(String),
    MissingSymbol(String),
    InvalidDescriptor(String),
    InvalidBuffer(String),
    ModuleStatus { operation: &'static str, code: u32 },
    BufferTooSmall { required: u64, capacity: u64 },
    Utf8(String),
}

impl Display for FfiError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "I/O error at {path}: {message}"),
            Self::UnsafePath(message) => write!(formatter, "unsafe native module path: {message}"),
            Self::HashMismatch { expected, actual } => {
                write!(
                    formatter,
                    "native module hash mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Load(message) => write!(formatter, "cannot load native module: {message}"),
            Self::MissingSymbol(message) => {
                write!(formatter, "native ABI symbol failed: {message}")
            }
            Self::InvalidDescriptor(message) => {
                write!(formatter, "invalid native ABI descriptor: {message}")
            }
            Self::InvalidBuffer(message) => write!(formatter, "invalid ABI buffer: {message}"),
            Self::ModuleStatus { operation, code } => {
                write!(
                    formatter,
                    "native module {operation} returned status {code}"
                )
            }
            Self::BufferTooSmall { required, capacity } => write!(
                formatter,
                "native output requires {required} bytes but host capacity is {capacity}"
            ),
            Self::Utf8(message) => write!(formatter, "native metadata is not UTF-8: {message}"),
        }
    }
}

impl Error for FfiError {}

/// Loaded native module with a single-owned opaque handle.
pub struct NativeModule {
    _library: Option<Library>,
    init: D2iInitFn,
    run: D2iRunFn,
    reset: D2iResetFn,
    destroy: D2iDestroyFn,
    handle: Option<NonNull<c_void>>,
    metadata: NativeModuleMetadata,
    metrics: AbiCopyMetrics,
    maximum_input_bytes: u64,
    maximum_output_bytes: u64,
}

impl NativeModule {
    /// Verifies, loads, validates, and initializes a native module.
    pub fn load(path: &Path, policy: &NativeModulePolicy, config: &[u8]) -> Result<Self, FfiError> {
        let (canonical_path, actual_hash) = verify_library(path, policy)?;
        // SAFETY: Loading native code is confined to this crate. The path was
        // canonicalized, bounded, symlink-checked, rooted, and hash-allowlisted.
        let library = unsafe { Library::new(&canonical_path) }
            .map_err(|error| FfiError::Load(error.to_string()))?;
        let entry: Symbol<'_, unsafe extern "C" fn() -> *const D2iModuleV1> = {
            // SAFETY: Symbol lookup uses the fixed ABI entry name and the
            // library remains owned by the resulting NativeModule.
            unsafe { library.get(ENTRY_SYMBOL) }
        }
        .map_err(|error| FfiError::MissingSymbol(error.to_string()))?;
        // SAFETY: The allowlisted module contract requires this function to
        // return a pointer to an immutable D2iModuleV1 table.
        let table_ptr = unsafe { entry() };
        let table = read_table(table_ptr)?;
        let (module_id, module_version) = validate_table(&table)?;
        let mut module = Self::from_table(
            Some(library),
            table,
            NativeModuleMetadata {
                module_id,
                module_version,
                abi_version: D2I_ABI_VERSION_V1,
                library_sha256: actual_hash,
            },
            policy.maximum_input_bytes,
            policy.maximum_output_bytes,
        )?;
        module.initialize(config)?;
        Ok(module)
    }

    fn from_table(
        library: Option<Library>,
        table: D2iModuleV1,
        metadata: NativeModuleMetadata,
        maximum_input_bytes: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, FfiError> {
        Ok(Self {
            _library: library,
            init: table
                .init
                .ok_or_else(|| FfiError::InvalidDescriptor("init function is null".to_owned()))?,
            run: table
                .run
                .ok_or_else(|| FfiError::InvalidDescriptor("run function is null".to_owned()))?,
            reset: table
                .reset
                .ok_or_else(|| FfiError::InvalidDescriptor("reset function is null".to_owned()))?,
            destroy: table.destroy.ok_or_else(|| {
                FfiError::InvalidDescriptor("destroy function is null".to_owned())
            })?,
            handle: None,
            metadata,
            metrics: AbiCopyMetrics::default(),
            maximum_input_bytes,
            maximum_output_bytes,
        })
    }

    fn initialize(&mut self, config: &[u8]) -> Result<(), FfiError> {
        let config_view = D2iBufferView::from_slice(config);
        config_view
            .validate_metadata(self.maximum_input_bytes)
            .map_err(|message| FfiError::InvalidBuffer(message.to_owned()))?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: Function table and input view were validated. out_handle
        // points to host stack storage and no Rust panic is allowed to cross.
        let status = unsafe { (self.init)(&config_view, &mut handle) };
        if status != D2iStatus::OK {
            return Err(FfiError::ModuleStatus {
                operation: "init",
                code: status.0,
            });
        }
        self.handle = NonNull::new(handle);
        if self.handle.is_none() {
            return Err(FfiError::InvalidDescriptor(
                "init returned a null handle".to_owned(),
            ));
        }
        Ok(())
    }

    /// Executes with borrowed input and a host-owned output allocation.
    pub fn run(&mut self, input: &[u8]) -> Result<Vec<u8>, FfiError> {
        let input_view = D2iBufferView::from_slice(input);
        input_view
            .validate_metadata(self.maximum_input_bytes)
            .map_err(|message| FfiError::InvalidBuffer(message.to_owned()))?;
        let output_capacity = usize::try_from(self.maximum_output_bytes)
            .map_err(|_| FfiError::InvalidBuffer("output limit exceeds usize".to_owned()))?;
        let mut output = vec![0_u8; output_capacity];
        let mut output_view = D2iBufferMut::from_slice(&mut output);
        let original_ptr = output_view.ptr;
        let original_capacity = output_view.capacity;
        let original_alignment = output_view.alignment;
        let original_memory_kind = output_view.memory_kind;
        let original_flags = output_view.flags;
        let original_reserved = output_view.reserved;
        let handle = self
            .handle
            .ok_or_else(|| FfiError::InvalidDescriptor("module is shut down".to_owned()))?;
        self.metrics.input_view_count = self.metrics.input_view_count.saturating_add(1);
        self.metrics.input_view_bytes =
            self.metrics.input_view_bytes.saturating_add(input_view.len);
        self.metrics.output_view_count = self.metrics.output_view_count.saturating_add(1);
        self.metrics.host_allocation_count = self.metrics.host_allocation_count.saturating_add(1);
        // SAFETY: The handle is live, input is borrowed for the call, and
        // output is initialized host memory whose metadata is checked below.
        let status = unsafe { (self.run)(handle.as_ptr(), &input_view, &mut output_view) };
        if output_view.ptr != original_ptr
            || output_view.capacity != original_capacity
            || output_view.alignment != original_alignment
            || output_view.memory_kind != original_memory_kind
            || output_view.flags != original_flags
            || output_view.reserved != original_reserved
        {
            return Err(FfiError::InvalidBuffer(
                "module mutated immutable host-owned output metadata".to_owned(),
            ));
        }
        if status == D2iStatus::BUFFER_TOO_SMALL {
            if output_view.len <= output_view.capacity {
                return Err(FfiError::InvalidBuffer(
                    "buffer-too-small status did not report a larger required size".to_owned(),
                ));
            }
            return Err(FfiError::BufferTooSmall {
                required: output_view.len,
                capacity: output_view.capacity,
            });
        }
        if status != D2iStatus::OK {
            return Err(FfiError::ModuleStatus {
                operation: "run",
                code: status.0,
            });
        }
        output_view
            .validate_metadata(self.maximum_output_bytes)
            .map_err(|message| FfiError::InvalidBuffer(message.to_owned()))?;
        let output_len = usize::try_from(output_view.len)
            .map_err(|_| FfiError::InvalidBuffer("output length exceeds usize".to_owned()))?;
        output.truncate(output_len);
        self.metrics.output_view_bytes = self
            .metrics
            .output_view_bytes
            .saturating_add(output_view.len);
        Ok(output)
    }

    /// Resets module-owned state without releasing the handle.
    pub fn reset(&mut self) -> Result<(), FfiError> {
        let handle = self
            .handle
            .ok_or_else(|| FfiError::InvalidDescriptor("module is shut down".to_owned()))?;
        // SAFETY: The handle is still exclusively owned by this wrapper.
        let status = unsafe { (self.reset)(handle.as_ptr()) };
        if status == D2iStatus::OK {
            Ok(())
        } else {
            Err(FfiError::ModuleStatus {
                operation: "reset",
                code: status.0,
            })
        }
    }

    /// Releases the opaque handle exactly once. Repeated calls are no-ops.
    pub fn shutdown(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: take() transfers the sole handle to this call, so Drop
            // and repeated shutdown calls cannot destroy it again.
            unsafe { (self.destroy)(handle.as_ptr()) };
        }
    }

    /// Returns immutable native module identity.
    #[must_use]
    pub fn metadata(&self) -> &NativeModuleMetadata {
        &self.metadata
    }

    /// Returns cumulative boundary copy and allocation counters.
    #[must_use]
    pub fn copy_metrics(&self) -> &AbiCopyMetrics {
        &self.metrics
    }

    #[cfg(test)]
    pub(crate) fn from_table_for_test(
        table: D2iModuleV1,
        metadata: NativeModuleMetadata,
        maximum_bytes: u64,
    ) -> Result<Self, FfiError> {
        Self::from_table(None, table, metadata, maximum_bytes, maximum_bytes)
    }

    #[cfg(test)]
    pub(crate) fn initialize_for_test(&mut self, config: &[u8]) -> Result<(), FfiError> {
        self.initialize(config)
    }
}

impl Drop for NativeModule {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn read_table(pointer: *const D2iModuleV1) -> Result<D2iModuleV1, FfiError> {
    if pointer.is_null() || (pointer as usize) % mem::align_of::<D2iModuleV1>() != 0 {
        return Err(FfiError::InvalidDescriptor(
            "entry returned a null or misaligned table".to_owned(),
        ));
    }
    // SAFETY: A module entry promises at least the two-field ABI header.
    let header = unsafe { pointer.cast::<D2iModuleHeader>().read() };
    if header.abi_version != D2I_ABI_VERSION_V1 {
        return Err(FfiError::InvalidDescriptor(format!(
            "ABI version {} is unsupported",
            header.abi_version
        )));
    }
    if header.struct_size < D2iModuleV1::current_struct_size() {
        return Err(FfiError::InvalidDescriptor(format!(
            "function table size {} is below {}",
            header.struct_size,
            D2iModuleV1::current_struct_size()
        )));
    }
    // SAFETY: The validated header declares readable storage of at least the
    // current table size; the library remains loaded while the copy is used.
    Ok(unsafe { pointer.read() })
}

fn validate_table(table: &D2iModuleV1) -> Result<(String, String), FfiError> {
    if table.abi_version != D2I_ABI_VERSION_V1 {
        return Err(FfiError::InvalidDescriptor(format!(
            "ABI version {} is unsupported",
            table.abi_version
        )));
    }
    if table.struct_size < D2iModuleV1::current_struct_size() {
        return Err(FfiError::InvalidDescriptor(format!(
            "function table size {} is below {}",
            table.struct_size,
            D2iModuleV1::current_struct_size()
        )));
    }
    let module_id = read_utf8_view(&table.module_id, "module_id")?;
    let module_version = read_utf8_view(&table.module_version, "module_version")?;
    if module_id.is_empty() || module_version.is_empty() {
        return Err(FfiError::InvalidDescriptor(
            "module identity fields must not be empty".to_owned(),
        ));
    }
    Ok((module_id, module_version))
}

fn read_utf8_view(view: &D2iBufferView, field: &str) -> Result<String, FfiError> {
    view.validate_metadata(MAX_ID_BYTES)
        .map_err(|message| FfiError::InvalidDescriptor(format!("{field}: {message}")))?;
    // SAFETY: Metadata is bounded and the allowlisted module promises that
    // identity bytes remain static while the library is loaded.
    let bytes = unsafe { view.as_slice() }
        .map_err(|message| FfiError::InvalidDescriptor(format!("{field}: {message}")))?;
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| FfiError::Utf8(error.to_string()))
}

pub(crate) fn verify_library(
    path: &Path,
    policy: &NativeModulePolicy,
) -> Result<(PathBuf, String), FfiError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| FfiError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(FfiError::UnsafePath("symbolic links are denied".to_owned()));
    }
    if !metadata.is_file() || metadata.len() > policy.maximum_library_bytes {
        return Err(FfiError::UnsafePath(
            "module must be a bounded regular file".to_owned(),
        ));
    }
    let canonical_root = fs::canonicalize(&policy.allowed_root).map_err(|error| FfiError::Io {
        path: policy.allowed_root.display().to_string(),
        message: error.to_string(),
    })?;
    let canonical_path = fs::canonicalize(path).map_err(|error| FfiError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(FfiError::UnsafePath(
            "module escapes the allowlisted root".to_owned(),
        ));
    }
    let actual_hash = file_sha256(&canonical_path)?;
    if actual_hash != policy.expected_sha256 {
        return Err(FfiError::HashMismatch {
            expected: policy.expected_sha256.clone(),
            actual: actual_hash,
        });
    }
    Ok((canonical_path, actual_hash))
}

/// Hashes a bounded native module file for allowlist configuration.
pub fn file_sha256(path: &Path) -> Result<String, FfiError> {
    let mut file = File::open(path).map_err(|error| FfiError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| FfiError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{D2I_BUFFER_READ_ONLY, D2I_MEMORY_HOST};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static DESTROY_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DESTROY_COUNT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static MODULE_ID: &[u8] = b"static-test";
    static MODULE_VERSION: &[u8] = b"1.0.0";

    unsafe extern "C" fn init(
        _config: *const D2iBufferView,
        out_handle: *mut *mut c_void,
    ) -> D2iStatus {
        if out_handle.is_null() {
            return D2iStatus::INVALID_ARGUMENT;
        }
        let handle = Box::into_raw(Box::new(7_u8)).cast::<c_void>();
        // SAFETY: out_handle was checked and points to host-provided storage.
        unsafe { out_handle.write(handle) };
        D2iStatus::OK
    }

    unsafe extern "C" fn run(
        _handle: *mut c_void,
        input: *const D2iBufferView,
        output: *mut D2iBufferMut,
    ) -> D2iStatus {
        if input.is_null() || output.is_null() {
            return D2iStatus::INVALID_ARGUMENT;
        }
        // SAFETY: Test host passes valid ABI structures for this synchronous call.
        let input = unsafe { &*input };
        // SAFETY: Test host passes exclusive output metadata.
        let output = unsafe { &mut *output };
        let Ok(length) = usize::try_from(input.len) else {
            return D2iStatus::INVALID_ARGUMENT;
        };
        if input.len > output.capacity {
            output.len = input.len;
            return D2iStatus::BUFFER_TOO_SMALL;
        }
        // SAFETY: The test input/output allocations are valid and capacity was checked.
        let source = unsafe { std::slice::from_raw_parts(input.ptr, length) };
        // SAFETY: The output is host-owned writable memory of at least length bytes.
        let destination = unsafe { std::slice::from_raw_parts_mut(output.ptr, length) };
        destination.copy_from_slice(source);
        output.len = input.len;
        D2iStatus::OK
    }

    unsafe extern "C" fn mutate_pointer(
        _handle: *mut c_void,
        _input: *const D2iBufferView,
        output: *mut D2iBufferMut,
    ) -> D2iStatus {
        if output.is_null() {
            return D2iStatus::INVALID_ARGUMENT;
        }
        // SAFETY: Test host passes exclusive output metadata.
        unsafe { (*output).ptr = NonNull::<u8>::dangling().as_ptr() };
        D2iStatus::OK
    }

    unsafe extern "C" fn reset(_handle: *mut c_void) -> D2iStatus {
        D2iStatus::OK
    }

    unsafe extern "C" fn timeout(
        _handle: *mut c_void,
        _input: *const D2iBufferView,
        _output: *mut D2iBufferMut,
    ) -> D2iStatus {
        D2iStatus::TIMEOUT
    }

    unsafe extern "C" fn destroy(handle: *mut c_void) {
        if !handle.is_null() {
            DESTROY_COUNT.fetch_add(1, Ordering::SeqCst);
            // SAFETY: init allocated exactly one Box<u8>; NativeModule calls destroy once.
            drop(unsafe { Box::from_raw(handle.cast::<u8>()) });
        }
    }

    fn table(run_fn: D2iRunFn) -> D2iModuleV1 {
        D2iModuleV1 {
            abi_version: D2I_ABI_VERSION_V1,
            struct_size: D2iModuleV1::current_struct_size(),
            module_id: D2iBufferView {
                ptr: MODULE_ID.as_ptr(),
                len: MODULE_ID.len() as u64,
                alignment: 1,
                memory_kind: D2I_MEMORY_HOST,
                flags: D2I_BUFFER_READ_ONLY,
                reserved: 0,
            },
            module_version: D2iBufferView {
                ptr: MODULE_VERSION.as_ptr(),
                len: MODULE_VERSION.len() as u64,
                alignment: 1,
                memory_kind: D2I_MEMORY_HOST,
                flags: D2I_BUFFER_READ_ONLY,
                reserved: 0,
            },
            init: Some(init),
            run: Some(run_fn),
            reset: Some(reset),
            destroy: Some(destroy),
        }
    }

    fn metadata() -> NativeModuleMetadata {
        NativeModuleMetadata {
            module_id: "static-test".to_owned(),
            module_version: "1.0.0".to_owned(),
            abi_version: D2I_ABI_VERSION_V1,
            library_sha256: format!("sha256:{}", "0".repeat(64)),
        }
    }

    #[test]
    fn host_owned_views_record_zero_boundary_copies_and_destroy_once() {
        let _guard = DESTROY_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        DESTROY_COUNT.store(0, Ordering::SeqCst);
        let mut module = match NativeModule::from_table_for_test(table(run), metadata(), 64) {
            Ok(module) => module,
            Err(error) => panic!("valid table failed: {error}"),
        };
        if let Err(error) = module.initialize_for_test(&[]) {
            panic!("module init failed: {error}");
        }
        let output = match module.run(b"native") {
            Ok(output) => output,
            Err(error) => panic!("module run failed: {error}"),
        };
        assert_eq!(output, b"native");
        assert_eq!(module.copy_metrics().boundary_copy_count, 0);
        assert_eq!(module.copy_metrics().boundary_copy_bytes, 0);
        module.shutdown();
        assert!(matches!(
            module.run(b"after shutdown"),
            Err(FfiError::InvalidDescriptor(_))
        ));
        module.shutdown();
        drop(module);
        assert_eq!(DESTROY_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn module_cannot_replace_host_owned_output_pointer() {
        let _guard = DESTROY_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        DESTROY_COUNT.store(0, Ordering::SeqCst);
        let mut module =
            match NativeModule::from_table_for_test(table(mutate_pointer), metadata(), 64) {
                Ok(module) => module,
                Err(error) => panic!("valid table failed: {error}"),
            };
        if let Err(error) = module.initialize_for_test(&[]) {
            panic!("module init failed: {error}");
        }
        assert!(matches!(module.run(b"x"), Err(FfiError::InvalidBuffer(_))));
    }

    #[test]
    fn unsupported_abi_version_and_truncated_function_table_are_rejected() {
        let mut wrong_version = table(run);
        wrong_version.abi_version = D2I_ABI_VERSION_V1 + 1;
        assert!(matches!(
            read_table(&wrong_version),
            Err(FfiError::InvalidDescriptor(_))
        ));

        let mut truncated = table(run);
        truncated.struct_size = D2iModuleV1::current_struct_size() - 1;
        assert!(matches!(
            read_table(&truncated),
            Err(FfiError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn cooperative_timeout_still_destroys_the_live_handle_once() {
        let _guard = DESTROY_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        DESTROY_COUNT.store(0, Ordering::SeqCst);
        let mut module = match NativeModule::from_table_for_test(table(timeout), metadata(), 64) {
            Ok(module) => module,
            Err(error) => panic!("valid table failed: {error}"),
        };
        if let Err(error) = module.initialize_for_test(&[]) {
            panic!("module init failed: {error}");
        }
        assert!(matches!(
            module.run(b"bounded"),
            Err(FfiError::ModuleStatus {
                operation: "run",
                code: 2
            })
        ));
        drop(module);
        assert_eq!(DESTROY_COUNT.load(Ordering::SeqCst), 1);
    }
}

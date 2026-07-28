#![allow(unsafe_code)]

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Status(u32);

const OK: Status = Status(0);
const INVALID: Status = Status(1);
const INTERNAL: Status = Status(3);
const BUFFER_TOO_SMALL: Status = Status(5);

#[repr(C)]
#[derive(Clone, Copy)]
struct BufferView {
    ptr: *const u8,
    len: u64,
    alignment: u32,
    memory_kind: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct BufferMut {
    ptr: *mut u8,
    len: u64,
    capacity: u64,
    alignment: u32,
    memory_kind: u32,
    flags: u32,
    reserved: u32,
}

type InitFn = unsafe extern "C" fn(*const BufferView, *mut *mut c_void) -> Status;
type RunFn =
    unsafe extern "C" fn(*mut c_void, *const BufferView, *mut BufferMut) -> Status;
type ResetFn = unsafe extern "C" fn(*mut c_void) -> Status;
type DestroyFn = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
struct ModuleV1 {
    abi_version: u32,
    struct_size: u32,
    module_id: BufferView,
    module_version: BufferView,
    init: Option<InitFn>,
    run: Option<RunFn>,
    reset: Option<ResetFn>,
    destroy: Option<DestroyFn>,
}

unsafe extern "C" fn init(
    _config: *const BufferView,
    out_handle: *mut *mut c_void,
) -> Status {
    match catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            return INVALID;
        }
        let handle = Box::into_raw(Box::new(0_u64)).cast::<c_void>();
        // SAFETY: The host supplies writable pointer storage for the handle.
        unsafe { out_handle.write(handle) };
        OK
    })) {
        Ok(status) => status,
        Err(_) => INTERNAL,
    }
}

unsafe extern "C" fn run(
    handle: *mut c_void,
    input: *const BufferView,
    output: *mut BufferMut,
) -> Status {
    match catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || input.is_null() || output.is_null() {
            return INVALID;
        }
        // SAFETY: The host validates these synchronous ABI pointers.
        let input = unsafe { &*input };
        // SAFETY: The host grants exclusive output metadata for this call.
        let output = unsafe { &mut *output };
        if input.ptr.is_null() || output.ptr.is_null() {
            return INVALID;
        }
        if input.len > output.capacity {
            output.len = input.len;
            return BUFFER_TOO_SMALL;
        }
        let Ok(length) = usize::try_from(input.len) else {
            return INVALID;
        };
        // SAFETY: Input length and output capacity were checked.
        let source = unsafe { std::slice::from_raw_parts(input.ptr, length) };
        // SAFETY: Output points to host-owned writable memory.
        let destination = unsafe { std::slice::from_raw_parts_mut(output.ptr, length) };
        for (target, value) in destination.iter_mut().zip(source) {
            *target = value.to_ascii_uppercase();
        }
        output.len = input.len;
        // SAFETY: init created a Box<u64> for this live handle.
        unsafe { *handle.cast::<u64>() += 1 };
        OK
    })) {
        Ok(status) => status,
        Err(_) => INTERNAL,
    }
}

unsafe extern "C" fn reset(handle: *mut c_void) -> Status {
    match catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return INVALID;
        }
        // SAFETY: init created a Box<u64> for this live handle.
        unsafe { *handle.cast::<u64>() = 0 };
        OK
    })) {
        Ok(status) => status,
        Err(_) => INTERNAL,
    }
}

unsafe extern "C" fn destroy(handle: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            // SAFETY: The host contract invokes destroy exactly once.
            drop(unsafe { Box::from_raw(handle.cast::<u64>()) });
        }
    }));
}

fn view(bytes: &'static [u8]) -> BufferView {
    BufferView {
        ptr: bytes.as_ptr(),
        len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        alignment: 1,
        memory_kind: 0,
        flags: 1,
        reserved: 0,
    }
}

#[no_mangle]
extern "C" fn d2i_module_v1() -> *const ModuleV1 {
    let table = ModuleV1 {
        abi_version: 1,
        struct_size: u32::try_from(std::mem::size_of::<ModuleV1>()).unwrap_or(u32::MAX),
        module_id: view(b"uppercase-fixture"),
        module_version: view(b"1.0.0"),
        init: Some(init),
        run: Some(run),
        reset: Some(reset),
        destroy: Some(destroy),
    };
    Box::into_raw(Box::new(table))
}

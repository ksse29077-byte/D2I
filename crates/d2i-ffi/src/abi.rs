use std::ffi::c_void;
use std::mem;
use std::slice;

/// Native D2I ABI major version.
pub const D2I_ABI_VERSION_V1: u32 = 1;
/// Host-addressable CPU memory.
pub const D2I_MEMORY_HOST: u32 = 0;
/// Buffer is read-only to the callee.
pub const D2I_BUFFER_READ_ONLY: u32 = 1;
/// No buffer flags.
pub const D2I_BUFFER_FLAGS_NONE: u32 = 0;
/// Maximum supported alignment in the MVP host allocator.
pub const D2I_MAX_ALIGNMENT: u32 = 4096;

/// C-compatible status value. Unknown integer values remain safe to inspect.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D2iStatus(pub u32);

impl D2iStatus {
    pub const OK: Self = Self(0);
    pub const INVALID_ARGUMENT: Self = Self(1);
    pub const TIMEOUT: Self = Self(2);
    pub const INTERNAL: Self = Self(3);
    pub const UNSUPPORTED: Self = Self(4);
    pub const BUFFER_TOO_SMALL: Self = Self(5);
}

/// Borrowed immutable bytes. The caller owns the referenced allocation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct D2iBufferView {
    pub ptr: *const u8,
    pub len: u64,
    pub alignment: u32,
    pub memory_kind: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl D2iBufferView {
    /// Creates a host-memory view that cannot outlive the borrowed slice.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            alignment: 1,
            memory_kind: D2I_MEMORY_HOST,
            flags: D2I_BUFFER_READ_ONLY,
            reserved: 0,
        }
    }

    /// Validates metadata without dereferencing the pointer.
    pub fn validate_metadata(&self, maximum_bytes: u64) -> Result<(), &'static str> {
        validate_common(
            self.ptr.cast_mut(),
            self.len,
            self.alignment,
            self.memory_kind,
            self.reserved,
            maximum_bytes,
        )?;
        if self.flags & !D2I_BUFFER_READ_ONLY != 0 {
            return Err("immutable buffer has unknown flags");
        }
        Ok(())
    }

    /// Borrows bytes after the host has established pointer provenance.
    ///
    /// # Safety
    ///
    /// `ptr..ptr+len` must remain readable for the returned lifetime and must
    /// refer to one allocation with the declared alignment.
    pub unsafe fn as_slice<'a>(&self) -> Result<&'a [u8], &'static str> {
        self.validate_metadata(u64::MAX)?;
        let length = usize::try_from(self.len).map_err(|_| "buffer length exceeds usize")?;
        // SAFETY: The caller guarantees provenance and readability; metadata
        // and usize conversion were validated above.
        Ok(unsafe { slice::from_raw_parts(self.ptr, length) })
    }
}

/// Host-owned writable bytes. A module may update only `len` and payload bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct D2iBufferMut {
    pub ptr: *mut u8,
    pub len: u64,
    pub capacity: u64,
    pub alignment: u32,
    pub memory_kind: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl D2iBufferMut {
    /// Creates a writable view over host-owned initialized memory.
    #[must_use]
    pub fn from_slice(bytes: &mut [u8]) -> Self {
        Self {
            ptr: bytes.as_mut_ptr(),
            len: 0,
            capacity: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            alignment: 1,
            memory_kind: D2I_MEMORY_HOST,
            flags: D2I_BUFFER_FLAGS_NONE,
            reserved: 0,
        }
    }

    /// Validates mutable metadata without dereferencing the pointer.
    pub fn validate_metadata(&self, maximum_bytes: u64) -> Result<(), &'static str> {
        validate_common(
            self.ptr,
            self.capacity,
            self.alignment,
            self.memory_kind,
            self.reserved,
            maximum_bytes,
        )?;
        if self.len > self.capacity {
            return Err("output length exceeds capacity");
        }
        if self.flags != D2I_BUFFER_FLAGS_NONE {
            return Err("mutable buffer has unknown flags");
        }
        Ok(())
    }
}

fn validate_common(
    pointer: *mut u8,
    length: u64,
    alignment: u32,
    memory_kind: u32,
    reserved: u32,
    maximum_bytes: u64,
) -> Result<(), &'static str> {
    if pointer.is_null() {
        return Err("buffer pointer is null");
    }
    if length > maximum_bytes {
        return Err("buffer exceeds configured byte limit");
    }
    if alignment == 0 || !alignment.is_power_of_two() || alignment > D2I_MAX_ALIGNMENT {
        return Err("buffer alignment is invalid");
    }
    if (pointer as usize) % alignment as usize != 0 {
        return Err("buffer pointer does not satisfy declared alignment");
    }
    if memory_kind != D2I_MEMORY_HOST {
        return Err("memory kind is unsupported");
    }
    if reserved != 0 {
        return Err("reserved buffer field must be zero");
    }
    Ok(())
}

pub type D2iInitFn =
    unsafe extern "C" fn(config: *const D2iBufferView, out_handle: *mut *mut c_void) -> D2iStatus;
pub type D2iRunFn = unsafe extern "C" fn(
    handle: *mut c_void,
    input: *const D2iBufferView,
    output: *mut D2iBufferMut,
) -> D2iStatus;
pub type D2iResetFn = unsafe extern "C" fn(handle: *mut c_void) -> D2iStatus;
pub type D2iDestroyFn = unsafe extern "C" fn(handle: *mut c_void);

/// Function table returned by the `d2i_module_v1` symbol.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct D2iModuleV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub module_id: D2iBufferView,
    pub module_version: D2iBufferView,
    pub init: Option<D2iInitFn>,
    pub run: Option<D2iRunFn>,
    pub reset: Option<D2iResetFn>,
    pub destroy: Option<D2iDestroyFn>,
}

impl D2iModuleV1 {
    /// Size that native producers must write into `struct_size`.
    #[must_use]
    pub fn current_struct_size() -> u32 {
        u32::try_from(mem::size_of::<Self>()).unwrap_or(u32::MAX)
    }
}

/// Optional zero-copy view over Arrow C Data Interface structures.
#[cfg(feature = "arrow-c-data")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct D2iArrowCDataView {
    pub array: *const c_void,
    pub schema: *const c_void,
}

#[cfg(feature = "arrow-c-data")]
impl D2iArrowCDataView {
    /// Rejects missing ArrowArray or ArrowSchema pointers.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.array.is_null() || self.schema.is_null() {
            Err("Arrow C Data pointers must be non-null")
        } else {
            Ok(())
        }
    }
}

/// Optional borrowed DLPack managed-tensor view.
#[cfg(feature = "dlpack")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct D2iDlpackView {
    pub managed_tensor: *mut c_void,
    pub flags: u64,
}

#[cfg(feature = "dlpack")]
impl D2iDlpackView {
    /// Rejects null tensor pointers and unknown flags.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.managed_tensor.is_null() {
            Err("DLPack managed tensor pointer must be non-null")
        } else if self.flags != 0 {
            Err("DLPack adapter flags are unsupported")
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn abi_v1_layout_is_stable_on_supported_64_bit_targets() {
        assert_eq!(size_of::<D2iStatus>(), 4);
        assert_eq!(size_of::<D2iBufferView>(), 32);
        assert_eq!(offset_of!(D2iBufferView, len), 8);
        assert_eq!(offset_of!(D2iBufferView, flags), 24);
        assert_eq!(size_of::<D2iBufferMut>(), 40);
        assert_eq!(offset_of!(D2iBufferMut, capacity), 16);
        assert_eq!(offset_of!(D2iBufferMut, flags), 32);
        assert_eq!(size_of::<D2iModuleV1>(), 104);
        assert_eq!(offset_of!(D2iModuleV1, module_id), 8);
        assert_eq!(offset_of!(D2iModuleV1, init), 72);
    }

    #[test]
    fn metadata_fuzz_corpus_never_accepts_invalid_contracts_by_accident() {
        let bytes = [0_u8; 64];
        let mut state = 0x9e37_79b9_u32;
        for _ in 0..10_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let view = D2iBufferView {
                ptr: bytes.as_ptr(),
                len: u64::from(state & 0x7f),
                alignment: (state >> 8) & 0x1fff,
                memory_kind: (state >> 21) & 0x3,
                flags: (state >> 23) & 0x3,
                reserved: state >> 25,
            };
            let accepted = view.validate_metadata(64).is_ok();
            if accepted {
                assert!(view.len <= 64);
                assert!(view.alignment.is_power_of_two());
                assert!(view.alignment <= D2I_MAX_ALIGNMENT);
                assert_eq!(view.memory_kind, D2I_MEMORY_HOST);
                assert_eq!(view.flags & !D2I_BUFFER_READ_ONLY, 0);
                assert_eq!(view.reserved, 0);
            }
        }
    }

    #[cfg(feature = "arrow-c-data")]
    #[test]
    fn arrow_adapter_rejects_null_interfaces() {
        let view = D2iArrowCDataView {
            array: std::ptr::null(),
            schema: std::ptr::null(),
        };
        assert!(view.validate().is_err());
    }

    #[cfg(feature = "dlpack")]
    #[test]
    fn dlpack_adapter_rejects_null_tensor() {
        let view = D2iDlpackView {
            managed_tensor: std::ptr::null_mut(),
            flags: 0,
        };
        assert!(view.validate().is_err());
    }
}

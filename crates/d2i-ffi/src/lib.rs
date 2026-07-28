//! Versioned C ABI, host-owned buffer views, and dynamic native module loader.

mod abi;
mod loader;
#[cfg(feature = "score-kernel")]
mod score_kernel;

pub use abi::*;
pub use loader::{
    file_sha256, AbiCopyMetrics, FfiError, NativeModule, NativeModuleMetadata, NativeModulePolicy,
};
#[cfg(feature = "score-kernel")]
pub use score_kernel::NativeScoreKernel;

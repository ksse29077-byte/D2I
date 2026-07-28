//! Source-to-IR compiler and deterministic package tooling.

mod lower;
mod package;

pub use lower::{build_ir, IrBuildReport, Phase4BuildData};
pub use package::{
    compile_package, diff_packages, load_verified_package, read_package, verify_package,
    BuildReport, CompileReport, PackageDiff, PackageError, PackageSummary, VerifiedPackage,
    COMPILER_VERSION, PACKAGE_FORMAT_VERSION, RUNTIME_ABI_VERSION,
};

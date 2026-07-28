use crate::{read_bounded, sha256_bytes, validate_hash, validate_text, DesktopError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_BROWSER_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DRIVER_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

/// Exact Microsoft Edge and EdgeDriver deployment identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEdgeDriverPin {
    pub schema_version: u32,
    pub browser_name: String,
    pub browser_executable: String,
    pub browser_version: String,
    pub browser_executable_hash: String,
    pub driver_executable: String,
    pub driver_version: String,
    pub driver_executable_hash: String,
    pub compatibility_version: String,
}

impl WindowsEdgeDriverPin {
    /// Validates shape, hashes, canonical paths, versions, and installed files.
    pub fn verify(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 || self.browser_name != "MicrosoftEdge" {
            return Err(DesktopError::Invalid(
                "EdgeDriver pin must use schema 1 and browser_name MicrosoftEdge".to_owned(),
            ));
        }
        validate_hash(
            &self.browser_executable_hash,
            "Edge browser executable hash",
        )?;
        validate_hash(&self.driver_executable_hash, "EdgeDriver executable hash")?;
        let browser_version = validate_four_part_version(&self.browser_version)?;
        let driver_version = validate_four_part_version(&self.driver_version)?;
        let compatibility = compatibility_version(&browser_version);
        if compatibility != compatibility_version(&driver_version)
            || compatibility != self.compatibility_version
        {
            return Err(DesktopError::Integrity(
                "Microsoft Edge and EdgeDriver first three version components differ".to_owned(),
            ));
        }
        let browser = verify_pinned_file(
            Path::new(&self.browser_executable),
            &self.browser_executable_hash,
            MAX_BROWSER_IMAGE_BYTES,
            "Microsoft Edge",
            "msedge.exe",
        )?;
        let driver = verify_pinned_file(
            Path::new(&self.driver_executable),
            &self.driver_executable_hash,
            MAX_DRIVER_IMAGE_BYTES,
            "Microsoft EdgeDriver",
            "msedgedriver.exe",
        )?;
        let actual_browser_version =
            d2i_windows_host::file_product_version(&browser).map_err(|error| {
                DesktopError::Integrity(format!("Microsoft Edge version read failed: {error}"))
            })?;
        let actual_driver_version =
            d2i_windows_host::file_product_version(&driver).map_err(|error| {
                DesktopError::Integrity(format!(
                    "Microsoft EdgeDriver version read failed: {error}"
                ))
            })?;
        if actual_browser_version != self.browser_version
            || actual_driver_version != self.driver_version
        {
            return Err(DesktopError::Integrity(
                "installed Edge or EdgeDriver version differs from the pin".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Creates and immediately verifies an exact Edge/EdgeDriver deployment pin.
pub fn create_windows_edge_driver_pin(
    browser_executable: &Path,
    driver_executable: &Path,
) -> Result<WindowsEdgeDriverPin, DesktopError> {
    let browser = canonical_regular_file(
        browser_executable,
        MAX_BROWSER_IMAGE_BYTES,
        "Microsoft Edge",
        "msedge.exe",
    )?;
    let driver = canonical_regular_file(
        driver_executable,
        MAX_DRIVER_IMAGE_BYTES,
        "Microsoft EdgeDriver",
        "msedgedriver.exe",
    )?;
    let browser_version = d2i_windows_host::file_product_version(&browser).map_err(|error| {
        DesktopError::Integrity(format!("Microsoft Edge version read failed: {error}"))
    })?;
    let driver_version = d2i_windows_host::file_product_version(&driver).map_err(|error| {
        DesktopError::Integrity(format!("Microsoft EdgeDriver version read failed: {error}"))
    })?;
    let browser_parts = validate_four_part_version(&browser_version)?;
    let driver_parts = validate_four_part_version(&driver_version)?;
    let compatibility = compatibility_version(&browser_parts);
    if compatibility != compatibility_version(&driver_parts) {
        return Err(DesktopError::Integrity(format!(
            "Microsoft Edge {browser_version} and EdgeDriver {driver_version} are incompatible"
        )));
    }
    let pin = WindowsEdgeDriverPin {
        schema_version: 1,
        browser_name: "MicrosoftEdge".to_owned(),
        browser_executable: browser.display().to_string(),
        browser_version,
        browser_executable_hash: sha256_bytes(&read_bounded(&browser, MAX_BROWSER_IMAGE_BYTES)?),
        driver_executable: driver.display().to_string(),
        driver_version,
        driver_executable_hash: sha256_bytes(&read_bounded(&driver, MAX_DRIVER_IMAGE_BYTES)?),
        compatibility_version: compatibility,
    };
    pin.verify()?;
    Ok(pin)
}

fn verify_pinned_file(
    path: &Path,
    expected_hash: &str,
    maximum: u64,
    label: &str,
    expected_name: &str,
) -> Result<PathBuf, DesktopError> {
    let canonical = canonical_regular_file(path, maximum, label, expected_name)?;
    if canonical.display().to_string() != path.display().to_string() {
        return Err(DesktopError::Integrity(format!(
            "{label} path is not its exact canonical path"
        )));
    }
    if sha256_bytes(&read_bounded(&canonical, maximum)?) != expected_hash {
        return Err(DesktopError::Integrity(format!(
            "{label} executable hash differs from the pin"
        )));
    }
    Ok(canonical)
}

fn canonical_regular_file(
    path: &Path,
    maximum: u64,
    label: &str,
    expected_name: &str,
) -> Result<PathBuf, DesktopError> {
    validate_text(&path.display().to_string(), label)?;
    if !path.is_absolute() {
        return Err(DesktopError::Invalid(format!(
            "{label} path must be absolute"
        )));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > maximum
        || d2i_windows_host::is_reparse_point(path).map_err(|error| {
            DesktopError::Integrity(format!("{label} reparse-point check failed: {error}"))
        })?
    {
        return Err(DesktopError::Integrity(format!(
            "{label} must be a bounded regular non-reparse file"
        )));
    }
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
    {
        return Err(DesktopError::Invalid(format!(
            "{label} executable name must be {expected_name}"
        )));
    }
    std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn validate_four_part_version(value: &str) -> Result<[u32; 4], DesktopError> {
    validate_text(value, "Windows executable product version")?;
    let mut result = [0_u32; 4];
    let mut count = 0_usize;
    for (index, part) in value.split('.').enumerate() {
        if index >= result.len()
            || part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(DesktopError::Invalid(
                "Windows executable product version must contain four decimal components"
                    .to_owned(),
            ));
        }
        result[index] = part.parse::<u32>().map_err(|_| {
            DesktopError::Invalid(
                "Windows executable product version component overflow".to_owned(),
            )
        })?;
        count += 1;
    }
    if count != 4 {
        return Err(DesktopError::Invalid(
            "Windows executable product version must contain four decimal components".to_owned(),
        ));
    }
    Ok(result)
}

fn compatibility_version(version: &[u32; 4]) -> String {
    format!("{}.{}.{}", version[0], version[1], version[2])
}

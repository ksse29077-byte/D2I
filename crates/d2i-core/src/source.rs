use crate::{ContentHash, Diagnostic, Severity, SourceLocation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Maximum accepted size of one source file (16 MiB).
pub const MAX_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const LOCK_FILE_NAME: &str = "sources.lock";
const ALLOWED_EXTENSIONS: &[&str] = &["csv", "json", "jsonl", "md", "txt", "yaml", "yml"];

/// Deterministically ordered metadata for one source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEntry {
    path: String,
    size: u64,
    content_hash: String,
}

impl SourceEntry {
    /// Slash-separated path relative to the canonical source-pack root.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 hash in `sha256:hex` form.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

/// Secure, sorted source inventory with a content-only aggregate hash.
#[derive(Debug, Clone)]
pub struct SourceInventory {
    root: PathBuf,
    entries: Vec<SourceEntry>,
    inventory_hash: ContentHash,
}

impl SourceInventory {
    /// Canonical source-pack root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Entries sorted by normalized relative path.
    #[must_use]
    pub fn entries(&self) -> &[SourceEntry] {
        &self.entries
    }

    /// Aggregate hash independent of timestamps and directory enumeration order.
    #[must_use]
    pub const fn inventory_hash(&self) -> &ContentHash {
        &self.inventory_hash
    }
}

/// Serializable lock file generated from a source inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLock {
    pub version: u32,
    pub inventory_hash: String,
    pub files: Vec<SourceEntry>,
}

impl From<&SourceInventory> for SourceLock {
    fn from(inventory: &SourceInventory) -> Self {
        Self {
            version: 1,
            inventory_hash: inventory.inventory_hash.to_string(),
            files: inventory.entries.clone(),
        }
    }
}

/// Builds a secure inventory and returns every discoverable diagnostic.
#[must_use]
pub fn build_inventory(root: &Path) -> (Option<SourceInventory>, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let canonical_root = match fs::canonicalize(root) {
        Ok(path) if path.is_dir() => path,
        Ok(_) => {
            diagnostics.push(root_error(root, "source-pack root is not a directory"));
            return (None, diagnostics);
        }
        Err(error) => {
            diagnostics.push(root_error(
                root,
                format!("cannot canonicalize source-pack root: {error}"),
            ));
            return (None, diagnostics);
        }
    };

    let mut files = Vec::new();
    let mut pending = vec![canonical_root.clone()];
    let mut visited_directories = BTreeSet::new();

    while let Some(directory) = pending.pop() {
        let canonical_directory = match fs::canonicalize(&directory) {
            Ok(path) => path,
            Err(error) => {
                diagnostics.push(io_diagnostic(
                    &canonical_root,
                    &directory,
                    "D2I1101",
                    format!("cannot canonicalize directory: {error}"),
                ));
                continue;
            }
        };

        if !canonical_directory.starts_with(&canonical_root) {
            diagnostics.push(io_diagnostic(
                &canonical_root,
                &directory,
                "D2I1102",
                "directory escapes the source-pack root",
            ));
            continue;
        }

        if !visited_directories.insert(canonical_directory.clone()) {
            continue;
        }

        let mut children = match fs::read_dir(&canonical_directory) {
            Ok(children) => {
                let mut entries = Vec::new();
                for child in children {
                    match child {
                        Ok(child) => entries.push(child),
                        Err(error) => diagnostics.push(io_diagnostic(
                            &canonical_root,
                            &canonical_directory,
                            "D2I1103",
                            format!("cannot read directory entry: {error}"),
                        )),
                    }
                }
                entries
            }
            Err(error) => {
                diagnostics.push(io_diagnostic(
                    &canonical_root,
                    &canonical_directory,
                    "D2I1103",
                    format!("cannot read directory: {error}"),
                ));
                continue;
            }
        };
        children.sort_by_key(std::fs::DirEntry::file_name);

        for child in children {
            let path = child.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    diagnostics.push(io_diagnostic(
                        &canonical_root,
                        &path,
                        "D2I1104",
                        format!("cannot inspect path: {error}"),
                    ));
                    continue;
                }
            };

            if metadata.file_type().is_symlink() {
                let target = fs::canonicalize(&path);
                let escapes = target
                    .as_ref()
                    .map_or(true, |target| !target.starts_with(&canonical_root));
                let message = if escapes {
                    "symbolic link escapes the source-pack root"
                } else {
                    "symbolic links are not accepted in source packs"
                };
                diagnostics.push(
                    io_diagnostic(&canonical_root, &path, "D2I1105", message)
                        .with_help("replace the link with a regular file or directory"),
                );
            } else if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                if relative_display(&canonical_root, &path) == LOCK_FILE_NAME {
                    continue;
                }
                files.push((path, metadata.len()));
            }
        }
    }

    files.sort_by_key(|(path, _)| relative_display(&canonical_root, path));
    let mut entries = Vec::new();

    for (path, size) in files {
        let relative = relative_display(&canonical_root, &path);
        if !has_allowed_extension(&path) {
            diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "D2I1106",
                    format!("unsupported source extension in '{relative}'"),
                )
                .with_location(SourceLocation::new(relative, None, None))
                .with_help("use Markdown, text, CSV, JSON, JSONL, YAML, or JSON Schema"),
            );
            continue;
        }

        if size > MAX_SOURCE_FILE_BYTES {
            diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "D2I1107",
                    format!("source file is {size} bytes; limit is {MAX_SOURCE_FILE_BYTES} bytes"),
                )
                .with_location(SourceLocation::new(relative, None, None))
                .with_help("split or reduce the source file"),
            );
            continue;
        }

        match read_bounded(&path, MAX_SOURCE_FILE_BYTES) {
            Ok(bytes) => {
                let digest = sha256_hex(&bytes);
                entries.push(SourceEntry {
                    path: relative,
                    size,
                    content_hash: format!("sha256:{digest}"),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => diagnostics.push(
                Diagnostic::new(Severity::Error, "D2I1107", error.to_string())
                    .with_location(SourceLocation::new(relative, None, None))
                    .with_help("split or reduce the source file"),
            ),
            Err(error) => diagnostics.push(io_diagnostic(
                &canonical_root,
                &path,
                "D2I1108",
                format!("cannot read source file: {error}"),
            )),
        }
    }

    let inventory_hash = hash_inventory(&entries);
    let inventory = match ContentHash::sha256(inventory_hash) {
        Ok(hash) => Some(SourceInventory {
            root: canonical_root,
            entries,
            inventory_hash: hash,
        }),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "D2I1199",
                format!("internal inventory hash error: {error}"),
            ));
            None
        }
    };

    (inventory, diagnostics)
}

/// Writes a deterministic pretty-printed `sources.lock` beside `domain.yaml`.
pub fn write_source_lock(inventory: &SourceInventory) -> Result<PathBuf, io::Error> {
    let path = inventory.root.join(LOCK_FILE_NAME);
    let mut bytes =
        serde_json::to_vec_pretty(&SourceLock::from(inventory)).map_err(io::Error::other)?;
    bytes.push(b'\n');
    fs::write(&path, bytes)?;
    Ok(path)
}

pub(crate) fn validate_relative_reference(path: &str) -> Result<(), &'static str> {
    let candidate = Path::new(path);
    if candidate.as_os_str().is_empty() {
        return Err("path must not be empty");
    }
    if candidate.is_absolute() {
        return Err("absolute paths are not allowed");
    }
    if candidate.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("path traversal is not allowed");
    }
    Ok(())
}

pub(crate) fn resolve_reference(root: &Path, reference: &str) -> Result<PathBuf, String> {
    validate_relative_reference(reference).map_err(str::to_owned)?;
    let joined = root.join(reference);
    let canonical = fs::canonicalize(&joined)
        .map_err(|error| format!("referenced path does not exist or is unreadable: {error}"))?;
    if !canonical.starts_with(root) {
        return Err("referenced path escapes the source-pack root".to_owned());
    }
    Ok(canonical)
}

pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source file exceeds the {limit} byte limit"),
        ));
    }
    Ok(bytes)
}

fn hash_inventory(entries: &[SourceEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"d2i-source-inventory-v1\0");
    for entry in entries {
        hash_length_prefixed(&mut hasher, entry.path.as_bytes());
        hasher.update(entry.size.to_be_bytes());
        hash_length_prefixed(&mut hasher, entry.content_hash.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn hash_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn has_allowed_extension(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| {
            ALLOWED_EXTENSIONS
                .iter()
                .any(|allowed| extension.eq_ignore_ascii_case(allowed))
        })
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn root_error(root: &Path, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Severity::Error, "D2I1100", message)
        .with_location(SourceLocation::new(root.display().to_string(), None, None))
        .with_help("pass a readable source-pack directory")
}

fn io_diagnostic(root: &Path, path: &Path, code: &str, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Severity::Error, code, message).with_location(SourceLocation::new(
        relative_display(root, path),
        None,
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_references_reject_traversal_and_absolute_paths() {
        assert!(validate_relative_reference("../outside.json").is_err());
        assert!(validate_relative_reference("a/../../outside.json").is_err());
        assert!(validate_relative_reference("C:\\outside.json").is_err());
        assert!(validate_relative_reference("schemas/request.schema.json").is_ok());
    }

    #[test]
    fn aggregate_hash_is_order_sensitive_but_timestamp_free() {
        let first = SourceEntry {
            path: "a.txt".to_owned(),
            size: 1,
            content_hash: format!("sha256:{}", "0".repeat(64)),
        };
        let second = SourceEntry {
            path: "b.txt".to_owned(),
            size: 1,
            content_hash: format!("sha256:{}", "1".repeat(64)),
        };
        assert_eq!(
            hash_inventory(&[first.clone(), second.clone()]),
            hash_inventory(&[first.clone(), second.clone()])
        );
        assert_ne!(
            hash_inventory(&[first.clone(), second.clone()]),
            hash_inventory(&[second, first])
        );
    }
}
